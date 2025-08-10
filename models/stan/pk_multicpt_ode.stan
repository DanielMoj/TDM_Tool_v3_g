// models/stan/pk_multicpt_ode.stan
functions {
  real infusion_rate(real t, int n_inf, vector t0, vector tinf, vector rate) {
    real r = 0;
    for (i in 1:n_inf) {
      if (t > t0[i] && t <= t0[i] + tinf[i]) r += rate[i];
    }
    return r;
  }
  vector derivs(real t, vector A, real k10, real k12, real k21, real k13, real k31,
                int n_inf, vector t0, vector tinf, vector rate) {
    real R = infusion_rate(t, n_inf, t0, tinf, rate);
    vector[3] dA;
    dA[1] = R - (k10 + k12 + k13) * A[1] + k21 * A[2] + k31 * A[3];
    dA[2] = k12 * A[1] - k21 * A[2];
    dA[3] = k13 * A[1] - k31 * A[3];
    return dA;
  }
}

data {
  int<lower=1> N;
  vector[N] t_obs;
  vector[N] y;
  int<lower=0,upper=1> is_blq[N];
  real<lower=0> lloq;
  int<lower=1,upper=3> n_cmt;
  int<lower=0> n_inf;
  vector[n_inf] t0;
  vector[n_inf] tinf;
  vector[n_inf] rate;
  int<lower=0> error_model; // 1=add,2=prop,3=comb,4=t-add,5=t-prop,6=mixture
  int<lower=0,upper=1> est_sigma;
  real<lower=1> nu;
  real<lower=0,upper=1> mix_w;
  real<lower=1> mix_scale;
  int idx_CL;
  int idx_Vc;
  int idx_Q1;
  int idx_Vp1;
  int idx_Q2;
  int idx_Vp2;
  int<lower=1> K; // number of theta entries
  vector[K] mu;
  vector[K] sd;
  real sigma_add_init;
  real sigma_prop_init;
}

transformed data {
  vector[3] A0;
  A0[1] = 0;
  A0[2] = 0;
  A0[3] = 0;
}

parameters {
  real logCL;
  real logVc;
  real logQ1;
  real logVp1;
  real logQ2;
  real logVp2;
  real<lower=0> sigma_add;
  real<lower=0> sigma_prop;
}

transformed parameters {
  real CL  = exp(logCL);
  real Vc  = exp(logVc);
  real Q1  = exp(logQ1);
  real Vp1 = exp(logVp1);
  real Q2  = exp(logQ2);
  real Vp2 = exp(logVp2);
  real k10 = CL / Vc;
  real k12 = (n_cmt >= 2) ? Q1 / Vc  : 0;
  real k21 = (n_cmt >= 2) ? Q1 / Vp1 : 0;
  real k13 = (n_cmt == 3) ? Q2 / Vc  : 0;
  real k31 = (n_cmt == 3) ? Q2 / Vp2 : 0;

  vector[N] pred;
  {
    array[N] vector[3] A;
    A = ode_rk45(derivs, A0, 0, t_obs, k10, k12, k21, k13, k31, n_inf, t0, tinf, rate);
    for (n in 1:N) pred[n] = A[n][1] / Vc;
  }
}

model {
  // Priors (lognormal on parameters)
  logCL ~ normal(mu[idx_CL], sd[idx_CL]);
  logVc ~ normal(mu[idx_Vc], sd[idx_Vc]);
  logQ1 ~ normal(mu[idx_Q1], sd[idx_Q1]);
  logVp1 ~ normal(mu[idx_Vp1], sd[idx_Vp1]);
  logQ2 ~ normal(mu[idx_Q2], sd[idx_Q2]);
  logVp2 ~ normal(mu[idx_Vp2], sd[idx_Vp2]);

  // Sigma priors
  sigma_add ~ normal(sigma_add_init, 1) T[0,];
  sigma_prop ~ normal(sigma_prop_init, 1) T[0,];


  for (n in 1:N) {
    real s;
    if (error_model == 1) {
      s = sigma_add;
    } else if (error_model == 2) {
      s = fmax(1e-6, sigma_prop * fabs(pred[n]));
    } else if (error_model == 3) {
      s = sqrt(fmax(1e-12, square(sigma_add) + square(sigma_prop * pred[n])));
    } else if (error_model == 4) { // t-add
      s = sigma_add;
    } else if (error_model == 5) { // t-prop
      s = fmax(1e-6, sigma_prop * fabs(pred[n]));
    } else { // mixture base sd uses sigma_add
      s = sigma_add;
    }

    if (is_blq[n] == 1) {
      // M3: censored likelihood
      if (error_model <= 3) {
        target += normal_lcdf(lloq | pred[n], s);
      } else if (error_model == 4 || error_model == 5) {
        // proper Student-t lcdf for BLQ under t-residual model
        target += student_t_lcdf(lloq | nu, pred[n], s);
      } else { // mixture (two normal components)
        target += log_sum_exp( log(mix_w) + normal_lcdf(lloq | pred[n], s),
                               log1m(mix_w) + normal_lcdf(lloq | pred[n], mix_scale * s) );
      }
    } else {
      if (error_model <= 3) {
        y[n] ~ normal(pred[n], s);
      } else if (error_model == 4 || error_model == 5) {
        y[n] ~ student_t(nu, pred[n], s);
      } else { // mixture
        target += log_sum_exp( log(mix_w)   + normal_lpdf(y[n] | pred[n], s),
                               log1m(mix_w) + normal_lpdf(y[n] | pred[n], mix_scale * s) );
      }
    }
  }

}

generated quantities {
  // expose natural-scale parameters
  real CL_out = CL;
  real Vc_out = Vc;
  real Q1_out = Q1;
  real Vp1_out = Vp1;
  real Q2_out = Q2;
  real Vp2_out = Vp2;
}
