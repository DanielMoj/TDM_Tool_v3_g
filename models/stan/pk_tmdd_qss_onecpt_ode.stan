// models/stan/pk_tmdd_qss_onecpt_ode.stan
functions {
  real infusion_rate(real t, int n_inf, vector t0, vector tinf, vector rate) {
    real r = 0;
    for (i in 1:n_inf) {
      if (t >= t0[i] && t <= t0[i] + tinf[i]) r += rate[i];
    }
    return r;
  }
  vector derivs(real t, vector A, real CL, real Vc, real kint, real Rtot, real Kss,
                int n_inf, vector t0, vector tinf, vector rate) {
    real R = infusion_rate(t, n_inf, t0, tinf, rate);
    real C = A[1] / Vc;
    real sat_elim = kint * Rtot * C / (Kss + C); // QSS internalization
    vector[1] dA;
    dA[1] = R - CL * C - sat_elim;
    return dA;
  }
}

data {
  int<lower=1> N;
  vector[N] t_obs;
  vector[N] y;
  int<lower=0,upper=1> is_blq[N];
  real<lower=0> lloq;

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
  int idx_kint;
  int idx_Rtot;
  int idx_Kss;
  int<lower=1> K;
  vector[K] mu;
  vector[K] sd;
  real sigma_add_init;
  real sigma_prop_init;
}

transformed data {
  vector[1] A0;
  A0[1] = 0;
}

parameters {
  real logCL;
  real logVc;
  real logkint;
  real logRtot;
  real logKss;
  real<lower=0> sigma_add;
  real<lower=0> sigma_prop;
}

transformed parameters {
  real<lower=0> CL    = exp(logCL);
  real<lower=0> Vc    = exp(logVc);
  real<lower=0> kint  = exp(logkint);
  real<lower=0> Rtot  = exp(logRtot);
  real<lower=0> Kss   = exp(logKss);
  vector[N] pred;
  {
    array[N] vector[1] A;
    A = ode_rk45(derivs, A0, 0, t_obs, CL, Vc, kint, Rtot, Kss, n_inf, t0, tinf, rate);
    for (n in 1:N) pred[n] = A[n][1] / Vc;
  }
}

model {
  // Priors (lognormal on parameters)
  logCL   ~ normal(mu[idx_CL],   sd[idx_CL]);
  logVc   ~ normal(mu[idx_Vc],   sd[idx_Vc]);
  logkint ~ normal(mu[idx_kint], sd[idx_kint]);
  logRtot ~ normal(mu[idx_Rtot], sd[idx_Rtot]);
  logKss  ~ normal(mu[idx_Kss],  sd[idx_Kss]);

  // Sigma priors
  sigma_add ~ normal(sigma_add_init, 1) T[0,];
  sigma_prop ~ normal(sigma_prop_init, 1) T[0,];

  for (n in 1:N) {
    real s;
    if (error_model == 1) {
      s = sigma_add;
    } else if (error_model == 2) {
      s = sigma_prop * pred[n];
    } else if (error_model == 3) {
      s = sqrt(square(sigma_add) + square(sigma_prop * pred[n]));
    } else if (error_model == 4) { // t-add
      s = sigma_add;
    } else if (error_model == 5) { // t-prop
      s = sigma_prop * pred[n];
    } else { // mixture uses normal components
      s = sqrt(square(sigma_add) + square(sigma_prop * pred[n]));
    }

    if (is_blq[n] == 1) {
      if (error_model <= 3) {
        target += normal_lcdf(lloq | pred[n], s);
      } else if (error_model == 4 || error_model == 5) {
        target += student_t_lcdf(lloq | nu, pred[n], s);
      } else {
        target += normal_lcdf(lloq | pred[n], s);
      }
    } else {
      if (error_model <= 3) {
        y[n] ~ normal(pred[n], s);
      } else if (error_model == 4 || error_model == 5) {
        y[n] ~ student_t(nu, pred[n], s);
      } else { // mixture with normal components
        target += log_sum_exp( log(mix_w)   + normal_lpdf(y[n] | pred[n], s),
                               log1m(mix_w) + normal_lpdf(y[n] | pred[n], mix_scale * s) );
      }
    }
  }
}
