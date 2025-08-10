
# JAGS-Modelle (diskrete ODE-Integration)

## Modelle
- `models/jags/pk_mm_onecpt_disc.jags` — 1-Kompartment + Michaelis–Menten (Euler, dt=0.1 h)
- `models/jags/pk_tmdd_qss_onecpt_disc.jags` — 1-Kompartment + TMDD (QSS) (Euler, dt=0.1 h)

## Datenübergabe (Backend)
`build_time_grid(regimen, obs_times, dt)` erzeugt:
- `t`: Zeitgitter 0..t_end
- `rate[t]`: Infusionsrate (mg/h) pro Schritt
- `idx[n]`: Index der Beobachtungszeitpunkte im Gitter
- `dt`: Schrittweite (h)

## BLQ
- BLQ via Bernoulli mit `p = Phi((LLOQ - mu)/sigma)` (Normalresiduen).
- Aktuell keine t-Residuals/Mixture im JAGS-Pfad (optional möglich).

## Performance
- `dt = 0.1 h` als Standard; bei langen Verläufen ggf. auf 0.2–0.25 erhöhen.
- Chains/Iterationen in `run_fit_jags()` anpassbar.
