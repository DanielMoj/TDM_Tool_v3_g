# Model Card – Meropenem

## PK-Modell
- Standard: Mehrkompartment linear (Stan)
- Optional: MM-1C, TMDD-QSS-1C (Stan/JAGS)

## Priors (θ)
```json
{
  "CL": 8.0,
  "Vc": 20.0,
  "Q1": 6.0,
  "Vp1": 12.0
}
```

## Zielmetriken (Defaults)
```json
{}
```

## Fehlermodelle
- additiv, proportional, kombiniert, t-Residuen, Mixture (JAGS voll; Stan teilweise)

## Gültigkeit & Limitationen
- Priors sind standortspezifisch zu prüfen/kalibrieren.
- CRRT-Integration im Stan-ODE noch offen.
- BLQ-M3+Mixture für Stan in Arbeit.

_Stand: 2025-08-09_
