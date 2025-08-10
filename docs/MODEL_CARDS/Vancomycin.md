# Model Card – Vancomycin

## PK-Modell
- Standard: Mehrkompartment linear (Stan)
- Optional: MM-1C, TMDD-QSS-1C (Stan/JAGS)

## Priors (θ)
```json
{
  "CL": 4.5,
  "Vc": 30.0,
  "Q1": 4.0,
  "Vp1": 25.0
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
