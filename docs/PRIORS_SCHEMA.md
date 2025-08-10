# PRIORS – JSON-SCHEMA

Priors pro Wirkstoff liegen unter `priors/<Drug>.json`. Das Schema ist **by-name** und nutzt **Log-Normal-Priors**.

## Felder
```json
{
  "name": "Meropenem",
  "n_comp": 2,
  "theta": {"CL": 8.0, "Vc": 20.0, "Q1": 6.0, "Vp1": 12.0},
  "theta_log": {
    "mu": {"CL": 2.079, "Vc": 2.996, "Q1": 1.792, "Vp1": 2.485},
    "sd": {"CL": 0.25,  "Vc": 0.30,  "Q1": 0.40,  "Vp1": 0.35}
  }
}
```
- **name**: Anzeigename.  
- **n_comp**: 1/2/3 (Anzahl PK-Kompartimente; informativ).  
- **theta**: Start-/Referenzwerte (natürliche Skala).  
- **theta_log.mu/sd**: Priors auf **log**-Skala.

## Parameter-Namen
- Linear: **CL, Vc, Q1, Vp1, Q2, Vp2**.  
- MM: **Vmax, Km** (falls genutzt).  
- TMDD (skeleton): **Kon, Koff, Rtot, Kint**.

## Validierung
- Admin-Tab zeigt JSON an; Speicherung validiert:  
  - nur bekannte Parameter, fehlende als 0/NA,  
  - `sd` > 0, numerisch, keine NAs.

## Neues Drug-Paket
1. JSON-Datei unter `priors/` anlegen.  
2. Admin-Tab → laden/prüfen/speichern.  
3. (Optional) **targets.json** & **tissue.json** ergänzen.
