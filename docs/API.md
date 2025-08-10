# API

Basis: **Plumber** (`api/plumber.R`). Standard-JSON; UTF-8; Zeitzonen in Stunden.

## Health
### `GET /healthz`
**200 OK**  
```json
{"status":"ok","time":"2025-08-08 12:00:00"}
```

## Fit
### `POST /fit`
Startet einen Fit mit übergebenen Daten.

**Request (JSON)**
```json
{
  "drug": "Meropenem",
  "model_type": "2C",
  "backend": "Laplace",
  "error_model": "kombiniert",
  "estimate_sigma": true,
  "sigma_init": {"add": 1.0, "prop": 0.15},
  "regimen": {"dose": 1000, "tau": 8, "tinf": 0.5, "n_doses": 6, "start_time": 0},
  "covariates": {"age": 64, "weight": 80, "crcl": 90},
  "obs": {"time": [1, 7.5], "conc": [12.3, 6.1]}
}
```

**Response (200)**
```json
{
  "posterior_summary": {
    "median": {"CL": 8.1, "Vc": 19.8, "Q1": 6.2, "Vp1": 12.1},
    "q2.5":  {"CL": 6.7, "Vc": 15.0, "Q1": 4.0, "Vp1":  8.0},
    "q97.5": {"CL": 9.8, "Vc": 25.7, "Q1": 8.5, "Vp1": 16.5}
  },
  "draws_head": [
    {"CL": 8.5, "Vc": 18.2, "Q1": 6.1, "Vp1": 13.2},
    {"CL": 8.3, "Vc": 20.0, "Q1": 6.5, "Vp1": 12.5}
  ]
}
```

**Fehler (400)**
```json
{"error":"unknown drug"}
```

## Predict
### `POST /predict`
Gibt C(t) für gegebenes θ-/Regimen/Zeiten zurück.

**Request**
```json
{
  "model_type": "2C",
  "theta": {"CL": 8.0, "Vc": 20.0, "Q1": 6.0, "Vp1": 12.0},
  "regimen": {"dose": 1000, "tau": 8, "tinf": 0.5, "n_doses": 10, "start_time": 0},
  "times": [0, 0.5, 1, 2, 4, 8]
}
```

**Response**
```json
{"time":[0,0.5,1,2,4,8],"conc":[0,15.2,18.4,10.7,5.2,2.1]}
```

## Hinweise
- **Timeouts**: Lange HMC-Läufe vermeiden, ggf. ADVI/Laplace nutzen.
- **Schema-Änderungen**: Backward-kompatibel halten; Beispielpayloads in Tests pinnen.
