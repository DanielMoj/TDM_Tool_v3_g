# API_CONTRACT_v1

**Auth:** `POST /auth/token` ⇒ `{access_token, token_type=Bearer, expires_in}`  
Header für alle anderen Endpoints: `Authorization: Bearer <token>`

## LIS/Antibiogramm
- `GET /lis/antibiogram/list` → `{ "drugs": ["Meropenem", ...] }`
- `GET /lis/antibiogram/get?drug=<name>` → `{ "n": <int>, "items": [ { "drug":"...", "mic":..., "prob":... }, ... ] }`
- `POST /lis/antibiogram/import?path=/abs/pfad.csv&source=myfeed` → `{version, checksum, n}`

## Hinweise
- Alle Antworten sind JSON.
- Fehlercodes: 400 (Bad Request), 401 (Auth), 500 (Server).
- Rate-Limits und `/v1`-Namespaces sind geplant.
