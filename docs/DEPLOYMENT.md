# DEPLOYMENT

## Docker Compose
```bash
docker compose up --build -d
# DB-Migration (einmalig)
docker exec -i $(docker ps -qf name=_db_) psql -U tdmx -d tdmx < db/migrations/001_init.sql
```
- **Shiny**: `http://localhost:3838`  
- **API**: `http://localhost:8000`

### Services
- **db**: Postgres 15 (Volume `dbdata`)  
- **shiny**: App-Container (Shiny Server)  
- **api**: Plumber (Fit/Predict)

### Environment
- `PG_DSN=postgresql://tdmx:tdmx@db:5432/tdmx` (im Compose gesetzt)
- `.env.example` vorhanden (lokaler Betrieb ohne Compose).

## Bare-Metal (ohne Docker)
- Shiny: `shiny::runApp()`  
- API:  
```bash
R -e "pr <- plumber::plumb('api/plumber.R'); pr$run(host='0.0.0.0', port=8000)"
```

## Health & Observability
- API: `GET /healthz` → `{status:'ok', time:'...'}`
- Logs: `./logs/` (anwendungsseitig), `docker logs` (Container).

## Sicherheit (Hinweis)
- **Demo-Auth** (`config/users.yaml`) ist nicht produktionsreif.  
- Für Produktion: Reverse Proxy (TLS), SSO/OIDC, Secret-Management (Vault), gehärtete Images, Rate-Limits.
