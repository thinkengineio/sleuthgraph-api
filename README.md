# sleuthgraph-api

Backend for [Sleuthgraph](https://github.com/francose/sleuthgraph) — FastAPI + Postgres+AGE + Redis + MinIO.

## Local development

Requires Python 3.12, Docker.

```bash
# 1. Python virtualenv
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# 2. Start infra (from the meta repo)
cd ../sleuthgraph/deploy
cp .env.example .env
docker compose --env-file .env -f docker-compose.yml up -d db redis minio minio-bootstrap

# 3. Run migrations
cd ../../sleuthgraph-api
export $(grep -v '^#' ../sleuthgraph/deploy/.env | sed 's/=db\b/=localhost/; s/=redis\b/=localhost/; s/=minio\b/=localhost/' | xargs)
alembic upgrade head

# 4. Run API
uvicorn sleuthgraph.main:app --reload
```

Docs: http://localhost:8000/docs

## Auth

Sleuthgraph uses Grafana-style auth: local email/password users + optional OIDC, single-tenant.

### Endpoints

| Method | Path | Description |
|---|---|---|
| POST | `/auth/login` | Form-encoded `username` + `password`; sets session cookie |
| POST | `/auth/logout` | Clears cookie |
| POST | `/auth/register` | Creates a user. **Only mounted when `AUTH_ALLOW_SIGNUP=true`** |
| GET | `/auth/ping` | Authed smoke; returns `{"user": email}` |
| GET | `/auth/oidc-status` | Reports whether OIDC is configured (safe — no secrets) |
| GET | `/users/me` | Current user profile |
| PATCH | `/users/me` | Update current user |

### Environment contract

| Var | Default | Purpose |
|---|---|---|
| `SECRET_KEY` | — (required, ≥32 chars) | JWT signing + credential encryption |
| `AUTH_COOKIE_NAME` | `sleuthgraph_session` | Session cookie name |
| `AUTH_COOKIE_SECURE` | `true` | Set `false` for plain http dev |
| `AUTH_SESSION_LIFETIME_SECONDS` | `604800` (1 week) | Session TTL |
| `AUTH_ALLOW_SIGNUP` | `false` | Public `/auth/register` route |
| `AUTH_ADMIN_EMAIL` | unset | Bootstrap admin on startup (idempotent) |
| `AUTH_ADMIN_PASSWORD` | unset | Bootstrap admin password |
| `OIDC_ISSUER` / `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | unset | OIDC config (status only in Phase 2; full flow in Phase 2.5) |

### Bootstrapping the first admin

Set `AUTH_ADMIN_EMAIL` + `AUTH_ADMIN_PASSWORD` in `deploy/.env` before `docker compose up`. The user is created on startup if it doesn't exist; subsequent startups are no-ops. To reset, delete the row from `users` and restart.

### Phase 2 deferred

- Full OIDC login/callback flow (status endpoint only)
- Password reset
- Email verification
- Per-user API tokens (Phase 5, for plugin authors)
- DB-backed session revocation (currently JWT)
- Frontend login page (Phase 8)

## Tests

```bash
pytest
```

## Lint

```bash
ruff check .
ruff format .
```

## License

Apache 2.0 — see [LICENSE](../sleuthgraph/LICENSE).
