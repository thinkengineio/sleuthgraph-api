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

## Cases, Entities, Relationships (Phase 3)

### Endpoints

| Method | Path | Description |
|---|---|---|
| POST | `/cases` | Create a new investigation case |
| GET | `/cases` | List my cases (query: `status`, `limit`, `offset`) |
| GET | `/cases/{case_id}` | Get one case |
| PATCH | `/cases/{case_id}` | Update case (name, status, tags) |
| DELETE | `/cases/{case_id}` | Soft-delete a case |
| POST | `/cases/{case_id}/entities` | Create an entity in a case |
| GET | `/cases/{case_id}/entities` | List entities (query: `type`, `limit`, `offset`) |
| GET | `/cases/{case_id}/entities/{entity_id}` | Get one entity |
| PATCH | `/cases/{case_id}/entities/{entity_id}` | Update entity (label, attrs, confidence) |
| DELETE | `/cases/{case_id}/entities/{entity_id}` | Soft-delete entity |
| POST | `/cases/{case_id}/relationships` | Create a relationship (immutable) |
| GET | `/cases/{case_id}/relationships` | List relationships (query: `rel_type`, `src`, `dst`, `limit`, `offset`) |
| GET | `/cases/{case_id}/relationships/{rel_id}` | Get one relationship |
| DELETE | `/cases/{case_id}/relationships/{rel_id}` | Soft-delete relationship |
| GET | `/cases/{case_id}/graph` | Flat graph dump (vertices + edges) |

### Entity types

`PERSON`, `ORGANIZATION`, `DOMAIN`, `IP_ADDRESS`, `EMAIL`, `PHONE`, `URL`, `CRYPTO_ADDRESS`.

### Relationship types

`OWNS`, `EMPLOYED_BY`, `REGISTERED_BY`, `HOSTED_ON`, `RESOLVES_TO`, `ASSOCIATED_WITH`, `COMMUNICATED_WITH`, `MENTIONS`.

### Graph model

- One shared Apache AGE graph (`sleuthgraph`); each entity becomes a vertex labeled by its type; each relationship becomes an edge.
- SQL is source of truth; AGE is a materialized mirror written in the same transaction as the SQL row.
- `case_id` is a property on every vertex and edge, so `/cases/{case_id}/graph` filters by it.
- Soft-deletes remove the AGE vertex/edge but preserve the SQL row (chain of custody for Phase 4).

### Ownership

Every endpoint checks that the current user owns the case; unauthorized access returns 404 (not 403) so existence isn't leaked.

### Immutability

Relationships have no update endpoint. Edits happen via delete + recreate. Entities can be updated (label / attrs / confidence), but the AGE vertex gets re-MERGEd on every update so the graph stays in sync.

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

## Evidence chain of custody (Phase 4)

### Endpoints

| Method | Path | Description |
|---|---|---|
| POST | `/cases/{case_id}/evidence` | Multipart upload: `file` + JSON `metadata` → 201 EvidenceRead |
| GET | `/cases/{case_id}/evidence` | Paginated list (`entity_id`, `source_plugin`, `limit`, `offset`) |
| GET | `/cases/{case_id}/evidence/{ev_id}` | One evidence record |
| GET | `/cases/{case_id}/evidence/{ev_id}/blob` | 307 redirect to presigned MinIO URL (5-min expiry) |
| GET | `/cases/{case_id}/evidence/export?format=json\|csv` | Full ledger dump for legal handoff |

**No PUT, PATCH, or DELETE** on evidence — append-only by design. Chain-of-custody requires evidence outlives even soft-deleted cases.

### Environment contract

| Var | Default | Purpose |
|---|---|---|
| `EVIDENCE_MAX_UPLOAD_BYTES` | `52428800` (50 MiB) | Hard cap on evidence file upload size; requests exceeding this are rejected with 413 before the body is fully buffered. |

### Design

- Blob stored in MinIO at `case/{case_id}/ev/{sha256_hex}` — same payload never uploaded twice.
- `response_hash` is SHA-256 of the raw bytes uploaded.
- `reproducibility_spec` validated with the same identifier-regex rules as entity `attrs` (defense against Cypher/SQL injection when plugin responses are serialized into this field in Phase 5+).
- Idempotent upload: repository does HEAD-before-PUT on MinIO; replays are no-ops.
- SQL row insert + MinIO upload are atomic from the API perspective: blob upload happens before SQL commit; any failure rolls back the row (orphan blob is cheap to garbage-collect).

### Deployment note — MinIO endpoint for browser downloads

The presigned URL returned by `/blob` embeds `S3_ENDPOINT`. For docker-compose local dev, `S3_ENDPOINT=http://minio:9000` points at the internal docker network hostname — it will NOT resolve from a browser on the host. Either:
1. Put MinIO behind a reverse proxy reachable at the same hostname inside and outside the container network, OR
2. Run MinIO with a public `MINIO_SERVER_URL` and set `S3_ENDPOINT` to that public URL so presigned URLs are browser-reachable.

For production (single-host Docker Compose), use option 2 with an HTTPS reverse proxy (caddy/traefik) in front of MinIO.
