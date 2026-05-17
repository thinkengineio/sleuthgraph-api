# sleuthgraph-api

FastAPI backend for [Sleuthgraph](https://sleuthgraph.io) — an OSINT investigation platform.
PostgreSQL 16 + Apache AGE graph · Redis 7 · MinIO object storage · arq background worker.

- **API docs:** http://localhost:8000/docs (OpenAPI / Swagger UI)
- **Redoc:** http://localhost:8000/redoc

---

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Python | 3.12 | Runtime |
| PostgreSQL + [Apache AGE](https://age.apache.org/) | 16 + AGE 1.6 | Relational + graph storage |
| Redis | 7 | Session cache + arq task queue |
| MinIO | latest | Evidence blob storage (S3-compatible) |
| Docker (optional) | 24+ | Run infra services via Compose |

---

## Quickstart — Docker (recommended for local dev)

The canonical Compose file lives in the meta-repo (`../sleuthgraph/deploy/`).

```bash
# 1. Start infrastructure
cd ../sleuthgraph/deploy
cp .env.example .env          # edit DATABASE_URL, SECRET_KEY, etc.
docker compose -f docker-compose.yml up -d db redis minio minio-bootstrap

# 2. Run the API in a container (picks up the same .env)
docker compose up -d api

# Open Swagger UI
open http://localhost:8000/docs
```

The `api` service already runs migrations on start via `alembic upgrade head`.

---

## Quickstart — local Python dev

Use this path when you need hot-reload or want to step through the code with a debugger.

### 1. Install dependencies

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### 2. Start infrastructure

Start PostgreSQL 16 + Apache AGE, Redis 7, and MinIO. The simplest way is to
reuse the meta-repo Compose stack:

```bash
cd ../sleuthgraph/deploy
cp .env.example .env
docker compose -f docker-compose.yml up -d db redis minio minio-bootstrap
```

Or point the vars below at an existing instance.

### 3. Configure environment

```bash
cd ../../sleuthgraph-api
cp .env.example .env
# Edit .env: set DATABASE_URL, REDIS_URL, S3_*, SECRET_KEY
# For the Compose stack with default ports, the .env.example values work as-is
# after replacing the Compose-internal hostnames with localhost:
export DATABASE_URL=postgresql+asyncpg://sleuthgraph:changeme@localhost:5432/sleuthgraph
export REDIS_URL=redis://:changeme_local_only_redis@localhost:6379/0
export S3_ENDPOINT=http://localhost:9000
export SECRET_KEY=<random-64-char-string>
```

Or load from `.env`:

```bash
export $(grep -v '^#' .env | xargs)
```

### 4. Run migrations

```bash
alembic upgrade head
```

### 5. Start the API

```bash
uvicorn sleuthgraph.main:app --reload
```

API is now at http://localhost:8000 — Swagger UI at http://localhost:8000/docs.

---

## Endpoints

### Health

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness — no external deps |
| GET | `/readiness` | Readiness — confirms DB connectivity |

### Auth

Grafana-style auth: local email/password + optional OIDC, single-tenant.

| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/login` | Form-encoded `username` + `password`; sets session cookie |
| POST | `/auth/logout` | Clears session cookie |
| POST | `/auth/register` | Create a user. **Only active when `AUTH_ALLOW_SIGNUP=true`** |
| POST | `/auth/forgot-password` | Request password reset token. Active when `AUTH_ALLOW_PASSWORD_RESET=true` |
| POST | `/auth/reset-password` | Exchange token for new password |
| GET  | `/auth/ping` | Authenticated smoke test; returns `{"user": email}` |
| GET  | `/auth/oidc-status` | Whether OIDC is configured (no secrets exposed) |
| GET  | `/auth/oidc/login` | Redirect to OIDC provider (requires OIDC config) |
| GET  | `/auth/oidc/callback` | OIDC callback — provisions/links user, sets cookie |
| GET  | `/users/me` | Current user profile |
| PATCH | `/users/me` | Update display name / password |

#### Bootstrapping the first admin

Set `AUTH_ADMIN_EMAIL` + `AUTH_ADMIN_PASSWORD` before startup. The user is
created on first boot (idempotent — subsequent restarts are no-ops).

```bash
AUTH_ADMIN_EMAIL=admin@example.com
AUTH_ADMIN_PASSWORD=<strong-password>
```

### Cases, Entities, Relationships

| Method | Path | Description |
|--------|------|-------------|
| POST | `/cases` | Create a new investigation case |
| GET | `/cases` | List my cases (query: `status`, `limit`, `offset`) |
| GET | `/cases/{case_id}` | Get one case |
| PATCH | `/cases/{case_id}` | Update case (name, status, tags) |
| DELETE | `/cases/{case_id}` | Soft-delete a case |
| POST | `/cases/{case_id}/entities` | Create an entity |
| GET | `/cases/{case_id}/entities` | List entities (query: `type`, `limit`, `offset`) |
| GET | `/cases/{case_id}/entities/{entity_id}` | Get one entity |
| PATCH | `/cases/{case_id}/entities/{entity_id}` | Update entity (label, attrs, confidence) |
| DELETE | `/cases/{case_id}/entities/{entity_id}` | Soft-delete entity |
| POST | `/cases/{case_id}/relationships` | Create a relationship (immutable) |
| GET | `/cases/{case_id}/relationships` | List relationships (query: `rel_type`, `src`, `dst`, `limit`, `offset`) |
| GET | `/cases/{case_id}/relationships/{rel_id}` | Get one relationship |
| DELETE | `/cases/{case_id}/relationships/{rel_id}` | Soft-delete relationship |

**Entity types:** `PERSON`, `ORGANIZATION`, `DOMAIN`, `IP_ADDRESS`, `EMAIL`, `PHONE`, `URL`, `CRYPTO_ADDRESS`

**Relationship types:** `OWNS`, `EMPLOYED_BY`, `REGISTERED_BY`, `HOSTED_ON`, `RESOLVES_TO`, `ASSOCIATED_WITH`, `COMMUNICATED_WITH`, `MENTIONS`

**Ownership:** all case endpoints enforce that the current user owns the case;
unauthorized access returns 404 (not 403) so existence is not leaked.

**Relationships are immutable.** Edit via delete + recreate.

### Graph

| Method | Path | Description |
|--------|------|-------------|
| GET | `/cases/{case_id}/graph` | Flat graph dump (vertices + edges) for visualization |

The graph is backed by Apache AGE. SQL is the source of truth; AGE is a
materialized mirror written in the same transaction. Each vertex and edge
carries `case_id` so the graph endpoint filters to the correct case. Soft-deletes
remove the AGE vertex/edge while preserving the SQL row for chain-of-custody.

### Evidence

Evidence is **append-only** — no PUT, PATCH, or DELETE.

| Method | Path | Description |
|--------|------|-------------|
| POST | `/cases/{case_id}/evidence` | Multipart upload: `file` + JSON `metadata` → 201 |
| GET | `/cases/{case_id}/evidence` | Paginated list (query: `entity_id`, `source_plugin`, `limit`, `offset`) |
| GET | `/cases/{case_id}/evidence/{ev_id}` | One evidence record |
| GET | `/cases/{case_id}/evidence/{ev_id}/blob` | 307 redirect to presigned MinIO URL (5-min expiry) |
| GET | `/cases/{case_id}/evidence/export` | Full ledger dump (`?format=json` or `?format=csv`) for legal handoff |

Upload size is capped by `EVIDENCE_MAX_UPLOAD_BYTES` (default 50 MiB). Blobs are
stored at `case/{case_id}/ev/{sha256_hex}` — identical files are stored once.
SQL row insert and MinIO upload are atomic: upload happens before commit; any
failure rolls back the row.

**MinIO hostname note:** The presigned URL returned by `/blob` embeds `S3_ENDPOINT`.
In Docker Compose, `S3_ENDPOINT=http://minio:9000` resolves inside the container
network but not from a browser. For production or browser-accessible downloads,
set `S3_ENDPOINT` to a publicly reachable URL (e.g. behind an HTTPS reverse proxy).

### Plugins

| Method | Path | Description |
|--------|------|-------------|
| GET | `/plugins` | List all registered plugins |
| GET | `/plugins/{plugin_id}` | Plugin details |
| POST | `/cases/{case_id}/plugins/{plugin_id}/run` | Queue a plugin run for an entity |
| GET | `/cases/{case_id}/plugins/runs` | List plugin runs for a case |
| GET | `/cases/{case_id}/plugins/runs/{run_id}` | Get one plugin run (status + results) |

Plugin runs are executed asynchronously by the arq worker process. Built-in
plugins: `crt_sh`, `dns_whois`, `github_public`, `opencorporates`, `opensanctions`,
`urlhaus`, `wayback_cdx`, `aleph_occrp`.

---

## Tests

```bash
pytest
```

With coverage:

```bash
pytest --cov=src/sleuthgraph --cov-report=term-missing
```

---

## Lint

```bash
ruff check .
ruff format .
```

CI enforces both. Format check (without auto-fix):

```bash
ruff format --check .
```

---

## Contributing

1. Fork the repo and open a PR against `dev` (not `main`).
2. All PRs must pass `ruff check .`, `ruff format --check .`, and `pytest` before merge.
3. For significant changes, open an issue first to discuss the approach.
4. See the meta-repo (`sleuthgraph/`) for architecture decisions and the overall
   project roadmap.

---

## License

Apache 2.0 — see [LICENSE](../sleuthgraph/LICENSE).
