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
