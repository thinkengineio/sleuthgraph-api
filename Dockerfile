# Multi-stage Dockerfile for Sleuthgraph API.

FROM python:3.14-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# --- deps layer (cached when pyproject.toml + stub src don't change) ---
# Editable install needs src/ to exist, so we stub it first.
# Real source gets copied below; the .pth file from editable install continues
# to point at /app/src so the real code picks up automatically.
COPY pyproject.toml ./
RUN mkdir -p src/sleuthgraph && touch src/sleuthgraph/__init__.py
RUN pip install --upgrade pip \
 && pip install -e ".[dev]"

# --- app layer (re-copy real src over the stub) ---
COPY src ./src
COPY alembic ./alembic
COPY alembic.ini ./
COPY tests ./tests

# Non-root user for runtime.
RUN useradd -m -u 1000 app \
 && chown -R app:app /app
USER app

EXPOSE 8000

CMD ["uvicorn", "sleuthgraph.main:app", "--host", "0.0.0.0", "--port", "8000"]
