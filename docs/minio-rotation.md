# MinIO Credential Rotation Runbook

Rotate MinIO (S3-compatible) credentials used by the API for evidence blob storage.

## Prerequisites

- `mc` CLI configured with the MinIO alias (e.g. `sleuthgraph`)
- Shell access to the host running docker-compose
- Access to the API's `.env` file

## Steps

### 1. Generate new credentials

```bash
NEW_ACCESS_KEY=$(openssl rand -hex 20)
NEW_SECRET_KEY=$(openssl rand -hex 32)
echo "Access: $NEW_ACCESS_KEY"
echo "Secret: $NEW_SECRET_KEY"
```

### 2. Update MinIO credentials in docker-compose `.env`

```bash
# Edit the .env file used by docker-compose:
#   MINIO_ROOT_USER=<NEW_ACCESS_KEY>
#   MINIO_ROOT_PASSWORD=<NEW_SECRET_KEY>
```

### 3. Restart MinIO

```bash
docker compose restart minio
```

### 4. Verify MinIO is healthy

```bash
mc alias set sleuthgraph http://localhost:9000 "$NEW_ACCESS_KEY" "$NEW_SECRET_KEY"
mc admin info sleuthgraph
```

Confirm the output shows the server is online and the `evidence` bucket is accessible:

```bash
mc ls sleuthgraph/evidence
```

### 5. Update the API's `.env` to match

```bash
# Edit the API .env:
#   S3_ACCESS_KEY=<NEW_ACCESS_KEY>
#   S3_SECRET_KEY=<NEW_SECRET_KEY>
```

### 6. Restart the API

```bash
docker compose restart api
```

### 7. Smoke-test evidence access

Upload a test evidence blob or verify an existing one:

```bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/health
# Expect: 200
```

Then confirm a presigned blob URL resolves (requires an authenticated session).

## Rollback

If the API cannot reach MinIO after rotation, revert both `.env` files to the previous credentials and restart both services.
