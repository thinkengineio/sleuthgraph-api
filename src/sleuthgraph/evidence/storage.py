"""MinIO / S3-compatible object storage wrapper for evidence blobs.

All objects live in a single bucket (configured via s3_bucket in settings).
Keys use a stable convention so the same payload produces the same key:

    case/{case_id}/ev/{sha256_hex}
"""

from __future__ import annotations

import aioboto3
from botocore.client import Config
from botocore.exceptions import ClientError

from sleuthgraph.config import get_settings


def build_key(case_id: str, sha256_hex: str) -> str:
    """Stable evidence key; same payload, same key within a case."""
    return f"case/{case_id}/ev/{sha256_hex}"


class EvidenceStorage:
    """Thin async facade for MinIO/S3. Config from app settings."""

    def __init__(self, *, endpoint: str | None = None, access_key: str | None = None,
                 secret_key: str | None = None, bucket: str | None = None,
                 region: str | None = None) -> None:
        s = get_settings()
        self.endpoint = endpoint or s.s3_endpoint
        self.access_key = access_key or s.s3_access_key
        self.secret_key = secret_key or s.s3_secret_key
        self.bucket = bucket or s.s3_bucket
        self.region = region or s.s3_region
        self._session = aioboto3.Session()

    def _client_kwargs(self) -> dict:
        return dict(
            service_name="s3",
            endpoint_url=self.endpoint,
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            region_name=self.region,
            # path-style for MinIO + OCI S3-compat.
            # request/response checksum "when_required" stops boto3 from
            # emitting aws-chunked + x-amz-trailer-checksum headers. OCI
            # Object Storage rejects those with MissingContentLength; also
            # aiohttp raises when ContentLength and Transfer-Encoding:
            # chunked are both set.
            config=Config(
                s3={"addressing_style": "path"},
                request_checksum_calculation="when_required",
                response_checksum_validation="when_required",
            ),
        )

    async def exists(self, key: str) -> bool:
        async with self._session.client(**self._client_kwargs()) as client:
            try:
                await client.head_object(Bucket=self.bucket, Key=key)
                return True
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "")
                if code in ("404", "NoSuchKey", "NotFound"):
                    return False
                raise

    async def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> None:
        """Idempotent upload. Skip network if object with same size exists."""
        async with self._session.client(**self._client_kwargs()) as client:
            # Short-circuit for already-present blobs.
            try:
                head = await client.head_object(Bucket=self.bucket, Key=key)
                if head.get("ContentLength") == len(data):
                    return
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "")
                if code not in ("404", "NoSuchKey", "NotFound"):
                    raise

            # With checksum_calculation=when_required set on the client
            # Config, boto3 emits a plain Content-Length header (no
            # aws-chunked). Works on AWS, MinIO, and OCI S3-compat.
            await client.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=data,
                ContentType=content_type,
            )

    async def get(self, key: str) -> bytes:
        async with self._session.client(**self._client_kwargs()) as client:
            resp = await client.get_object(Bucket=self.bucket, Key=key)
            async with resp["Body"] as stream:
                return await stream.read()

    async def presign_get(self, key: str, expires_in: int = 300) -> str:
        """Pre-signed URL for GET; default 5 min."""
        async with self._session.client(**self._client_kwargs()) as client:
            return await client.generate_presigned_url(
                "get_object",
                Params={"Bucket": self.bucket, "Key": key},
                ExpiresIn=expires_in,
            )
