"""opensanctions plugin: PERSON|ORGANIZATION → sanctions evidence.

Input: PERSON or ORGANIZATION label.
Output: Evidence-only. Full API response is attached with matched=True|False
  so the UI can highlight sanctioned entities. Operator decides whether to
  materialize hits as explicit ORGANIZATION entities.

API docs: https://www.opensanctions.org/docs/api/
  Public endpoint, no auth required.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlencode

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from sleuthgraph.entities.types import EntityType
from sleuthgraph.plugins.base import (
    EvidenceProposal,
    OSINTPlugin,
    PluginContext,
    QueryResult,
)

MAX_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MiB


class OpenSanctionsPlugin(OSINTPlugin):
    """Sanctions / PEP list lookup via api.opensanctions.org."""

    name = "opensanctions"
    version = "0.1.0"
    entity_types_accepted = [EntityType.PERSON, EntityType.ORGANIZATION]
    entity_types_produced = []
    requires_credentials = False
    http_timeout_seconds = 30.0
    dispatch_mode = "sync"

    BASE_URL = "https://api.opensanctions.org/search/default"

    async def query(
        self,
        input_entity,
        credentials: dict | None,
        context: PluginContext,
    ) -> QueryResult:
        term = input_entity.label.strip()
        if not term:
            return QueryResult()

        url = f"{self.BASE_URL}?{urlencode({'q': term, 'limit': 10})}"

        raw_bytes = b""
        hit_count = 0
        fetch_status = "ok"
        try:
            raw_bytes, hit_count = await self._fetch(context.http_client, url)
        except httpx.HTTPError:
            fetch_status = "error"

        matched = hit_count > 0

        evidence = [
            EvidenceProposal(
                query=f"OpenSanctions search for {term}",
                payload=raw_bytes or b"{}",
                content_type="application/json",
                reproducibility_spec={
                    "url": url,
                    "method": "GET",
                    "queried_at": datetime.now(timezone.utc).isoformat(),
                    "hit_count": hit_count,
                    "matched": matched,
                    "fetch_status": fetch_status,
                },
                link_to_input=True,
            )
        ]

        return QueryResult(evidence=evidence)

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((httpx.HTTPError,)),
        reraise=True,
    )
    async def _fetch(
        self, client: httpx.AsyncClient, url: str
    ) -> tuple[bytes, int]:
        """Streaming GET with 10 MiB cap. Returns (raw_bytes, hit_count)."""
        chunks: list[bytes] = []
        total = 0
        async with client.stream(
            "GET", url, headers={"User-Agent": "sleuthgraph/0.1"}
        ) as resp:
            resp.raise_for_status()
            async for chunk in resp.aiter_bytes():
                total += len(chunk)
                if total > MAX_RESPONSE_BYTES:
                    raise httpx.HTTPError(
                        f"opensanctions response exceeded {MAX_RESPONSE_BYTES} bytes"
                    )
                chunks.append(chunk)
        raw = b"".join(chunks)
        try:
            parsed: Any = json.loads(raw)
        except json.JSONDecodeError:
            return raw, 0
        hit_count = 0
        if isinstance(parsed, dict):
            results = parsed.get("results")
            if isinstance(results, list):
                hit_count = len(results)
        return raw, hit_count
