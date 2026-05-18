"""aleph_occrp plugin: PERSON|ORGANIZATION → Aleph investigation hits (evidence only).

Input: PERSON or ORGANIZATION label.
Output: Evidence-only; Aleph's /api/2/entities JSON is attached. Hit count
  and matched flag are mirrored into reproducibility_spec so the UI can
  highlight positive hits.

API docs: https://docs.aleph.occrp.org/developers/api/
  Public endpoint, no auth required (higher tiers need keys; we stay free).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    stop_after_delay,
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


class AlephOccrpPlugin(OSINTPlugin):
    """OCCRP Aleph investigation-database search."""

    name = "aleph_occrp"
    version = "0.1.0"
    entity_types_accepted = [EntityType.PERSON, EntityType.ORGANIZATION]
    entity_types_produced = []
    requires_credentials = False
    http_timeout_seconds = 30.0
    dispatch_mode = "sync"

    BASE_URL = "https://aleph.occrp.org/api/2/entities"

    async def query(
        self,
        input_entity,
        credentials: dict | None,
        context: PluginContext,
    ) -> QueryResult:
        term = input_entity.label.strip()
        if not term:
            return QueryResult()

        url = f"{self.BASE_URL}?{urlencode({'q': term, 'limit': 20})}"

        # Let httpx.HTTPError propagate — the plugin runner's error
        # taxonomy classifies it as upstream_http_error and marks the
        # run failed. Swallowing it here would surface as a "succeeded
        # with 0 hits" result, which is misleading for the UI and for
        # audit trails (Code-Important-8).
        raw_bytes, hit_count = await self._fetch(context.http_client, url)

        evidence = [
            EvidenceProposal(
                query=f"Aleph (OCCRP) search for {term}",
                payload=raw_bytes or b"{}",
                content_type="application/json",
                reproducibility_spec={
                    "url": url,
                    "method": "GET",
                    "queried_at": datetime.now(UTC).isoformat(),
                    "hit_count": hit_count,
                    "matched": hit_count > 0,
                    "fetch_status": "ok",
                },
                link_to_input=True,
            )
        ]
        return QueryResult(evidence=evidence)

    @retry(
        stop=(stop_after_attempt(3) | stop_after_delay(30)),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((httpx.TransportError, httpx.TimeoutException)),
        reraise=True,
    )
    async def _fetch(self, client: httpx.AsyncClient, url: str) -> tuple[bytes, int]:
        chunks: list[bytes] = []
        total = 0
        async with client.stream("GET", url, headers={"User-Agent": "sleuthgraph/0.1"}) as resp:
            resp.raise_for_status()
            async for chunk in resp.aiter_bytes():
                total += len(chunk)
                if total > MAX_RESPONSE_BYTES:
                    raise httpx.HTTPError(f"aleph response exceeded {MAX_RESPONSE_BYTES} bytes")
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
