"""crt.sh plugin: discover subdomains from Certificate Transparency logs.

Input: DOMAIN entity (e.g. example.com)
Output: one DOMAIN EntityProposal per unique subdomain found;
        one SUBDOMAIN_OF RelationshipProposal per subdomain -> input;
        one EvidenceProposal carrying the raw crt.sh JSON.
"""

from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime, timezone
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
    EntityProposal,
    EvidenceProposal,
    OSINTPlugin,
    PluginContext,
    QueryResult,
    RelationshipProposal,
)
from sleuthgraph.relationships.types import RelationshipType

MAX_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MiB
MAX_SUBDOMAINS = 1000  # Per-run cap; excess marked as truncated in evidence


class CrtShPlugin(OSINTPlugin):
    """Subdomain discovery via https://crt.sh Certificate Transparency search."""

    name = "crtsh"
    version = "0.1.0"
    entity_types_accepted = [EntityType.DOMAIN]
    entity_types_produced = [EntityType.DOMAIN]
    requires_credentials = False
    http_timeout_seconds = 30.0

    BASE_URL = "https://crt.sh/"

    async def query(
        self,
        input_entity,
        credentials: dict | None,
        context: PluginContext,
    ) -> QueryResult:
        domain = input_entity.label.strip().lower()
        if not domain:
            return QueryResult()

        url = f"{self.BASE_URL}?{urlencode({'q': domain, 'output': 'json'})}"
        raw_bytes, data = await self._fetch(context.http_client, url)

        subdomains, truncated = self._extract_subdomains(data, domain)

        entities = [
            EntityProposal(
                ref=f"sub-{i}",
                type=EntityType.DOMAIN,
                label=sub,
                attrs={"discovered_via": "crt.sh"},
                confidence=0.8,
            )
            for i, sub in enumerate(sorted(subdomains))
        ]

        relationships = [
            RelationshipProposal(
                src={"ref": f"sub-{i}"},
                dst={"input": True},
                rel_type=RelationshipType.SUBDOMAIN_OF,
                confidence=0.9,
            )
            for i in range(len(entities))
        ]

        evidence = [
            EvidenceProposal(
                query=f"crt.sh subdomain lookup for {domain}",
                payload=raw_bytes,
                content_type="application/json",
                reproducibility_spec={
                    "url": url,
                    "method": "GET",
                    "queried_at": datetime.now(timezone.utc).isoformat(),
                    "subdomain_count": len(entities),
                    "truncated": truncated,
                    "max_subdomains": MAX_SUBDOMAINS,
                },
                link_to_input=True,
            )
        ]

        return QueryResult(
            entities=entities, relationships=relationships, evidence=evidence,
        )

    @retry(
        stop=(stop_after_attempt(3) | stop_after_delay(30)),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((httpx.TransportError, httpx.TimeoutException)),
        reraise=True,
    )
    async def _fetch(
        self, client: httpx.AsyncClient, url: str,
    ) -> tuple[bytes, list[dict[str, Any]]]:
        """Stream the response body with a hard byte cap, then parse JSON."""
        chunks: list[bytes] = []
        total = 0
        async with client.stream(
            "GET", url, headers={"User-Agent": "sleuthgraph/0.1"},
        ) as resp:
            if resp.status_code == 429:
                delay = 0
                retry_after = resp.headers.get("Retry-After", "")
                try:
                    delay = min(int(retry_after), 30)
                except (ValueError, TypeError):
                    delay = 0
                if delay > 0:
                    await asyncio.sleep(delay)
                # Raise a retryable error so tenacity retries the request.
                raise httpx.TransportError(
                    f"crt.sh 429 rate-limited; slept {delay}s"
                )
            resp.raise_for_status()
            async for chunk in resp.aiter_bytes():
                total += len(chunk)
                if total > MAX_RESPONSE_BYTES:
                    raise httpx.HTTPError(
                        f"crt.sh response exceeded {MAX_RESPONSE_BYTES} bytes; aborted"
                    )
                chunks.append(chunk)
        raw = b"".join(chunks)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = []
        if not isinstance(data, list):
            data = []
        return raw, data

    @staticmethod
    def _extract_subdomains(data: list[dict], input_domain: str) -> tuple[set[str], bool]:
        """Return (subdomains, truncated_flag). Caps at MAX_SUBDOMAINS."""
        suffix = "." + input_domain
        result: set[str] = set()
        truncated = False

        for entry in data:
            name_value = entry.get("name_value", "")
            if not isinstance(name_value, str):
                continue
            for name in name_value.splitlines():
                name = name.strip().lower()
                if not name:
                    continue
                if name.startswith("*"):
                    continue
                if name == input_domain:
                    continue
                if not name.endswith(suffix):
                    continue
                if not re.match(r"^[a-z0-9._-]+$", name):
                    continue
                if len(result) >= MAX_SUBDOMAINS:
                    truncated = True
                    return result, truncated
                result.add(name)

        return result, truncated
