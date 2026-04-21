"""crt.sh plugin: discover subdomains from Certificate Transparency logs.

Input: DOMAIN entity (e.g. example.com)
Output: one DOMAIN EntityProposal per unique subdomain found;
        one SUBDOMAIN_OF RelationshipProposal per subdomain -> input;
        one EvidenceProposal carrying the raw crt.sh JSON.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
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

        url = f"{self.BASE_URL}?q={domain}&output=json"
        raw_bytes, data = await self._fetch(context.http_client, url)

        subdomains = self._extract_subdomains(data, domain)

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
                },
                link_to_input=True,
            )
        ]

        return QueryResult(
            entities=entities, relationships=relationships, evidence=evidence,
        )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((httpx.HTTPError,)),
        reraise=True,
    )
    async def _fetch(
        self, client: httpx.AsyncClient, url: str,
    ) -> tuple[bytes, list[dict[str, Any]]]:
        resp = await client.get(url, headers={"User-Agent": "sleuthgraph/0.1"})
        resp.raise_for_status()
        raw = resp.content
        try:
            data = resp.json()
        except json.JSONDecodeError:
            data = []
        if not isinstance(data, list):
            data = []
        return raw, data

    @staticmethod
    def _extract_subdomains(data: list[dict], input_domain: str) -> set[str]:
        """Flatten crt.sh entries -> set of subdomain strings strictly below input_domain."""
        suffix = "." + input_domain
        result: set[str] = set()

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
                result.add(name)

        return result
