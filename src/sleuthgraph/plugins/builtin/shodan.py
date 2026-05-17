"""Shodan plugin: BYOK enrichment for IP_ADDRESS entities.

Input: IP_ADDRESS entity
Output:
  - DOMAIN EntityProposals for discovered hostnames (RESOLVES_TO relationships)
  - EvidenceProposal with raw JSON (open ports, services, vulns stored in
    evidence payload + reproducibility_spec summary, not as separate entities
    since ports/services are not entity types in the graph model)

API: Shodan REST — https://api.shodan.io/
Auth: query-string ``key`` parameter (BYOK)

SECURITY NOTE: Shodan passes the API key in the URL query string. The
``reproducibility_spec`` stores a redacted URL (``key=REDACTED``) to prevent
credential leakage into the evidence ledger.
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
    PluginContext,
    QueryResult,
    RelationshipProposal,
)
from sleuthgraph.plugins.byok import BYOKPlugin
from sleuthgraph.relationships.types import RelationshipType

MAX_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MiB
MAX_ENTITIES = 50  # Per-run cap

# Strict LDH domain regex (consistent with dns_whois / virustotal plugins).
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)

# Input validation for IP addresses flowing into URL paths.
# Allows only hex digits, dots, and colons — prevents path/query injection.
_IP_INPUT_RE = re.compile(r"^[0-9a-fA-F.:]+$")


class ShodanPlugin(BYOKPlugin):
    """Shodan host enrichment for IP addresses."""

    name = "shodan"
    version = "0.1.0"
    entity_types_accepted = [EntityType.IP_ADDRESS]
    entity_types_produced = [EntityType.DOMAIN]
    requires_credentials = True
    credential_name = "shodan"
    credential_url = "https://account.shodan.io/"
    http_timeout_seconds = 30.0

    BASE_URL = "https://api.shodan.io"

    async def query(
        self,
        input_entity,
        credentials: dict | None,
        context: PluginContext,
    ) -> QueryResult:
        api_key = credentials["api_key"]  # BYOK — always present
        ip = input_entity.label.strip()
        if not ip:
            return QueryResult()

        # Security: reject labels with path/query injection characters before
        # they flow into the API URL. An entity label like "1.2.3.4?key=evil"
        # would inject a duplicate query param (CWE-20, CWE-74).
        if not _IP_INPUT_RE.match(ip):
            return QueryResult()

        url = f"{self.BASE_URL}/shodan/host/{ip}?key={api_key}"
        # Redacted URL for evidence — never store the real API key.
        redacted_url = f"{self.BASE_URL}/shodan/host/{ip}?key=REDACTED"

        raw_bytes, data = await self._fetch(context.http_client, url)

        entities: list[EntityProposal] = []
        relationships: list[RelationshipProposal] = []
        entity_count = 0
        truncated = False

        # Extract hostnames
        hostnames = data.get("hostnames", [])
        if not isinstance(hostnames, list):
            hostnames = []
        seen_hostnames: set[str] = set()

        for hostname in hostnames:
            if entity_count >= MAX_ENTITIES:
                truncated = True
                break
            if not isinstance(hostname, str):
                continue
            hostname = hostname.strip().rstrip(".").lower()
            if not hostname or not _DOMAIN_RE.match(hostname):
                continue
            if hostname in seen_hostnames:
                continue
            seen_hostnames.add(hostname)

            ref = f"host-{entity_count}"
            entities.append(
                EntityProposal(
                    ref=ref,
                    type=EntityType.DOMAIN,
                    label=hostname,
                    attrs={"discovered_via": "shodan"},
                    confidence=0.8,
                )
            )
            relationships.append(
                RelationshipProposal(
                    src={"ref": ref},
                    dst={"input": True},
                    rel_type=RelationshipType.RESOLVES_TO,
                    confidence=0.8,
                )
            )
            entity_count += 1

        # Also check domains (Shodan sometimes returns a separate list)
        domains = data.get("domains", [])
        if not isinstance(domains, list):
            domains = []

        for domain in domains:
            if entity_count >= MAX_ENTITIES:
                truncated = True
                break
            if not isinstance(domain, str):
                continue
            domain = domain.strip().rstrip(".").lower()
            if not domain or not _DOMAIN_RE.match(domain):
                continue
            if domain in seen_hostnames:
                continue
            seen_hostnames.add(domain)

            ref = f"host-{entity_count}"
            entities.append(
                EntityProposal(
                    ref=ref,
                    type=EntityType.DOMAIN,
                    label=domain,
                    attrs={"discovered_via": "shodan"},
                    confidence=0.7,
                )
            )
            relationships.append(
                RelationshipProposal(
                    src={"ref": ref},
                    dst={"input": True},
                    rel_type=RelationshipType.RESOLVES_TO,
                    confidence=0.7,
                )
            )
            entity_count += 1

        # Summarize ports/services/vulns for reproducibility_spec
        # (these are enrichment data on the input entity, stored in evidence
        # since the proposal API has no input-entity mutation mechanism)
        ports = data.get("ports", [])
        vulns = data.get("vulns", [])
        services_summary = []
        for service_data in data.get("data", []):
            if isinstance(service_data, dict):
                port = service_data.get("port")
                product = service_data.get("product", "")
                transport = service_data.get("transport", "tcp")
                services_summary.append({
                    "port": port,
                    "transport": transport,
                    "product": product,
                })

        evidence = [
            EvidenceProposal(
                query=f"Shodan host lookup for {ip}",
                payload=raw_bytes,
                content_type="application/json",
                reproducibility_spec={
                    "url": redacted_url,
                    "method": "GET",
                    "queried_at": datetime.now(timezone.utc).isoformat(),
                    "entity_count": entity_count,
                    "truncated": truncated,
                    "max_entities": MAX_ENTITIES,
                    "open_ports": ports if isinstance(ports, list) else [],
                    "vulns": vulns if isinstance(vulns, list) else [],
                    "services_summary": services_summary[:20],  # cap summary
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
    ) -> tuple[bytes, dict[str, Any]]:
        """Streaming GET with 10 MiB cap."""
        chunks: list[bytes] = []
        total = 0
        async with client.stream(
            "GET",
            url,
            headers={"User-Agent": "sleuthgraph/0.1"},
        ) as resp:
            resp.raise_for_status()
            async for chunk in resp.aiter_bytes():
                total += len(chunk)
                if total > MAX_RESPONSE_BYTES:
                    raise httpx.HTTPError(
                        f"Shodan response exceeded {MAX_RESPONSE_BYTES} bytes; aborted"
                    )
                chunks.append(chunk)
        raw = b"".join(chunks)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = {}
        if not isinstance(data, dict):
            data = {}
        return raw, data
