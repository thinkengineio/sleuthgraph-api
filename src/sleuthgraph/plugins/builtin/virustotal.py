"""VirusTotal plugin: BYOK enrichment for DOMAIN / IP_ADDRESS / URL entities.

Input: DOMAIN | IP_ADDRESS | URL entity
Output:
  - For DOMAIN: IP_ADDRESS entities (RESOLVES_TO), DOMAIN entities (SUBDOMAIN_OF),
    URL entities from detected_urls.
  - For IP_ADDRESS: DOMAIN entities (RESOLVES_TO), URL entities from detected_urls.
  - For URL: analysis results as evidence only (no new entities produced).

API: VirusTotal API v3 — https://www.virustotal.com/api/v3/
Auth: x-apikey header (BYOK)
"""

from __future__ import annotations

import base64
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
MAX_ENTITIES = 50  # Per-run cap across all categories

# Strict LDH domain regex (same as dns_whois).
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)

# Loose IPv4 regex for filtering resolutions.
_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# IPv6 (simplified: contains colons, only hex digits and colons).
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")

# Input validation for IP addresses flowing into URL paths.
# Allows only hex digits, dots, and colons — prevents path/query injection.
_IP_INPUT_RE = re.compile(r"^[0-9a-fA-F.:]+$")


def _is_ip(value: str) -> bool:
    return bool(_IPV4_RE.match(value) or _IPV6_RE.match(value))


def _url_id(url: str) -> str:
    """Compute VT v3 URL identifier: base64url without padding."""
    return base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()


class VirusTotalPlugin(BYOKPlugin):
    """VirusTotal v3 BYOK enrichment plugin."""

    name = "virustotal"
    version = "0.1.0"
    entity_types_accepted = [EntityType.DOMAIN, EntityType.IP_ADDRESS, EntityType.URL]
    entity_types_produced = [EntityType.DOMAIN, EntityType.IP_ADDRESS, EntityType.URL]
    requires_credentials = True
    credential_name = "virustotal"
    credential_url = "https://www.virustotal.com/gui/my-apikey"
    http_timeout_seconds = 30.0

    BASE_URL = "https://www.virustotal.com/api/v3"

    async def query(
        self,
        input_entity,
        credentials: dict | None,
        context: PluginContext,
    ) -> QueryResult:
        api_key = credentials["api_key"]  # BYOK — always present
        entity_type = EntityType(input_entity.type)
        label = input_entity.label.strip()
        if not label:
            return QueryResult()

        if entity_type == EntityType.DOMAIN:
            return await self._query_domain(label, api_key, context)
        elif entity_type == EntityType.IP_ADDRESS:
            return await self._query_ip(label, api_key, context)
        elif entity_type == EntityType.URL:
            return await self._query_url(label, api_key, context)
        else:
            return QueryResult()

    async def _query_domain(
        self, domain: str, api_key: str, context: PluginContext,
    ) -> QueryResult:
        domain = domain.lower().rstrip(".")
        # Security: reject anything that is not a strict LDH domain before it
        # flows into the API URL path (prevents path-component injection).
        if not _DOMAIN_RE.match(domain):
            return QueryResult()
        url = f"{self.BASE_URL}/domains/{domain}"
        raw_bytes, data = await self._fetch(context.http_client, url, api_key)

        entities: list[EntityProposal] = []
        relationships: list[RelationshipProposal] = []
        entity_count = 0
        truncated = False

        # Extract resolved IPs from last_dns_records
        dns_records = data.get("data", {}).get("attributes", {}).get(
            "last_dns_records", []
        )
        for rec in dns_records:
            if entity_count >= MAX_ENTITIES:
                truncated = True
                break
            rtype = rec.get("type", "")
            value = rec.get("value", "").strip()
            if rtype in ("A", "AAAA") and value and _is_ip(value):
                ref = f"ip-{entity_count}"
                entities.append(
                    EntityProposal(
                        ref=ref,
                        type=EntityType.IP_ADDRESS,
                        label=value,
                        attrs={"discovered_via": "virustotal", "rdtype": rtype},
                        confidence=0.85,
                    )
                )
                relationships.append(
                    RelationshipProposal(
                        src={"input": True},
                        dst={"ref": ref},
                        rel_type=RelationshipType.RESOLVES_TO,
                        confidence=0.85,
                    )
                )
                entity_count += 1

        # Extract subdomains
        subdomains = data.get("data", {}).get("attributes", {}).get("last_dns_records", [])
        for rec in subdomains:
            if entity_count >= MAX_ENTITIES:
                truncated = True
                break
            rtype = rec.get("type", "")
            value = rec.get("value", "").strip().rstrip(".").lower()
            if rtype == "CNAME" and value and _DOMAIN_RE.match(value):
                if value != domain and value.endswith(f".{domain}"):
                    ref = f"sub-{entity_count}"
                    entities.append(
                        EntityProposal(
                            ref=ref,
                            type=EntityType.DOMAIN,
                            label=value,
                            attrs={"discovered_via": "virustotal"},
                            confidence=0.8,
                        )
                    )
                    relationships.append(
                        RelationshipProposal(
                            src={"ref": ref},
                            dst={"input": True},
                            rel_type=RelationshipType.SUBDOMAIN_OF,
                            confidence=0.8,
                        )
                    )
                    entity_count += 1

        # VT v3 does not return detected_urls inline on /domains/{domain};
        # that requires a separate /relationships call which would be a
        # second API hit. We skip fabricating entities we don't have data for.

        evidence = [
            EvidenceProposal(
                query=f"VirusTotal domain lookup for {domain}",
                payload=raw_bytes,
                content_type="application/json",
                reproducibility_spec={
                    "url": url,
                    "method": "GET",
                    "queried_at": datetime.now(timezone.utc).isoformat(),
                    "entity_count": entity_count,
                    "truncated": truncated,
                    "max_entities": MAX_ENTITIES,
                },
                link_to_input=True,
            )
        ]

        return QueryResult(
            entities=entities, relationships=relationships, evidence=evidence,
        )

    async def _query_ip(
        self, ip: str, api_key: str, context: PluginContext,
    ) -> QueryResult:
        # Security: reject labels with path/query injection characters before
        # they flow into the API URL (CWE-20, CWE-74).
        if not _IP_INPUT_RE.match(ip):
            return QueryResult()
        url = f"{self.BASE_URL}/ip_addresses/{ip}"
        raw_bytes, data = await self._fetch(context.http_client, url, api_key)

        entities: list[EntityProposal] = []
        relationships: list[RelationshipProposal] = []
        entity_count = 0
        truncated = False

        # VT v3 ip_addresses endpoint: resolutions are via /relationships.
        # Extract hostnames from last_https_certificate subject alt names.
        cert = data.get("data", {}).get("attributes", {}).get(
            "last_https_certificate", {}
        )
        alt_names = (
            cert.get("extensions", {}).get("subject_alternative_name", [])
            if isinstance(cert, dict)
            else []
        )
        for name in alt_names:
            if entity_count >= MAX_ENTITIES:
                truncated = True
                break
            name = name.strip().rstrip(".").lower()
            if name and _DOMAIN_RE.match(name):
                ref = f"domain-{entity_count}"
                entities.append(
                    EntityProposal(
                        ref=ref,
                        type=EntityType.DOMAIN,
                        label=name,
                        attrs={"discovered_via": "virustotal"},
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

        evidence = [
            EvidenceProposal(
                query=f"VirusTotal IP lookup for {ip}",
                payload=raw_bytes,
                content_type="application/json",
                reproducibility_spec={
                    "url": url,
                    "method": "GET",
                    "queried_at": datetime.now(timezone.utc).isoformat(),
                    "entity_count": entity_count,
                    "truncated": truncated,
                    "max_entities": MAX_ENTITIES,
                },
                link_to_input=True,
            )
        ]

        return QueryResult(
            entities=entities, relationships=relationships, evidence=evidence,
        )

    async def _query_url(
        self, url_label: str, api_key: str, context: PluginContext,
    ) -> QueryResult:
        """URL analysis — returns evidence only (analysis stats), no new entities."""
        url_identifier = _url_id(url_label)
        url = f"{self.BASE_URL}/urls/{url_identifier}"
        raw_bytes, data = await self._fetch(context.http_client, url, api_key)

        evidence = [
            EvidenceProposal(
                query=f"VirusTotal URL analysis for {url_label[:120]}",
                payload=raw_bytes,
                content_type="application/json",
                reproducibility_spec={
                    "url": url,
                    "method": "GET",
                    "queried_at": datetime.now(timezone.utc).isoformat(),
                    "entity_count": 0,
                    "truncated": False,
                    "max_entities": MAX_ENTITIES,
                },
                link_to_input=True,
            )
        ]

        return QueryResult(evidence=evidence)

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((httpx.TransportError, httpx.TimeoutException)),
        reraise=True,
    )
    async def _fetch(
        self, client: httpx.AsyncClient, url: str, api_key: str,
    ) -> tuple[bytes, dict[str, Any]]:
        """Streaming GET with auth header and 10 MiB cap."""
        chunks: list[bytes] = []
        total = 0
        async with client.stream(
            "GET",
            url,
            headers={
                "x-apikey": api_key,
                "User-Agent": "sleuthgraph/0.1",
            },
        ) as resp:
            resp.raise_for_status()
            async for chunk in resp.aiter_bytes():
                total += len(chunk)
                if total > MAX_RESPONSE_BYTES:
                    raise httpx.HTTPError(
                        f"VirusTotal response exceeded {MAX_RESPONSE_BYTES} bytes; aborted"
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
