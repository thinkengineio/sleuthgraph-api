"""dns_whois plugin: DOMAIN → IP_ADDRESS + nameserver/MX DOMAINs + RDAP evidence.

Input: DOMAIN entity (e.g. example.com)
Output:
  - IP_ADDRESS EntityProposals from A/AAAA records (+ RESOLVES_TO relationships)
  - DOMAIN EntityProposals for NS + MX hosts (+ ASSOCIATED_WITH relationships
    with attrs.role=nameserver|mx)
  - One EvidenceProposal carrying the RDAP JSON (registrant data, etc.)

API docs:
  - DNS resolver: dnspython (stdlib socket-backed)
  - RDAP: https://rdap.org/domain/<domain>  (IANA-bootstrapped, no key)
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import dns.asyncresolver
import dns.exception
import dns.resolver
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

MAX_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MiB RDAP cap
DNS_LIFETIME_SECONDS = 5.0

# Strict LDH domain regex (RFC 1035 + RFC 5890 punycode tolerance).
# Total length <= 253 chars; each label 1–63 LDH chars, no leading/trailing hyphen;
# at least two labels (there must be a dot).
# This prevents RDAP URL path-component injection via `entity.label`
# (CWE-20: improper input validation, CWE-74: injection).
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)

_DNS_TOLERATED = (
    dns.resolver.NXDOMAIN,
    dns.resolver.NoAnswer,
    dns.resolver.NoNameservers,
    dns.exception.Timeout,
)


class DnsWhoisPlugin(OSINTPlugin):
    """DNS + RDAP enrichment for DOMAIN entities."""

    name = "dns_whois"
    version = "0.1.0"
    entity_types_accepted = [EntityType.DOMAIN]
    entity_types_produced = [EntityType.DOMAIN, EntityType.IP_ADDRESS]
    requires_credentials = False
    http_timeout_seconds = 30.0
    dispatch_mode = "sync"

    RDAP_URL_TEMPLATE = "https://rdap.org/domain/{domain}"

    async def query(
        self,
        input_entity,
        credentials: dict | None,
        context: PluginContext,
    ) -> QueryResult:
        domain = input_entity.label.strip().lower().rstrip(".")
        if not domain:
            return QueryResult()

        # Security: reject anything that is not a strict LDH domain before it
        # flows into the RDAP URL template. Treat as an empty result rather
        # than raising — an arbitrary label-shaped input from elsewhere in the
        # system should silently produce nothing instead of failing the run.
        if not _DOMAIN_RE.match(domain):
            return QueryResult()

        entities: list[EntityProposal] = []
        relationships: list[RelationshipProposal] = []

        a_records = await self._try_resolve(domain, "A")
        aaaa_records = await self._try_resolve(domain, "AAAA")
        ns_records = await self._try_resolve(domain, "NS")
        mx_records = await self._try_resolve_mx(domain)

        for i, ip in enumerate(a_records):
            ref = f"ip-a-{i}"
            entities.append(
                EntityProposal(
                    ref=ref,
                    type=EntityType.IP_ADDRESS,
                    label=ip,
                    attrs={"discovered_via": "dns_whois", "rdtype": "A"},
                    confidence=0.95,
                )
            )
            relationships.append(
                RelationshipProposal(
                    src={"ref": ref},
                    dst={"input": True},
                    rel_type=RelationshipType.RESOLVES_TO,
                    attrs={"rdtype": "A"},
                    confidence=0.95,
                )
            )

        for i, ip in enumerate(aaaa_records):
            ref = f"ip-aaaa-{i}"
            entities.append(
                EntityProposal(
                    ref=ref,
                    type=EntityType.IP_ADDRESS,
                    label=ip,
                    attrs={"discovered_via": "dns_whois", "rdtype": "AAAA"},
                    confidence=0.95,
                )
            )
            relationships.append(
                RelationshipProposal(
                    src={"ref": ref},
                    dst={"input": True},
                    rel_type=RelationshipType.RESOLVES_TO,
                    attrs={"rdtype": "AAAA"},
                    confidence=0.95,
                )
            )

        for i, ns in enumerate(ns_records):
            ref = f"ns-{i}"
            entities.append(
                EntityProposal(
                    ref=ref,
                    type=EntityType.DOMAIN,
                    label=ns,
                    attrs={"discovered_via": "dns_whois", "role": "nameserver"},
                    confidence=0.9,
                )
            )
            relationships.append(
                RelationshipProposal(
                    src={"ref": ref},
                    dst={"input": True},
                    rel_type=RelationshipType.ASSOCIATED_WITH,
                    attrs={"role": "nameserver"},
                    confidence=0.9,
                )
            )

        for i, (preference, host) in enumerate(mx_records):
            ref = f"mx-{i}"
            entities.append(
                EntityProposal(
                    ref=ref,
                    type=EntityType.DOMAIN,
                    label=host,
                    attrs={
                        "discovered_via": "dns_whois",
                        "role": "mx",
                        "preference": preference,
                    },
                    confidence=0.9,
                )
            )
            relationships.append(
                RelationshipProposal(
                    src={"ref": ref},
                    dst={"input": True},
                    rel_type=RelationshipType.ASSOCIATED_WITH,
                    attrs={"role": "mx", "preference": preference},
                    confidence=0.9,
                )
            )

        # RDAP — evidence only, never raises.
        # Defense in depth: quote the already-validated domain with
        # safe="" so no character can escape the path component.
        rdap_url = self.RDAP_URL_TEMPLATE.format(domain=quote(domain, safe=""))
        rdap_raw: bytes = b""
        rdap_ok = False
        try:
            rdap_raw, rdap_ok = await self._fetch_rdap(context.http_client, rdap_url)
        except Exception:  # noqa: BLE001 — RDAP is supplementary; any failure tolerable
            rdap_raw = b""
            rdap_ok = False

        counts = {
            "a": len(a_records),
            "aaaa": len(aaaa_records),
            "ns": len(ns_records),
            "mx": len(mx_records),
        }

        evidence = [
            EvidenceProposal(
                query=f"DNS + RDAP lookup for {domain}",
                payload=rdap_raw or b"{}",
                content_type="application/json",
                reproducibility_spec={
                    "url": rdap_url,
                    "method": "GET",
                    "queried_at": datetime.now(timezone.utc).isoformat(),
                    "dns_record_counts": counts,
                    "rdap_status": "ok" if rdap_ok else "unavailable",
                    "max_response_bytes": MAX_RESPONSE_BYTES,
                },
                link_to_input=True,
            )
        ]

        return QueryResult(
            entities=entities, relationships=relationships, evidence=evidence
        )

    @staticmethod
    async def _try_resolve(domain: str, rdtype: str) -> list[str]:
        try:
            answers = await dns.asyncresolver.resolve(
                domain, rdtype, lifetime=DNS_LIFETIME_SECONDS
            )
        except _DNS_TOLERATED:
            return []
        except Exception:  # noqa: BLE001 — never let DNS noise crash plugin
            return []
        out: list[str] = []
        for a in answers:
            text = a.to_text().strip().rstrip(".")
            if text:
                out.append(text)
        return out

    @staticmethod
    async def _try_resolve_mx(domain: str) -> list[tuple[int, str]]:
        try:
            answers = await dns.asyncresolver.resolve(
                domain, "MX", lifetime=DNS_LIFETIME_SECONDS
            )
        except _DNS_TOLERATED:
            return []
        except Exception:  # noqa: BLE001
            return []
        out: list[tuple[int, str]] = []
        for a in answers:
            host = a.exchange.to_text().strip().rstrip(".")
            if host:
                out.append((int(a.preference), host))
        return out

    @retry(
        stop=(stop_after_attempt(3) | stop_after_delay(30)),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((httpx.TransportError, httpx.TimeoutException)),
        reraise=True,
    )
    async def _fetch_rdap(
        self, client: httpx.AsyncClient, url: str
    ) -> tuple[bytes, bool]:
        """Streaming RDAP fetch with 10 MiB cap.

        Returns (raw_bytes, ok) where ok=True only when status 200 + parseable JSON.
        A 404 on the registry is common (not every domain is registered) and
        yields (b"", False) rather than raising.
        """
        chunks: list[bytes] = []
        total = 0
        async with client.stream(
            "GET",
            url,
            headers={
                "User-Agent": "sleuthgraph/0.1",
                "Accept": "application/rdap+json",
            },
        ) as resp:
            if resp.status_code == 404:
                return b"", False
            resp.raise_for_status()
            async for chunk in resp.aiter_bytes():
                total += len(chunk)
                if total > MAX_RESPONSE_BYTES:
                    raise httpx.HTTPError(
                        f"rdap response exceeded {MAX_RESPONSE_BYTES} bytes; aborted"
                    )
                chunks.append(chunk)
        raw = b"".join(chunks)
        ok: bool
        try:
            parsed: Any = json.loads(raw)
            ok = isinstance(parsed, dict)
        except json.JSONDecodeError:
            ok = False
        return raw, ok
