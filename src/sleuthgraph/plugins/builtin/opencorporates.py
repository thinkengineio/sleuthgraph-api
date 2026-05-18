"""opencorporates plugin: PERSON|ORGANIZATION → ORGANIZATION matches.

Input: PERSON or ORGANIZATION label.
Output: ORGANIZATION EntityProposals with jurisdiction/company_number/status in attrs.
  No relationships are proposed — the match confidence (0.6) is too low to
  justify auto-linking; operators can link manually in the UI.

API docs: https://api.opencorporates.com/documentation/API-Reference
No auth required for the free-tier search endpoint.
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
)

MAX_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MiB
MAX_MATCHES = 50  # Free-tier search returns 30 by default; cap at 50


class OpenCorporatesPlugin(OSINTPlugin):
    """Company search via api.opencorporates.com."""

    name = "opencorporates"
    version = "0.1.0"
    entity_types_accepted = [EntityType.PERSON, EntityType.ORGANIZATION]
    entity_types_produced = [EntityType.ORGANIZATION]
    requires_credentials = False
    http_timeout_seconds = 30.0
    dispatch_mode = "sync"

    BASE_URL = "https://api.opencorporates.com/v0.4/companies/search"

    async def query(
        self,
        input_entity,
        credentials: dict | None,
        context: PluginContext,
    ) -> QueryResult:
        term = input_entity.label.strip()
        if not term:
            return QueryResult()

        url = f"{self.BASE_URL}?{urlencode({'q': term, 'format': 'json'})}"

        raw_bytes = b""
        companies: list[dict[str, Any]] = []
        fetch_status = "ok"
        try:
            raw_bytes, companies = await self._fetch(context.http_client, url)
        except httpx.HTTPError:
            fetch_status = "error"

        total_matches = len(companies)
        truncated = total_matches > MAX_MATCHES
        companies = companies[:MAX_MATCHES]

        entities: list[EntityProposal] = []
        for i, company in enumerate(companies):
            name = company.get("name")
            if not isinstance(name, str) or not name.strip():
                continue
            attrs = {
                "discovered_via": "opencorporates",
                "jurisdiction": company.get("jurisdiction_code"),
                "company_number": company.get("company_number"),
                "status": company.get("current_status"),
                "opencorporates_url": company.get("opencorporates_url"),
            }
            # Drop any None values so the JSON stays tidy
            attrs = {k: v for k, v in attrs.items() if v is not None}
            entities.append(
                EntityProposal(
                    ref=f"co-{i}",
                    type=EntityType.ORGANIZATION,
                    label=name.strip(),
                    attrs=attrs,
                    confidence=0.6,
                )
            )

        evidence = [
            EvidenceProposal(
                query=f"OpenCorporates search for {term}",
                payload=raw_bytes or b"{}",
                content_type="application/json",
                reproducibility_spec={
                    "url": url,
                    "method": "GET",
                    "queried_at": datetime.now(timezone.utc).isoformat(),
                    "match_count": len(entities),
                    "truncated": truncated,
                    "max_matches": MAX_MATCHES,
                    "fetch_status": fetch_status,
                },
                link_to_input=True,
            )
        ]

        return QueryResult(entities=entities, evidence=evidence)

    @retry(
        stop=(stop_after_attempt(3) | stop_after_delay(30)),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((httpx.TransportError, httpx.TimeoutException)),
        reraise=True,
    )
    async def _fetch(
        self, client: httpx.AsyncClient, url: str
    ) -> tuple[bytes, list[dict[str, Any]]]:
        """Streaming GET with 10 MiB cap. Returns (raw, companies_list)."""
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
                        f"opencorporates response exceeded {MAX_RESPONSE_BYTES} bytes"
                    )
                chunks.append(chunk)
        raw = b"".join(chunks)
        try:
            parsed: Any = json.loads(raw)
        except json.JSONDecodeError:
            return raw, []
        if not isinstance(parsed, dict):
            return raw, []
        results = parsed.get("results")
        if not isinstance(results, dict):
            return raw, []
        companies_wrapper = results.get("companies")
        if not isinstance(companies_wrapper, list):
            return raw, []
        companies: list[dict[str, Any]] = []
        for wrapper in companies_wrapper:
            if isinstance(wrapper, dict):
                company = wrapper.get("company")
                if isinstance(company, dict):
                    companies.append(company)
        return raw, companies
