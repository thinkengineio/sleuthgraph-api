"""HIBP plugin: BYOK breach lookup for EMAIL entities.

Input: EMAIL entity
Output:
  - No new entities (breaches are metadata, not graph entities).
  - One EvidenceProposal containing the full breach list as JSON payload when
    breaches exist.  A 404 from HIBP means "no breaches found" and returns an
    empty QueryResult (no evidence row).  This is intentional — absence of a
    breach is not itself a finding worth recording in the evidence ledger.

API: Have I Been Pwned v3 — https://haveibeenpwned.com/api/v3/
  GET /breachedaccount/{account}?truncateResponse=false
Auth: hibp-api-key header (BYOK)

SECURITY NOTES:
  - Email is URL-encoded before path interpolation (CWE-74).  RFC 5321 allows
    "+" in the local part which would otherwise be interpreted as a space.
  - Strict RFC-5321-lite regex validation runs *before* URL construction to
    reject script/path injection payloads.
  - API key is sent in the hibp-api-key header, never in the URL.
  - 404 returns cleanly — tenacity never retries it.
  - 429 raises HTTPStatusError which tenacity retries with back-off.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from urllib.parse import quote

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
    PluginContext,
    QueryResult,
)
from sleuthgraph.plugins.byok import BYOKPlugin

MAX_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MiB

# RFC-5321-lite email regex: accepts common local-part characters and a
# multi-label domain.  Strict enough to reject script injection, path
# traversal, and query-string injection attempts.
_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$"
)


class HIBPPlugin(BYOKPlugin):
    """Have I Been Pwned breach database search for EMAIL entities."""

    name = "hibp"
    version = "0.1.0"
    entity_types_accepted = [EntityType.EMAIL]
    entity_types_produced = []  # HIBP returns breach metadata, not graph entities
    requires_credentials = True
    credential_name = "hibp"
    credential_url = "https://haveibeenpwned.com/API/Key"
    http_timeout_seconds = 15.0

    BASE_URL = "https://haveibeenpwned.com/api/v3"

    async def query(
        self,
        input_entity,
        credentials: dict | None,
        context: PluginContext,
    ) -> QueryResult:
        api_key = credentials["api_key"]  # BYOK — always present
        email = input_entity.label.strip()
        if not email:
            return QueryResult()

        # Security: validate before allowing the value near URL construction.
        if not _EMAIL_RE.match(email):
            return QueryResult()

        # URL-encode the email to handle "+" and other special chars safely.
        encoded = quote(email, safe="")
        url = f"{self.BASE_URL}/breachedaccount/{encoded}?truncateResponse=false"

        result = await self._fetch(context.http_client, url, api_key)

        # None signals "404 — no breaches found" — return empty result (not an error).
        if result is None:
            return QueryResult()

        raw_bytes, breaches = result

        breach_names = [b.get("Name", "") for b in breaches if isinstance(b, dict)]
        data_classes: list[str] = []
        for breach in breaches:
            if isinstance(breach, dict):
                data_classes.extend(
                    dc for dc in breach.get("DataClasses", [])
                    if isinstance(dc, str)
                )
        # Deduplicate while preserving insertion order.
        seen: set[str] = set()
        unique_data_classes: list[str] = []
        for dc in data_classes:
            if dc not in seen:
                seen.add(dc)
                unique_data_classes.append(dc)

        evidence = [
            EvidenceProposal(
                query=f"HIBP breach lookup for {email}",
                payload=raw_bytes,
                content_type="application/json",
                reproducibility_spec={
                    "url": url,
                    "method": "GET",
                    "queried_at": datetime.now(timezone.utc).isoformat(),
                    "breach_count": len(breaches),
                    "breach_names": breach_names,
                    "data_classes": unique_data_classes,
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
    async def _fetch(
        self,
        client: httpx.AsyncClient,
        url: str,
        api_key: str,
    ) -> tuple[bytes, list] | None:
        """Streaming GET with HIBP auth headers and 10 MiB cap.

        Returns:
          - ``(raw_bytes, breach_list)`` on 200.
          - ``None`` on 404 (no breaches found — not an error, tenacity won't retry).
          - Raises ``httpx.HTTPStatusError`` on 429 / 5xx (triggering retry).
        """
        chunks: list[bytes] = []
        total = 0
        async with client.stream(
            "GET",
            url,
            headers={
                "hibp-api-key": api_key,
                "User-Agent": "sleuthgraph/0.1",
            },
        ) as resp:
            # 404 means "account not found in any breach" — return None, not an error.
            if resp.status_code == 404:
                return None

            resp.raise_for_status()

            async for chunk in resp.aiter_bytes():
                total += len(chunk)
                if total > MAX_RESPONSE_BYTES:
                    raise httpx.HTTPError(
                        f"HIBP response exceeded {MAX_RESPONSE_BYTES} bytes; aborted"
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
