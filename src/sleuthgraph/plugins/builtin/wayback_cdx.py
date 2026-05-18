"""wayback_cdx plugin: DOMAIN|URL → archived URL snapshots from archive.org.

Input: DOMAIN or URL entity.
Output: URL EntityProposals for each unique archived snapshot (+
  ASSOCIATED_WITH relationship to the input with attrs.role=archived).

API docs: http://web.archive.org/cdx/search/cdx — no auth.
Dispatched async (CDX can take tens of seconds on popular domains).
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
    RelationshipProposal,
)
from sleuthgraph.relationships.types import RelationshipType

MAX_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MiB
MAX_SNAPSHOTS = 500  # Per-run cap; matches CDX "limit" parameter
# EntityProposal.label is capped at 512 chars. Wayback occasionally returns
# very long archived URLs (nested URL-encoded query strings from old
# redirects). Skip those rather than truncating — a truncated URL isn't
# re-fetchable and loses its meaning as identifying data.
MAX_URL_LEN = 500  # leave margin below the 512 schema cap


class WaybackCdxPlugin(OSINTPlugin):
    """Archive.org Wayback CDX lookup for DOMAIN|URL."""

    name = "wayback_cdx"
    version = "0.1.0"
    entity_types_accepted = [EntityType.DOMAIN, EntityType.URL]
    entity_types_produced = [EntityType.URL]
    requires_credentials = False
    http_timeout_seconds = 60.0
    dispatch_mode = "async"

    BASE_URL = "http://web.archive.org/cdx/search/cdx"

    async def query(
        self,
        input_entity,
        credentials: dict | None,
        context: PluginContext,
    ) -> QueryResult:
        label = input_entity.label.strip()
        if not label:
            return QueryResult()

        is_domain = input_entity.type == EntityType.DOMAIN.value
        query_target = f"{label}/*" if is_domain else label

        params = {
            "url": query_target,
            "output": "json",
            "limit": str(MAX_SNAPSHOTS + 1),  # +1 so we can detect truncation
            "fl": "timestamp,original,statuscode",
            "collapse": "urlkey",
        }
        url = f"{self.BASE_URL}?{urlencode(params)}"

        raw_bytes = b""
        rows: list[list[str]] = []
        fetch_status = "ok"
        try:
            raw_bytes, rows = await self._fetch(context.http_client, url)
        except httpx.HTTPError:
            fetch_status = "error"
            raw_bytes = b""
            rows = []

        snapshots = self._extract_snapshots(rows)
        truncated = len(snapshots) > MAX_SNAPSHOTS
        if truncated:
            snapshots = snapshots[:MAX_SNAPSHOTS]

        entities: list[EntityProposal] = []
        relationships: list[RelationshipProposal] = []
        skipped_too_long = 0
        for i, (original, first_seen, last_seen, status_code) in enumerate(snapshots):
            if len(original) > MAX_URL_LEN:
                skipped_too_long += 1
                continue
            ref = f"snap-{i}"
            entities.append(
                EntityProposal(
                    ref=ref,
                    type=EntityType.URL,
                    label=original,
                    attrs={
                        "discovered_via": "wayback_cdx",
                        "first_seen": first_seen,
                        "last_seen": last_seen,
                        "status_code": status_code,
                    },
                    confidence=0.8,
                )
            )
            relationships.append(
                RelationshipProposal(
                    src={"ref": ref},
                    dst={"input": True},
                    rel_type=RelationshipType.ASSOCIATED_WITH,
                    attrs={"role": "archived"},
                    confidence=0.8,
                )
            )

        evidence = [
            EvidenceProposal(
                query=f"wayback CDX lookup for {label}",
                payload=raw_bytes or b"[]",
                content_type="application/json",
                reproducibility_spec={
                    "url": url,
                    "method": "GET",
                    "queried_at": datetime.now(timezone.utc).isoformat(),
                    "snapshot_count": len(entities),
                    "truncated": truncated,
                    "skipped_too_long": skipped_too_long,
                    "max_snapshots": MAX_SNAPSHOTS,
                    "max_url_length": MAX_URL_LEN,
                    "fetch_status": fetch_status,
                },
                link_to_input=True,
            )
        ]

        return QueryResult(
            entities=entities, relationships=relationships, evidence=evidence
        )

    @retry(
        stop=(stop_after_attempt(3) | stop_after_delay(30)),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((httpx.TransportError, httpx.TimeoutException)),
        reraise=True,
    )
    async def _fetch(
        self, client: httpx.AsyncClient, url: str
    ) -> tuple[bytes, list[list[str]]]:
        """Streaming GET with 10 MiB cap. Returns (raw, parsed_rows_excluding_header)."""
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
                        f"wayback cdx response exceeded {MAX_RESPONSE_BYTES} bytes; aborted"
                    )
                chunks.append(chunk)
        raw = b"".join(chunks)
        try:
            parsed: Any = json.loads(raw)
        except json.JSONDecodeError:
            return raw, []
        if not isinstance(parsed, list) or len(parsed) < 1:
            return raw, []
        # First row is the header ["timestamp","original","statuscode"]
        return raw, [row for row in parsed[1:] if isinstance(row, list)]

    @staticmethod
    def _extract_snapshots(rows: list[list[str]]) -> list[tuple[str, str, str, str]]:
        """Collapse rows by original URL; track first/last timestamps.

        Returns list of (original, first_seen, last_seen, status_code) tuples,
        ordered by first_seen ascending.
        """
        by_url: dict[str, dict[str, str]] = {}
        for row in rows:
            if len(row) < 3:
                continue
            timestamp, original, statuscode = row[0], row[1], row[2]
            if not isinstance(original, str) or not original:
                continue
            entry = by_url.get(original)
            if entry is None:
                by_url[original] = {
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "status_code": statuscode,
                }
            else:
                if timestamp < entry["first_seen"]:
                    entry["first_seen"] = timestamp
                if timestamp > entry["last_seen"]:
                    entry["last_seen"] = timestamp

        out = [
            (url, e["first_seen"], e["last_seen"], e["status_code"])
            for url, e in by_url.items()
        ]
        out.sort(key=lambda t: t[1])
        return out
