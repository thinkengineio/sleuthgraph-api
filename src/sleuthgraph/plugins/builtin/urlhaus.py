"""urlhaus plugin: URL|DOMAIN → malware hit evidence.

Input: URL or DOMAIN.
Output: Evidence-only. urlhaus-api.abuse.ch returns ``query_status`` + a list
  of known-bad URLs hosted on the target, or ``no_results``. We capture the
  raw response and mirror the malicious flag into reproducibility_spec.

API docs: https://urlhaus-api.abuse.ch/
  POST form-body, no key needed for free tier.
"""

from __future__ import annotations

import json
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
    EvidenceProposal,
    OSINTPlugin,
    PluginContext,
    QueryResult,
)

MAX_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MiB


class UrlhausPlugin(OSINTPlugin):
    """abuse.ch URLhaus lookup for URL or DOMAIN."""

    name = "urlhaus"
    version = "0.1.0"
    entity_types_accepted = [EntityType.URL, EntityType.DOMAIN]
    entity_types_produced = []
    requires_credentials = False
    http_timeout_seconds = 30.0
    dispatch_mode = "sync"

    URL_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
    HOST_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"

    async def query(
        self,
        input_entity,
        credentials: dict | None,
        context: PluginContext,
    ) -> QueryResult:
        label = input_entity.label.strip()
        if not label:
            return QueryResult()

        is_url = input_entity.type == EntityType.URL.value
        if is_url:
            endpoint = self.URL_ENDPOINT
            form = {"url": label}
        else:
            endpoint = self.HOST_ENDPOINT
            form = {"host": label}

        raw_bytes = b""
        parsed: Any = None
        fetch_status = "ok"
        try:
            raw_bytes, parsed = await self._fetch(context.http_client, endpoint, form)
        except httpx.HTTPError:
            fetch_status = "error"

        query_status = ""
        malicious = False
        if isinstance(parsed, dict):
            query_status = str(parsed.get("query_status", ""))
            if query_status == "ok":
                # Either url_info exists (URL endpoint) or urls list non-empty (host endpoint)
                url_info = parsed.get("url_info")
                urls = parsed.get("urls")
                if isinstance(url_info, dict) or (
                    isinstance(urls, list) and len(urls) > 0
                ):
                    malicious = True

        evidence = [
            EvidenceProposal(
                query=f"URLhaus lookup for {label}",
                payload=raw_bytes or b"{}",
                content_type="application/json",
                reproducibility_spec={
                    "url": endpoint,
                    "method": "POST",
                    "queried_at": datetime.now(timezone.utc).isoformat(),
                    "query_status": query_status,
                    "malicious": malicious,
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
        self,
        client: httpx.AsyncClient,
        url: str,
        form: dict[str, str],
    ) -> tuple[bytes, Any]:
        resp = await client.post(
            url,
            data=form,
            headers={"User-Agent": "sleuthgraph/0.1"},
        )
        resp.raise_for_status()
        raw = resp.content
        if len(raw) > MAX_RESPONSE_BYTES:
            raise httpx.HTTPError(
                f"urlhaus response exceeded {MAX_RESPONSE_BYTES} bytes"
            )
        try:
            parsed: Any = json.loads(raw)
        except json.JSONDecodeError:
            parsed = None
        return raw, parsed
