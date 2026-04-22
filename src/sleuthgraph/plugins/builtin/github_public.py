"""github_public plugin: PERSON|EMAIL → GitHub profile.

Input: PERSON (treated as username) or EMAIL.
Output: One PERSON EntityProposal with github_login/bio/company in attrs,
  one ASSOCIATED_WITH relationship back to the input entity, plus evidence.

API docs: https://docs.github.com/en/rest
  - PERSON: GET /users/{username}
  - EMAIL:  GET /search/users?q=<email>+in:email

Unauth'd: 60 requests/hour per IP. A 403 with X-RateLimit-Remaining: 0 is
surfaced as httpx.HTTPStatusError so the runner's error taxonomy picks it up.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urlencode

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

MAX_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MiB


class GithubPublicPlugin(OSINTPlugin):
    """GitHub public-profile lookup for PERSON or EMAIL."""

    name = "github_public"
    version = "0.1.0"
    entity_types_accepted = [EntityType.PERSON, EntityType.EMAIL]
    entity_types_produced = [EntityType.PERSON]
    requires_credentials = False
    http_timeout_seconds = 30.0
    dispatch_mode = "sync"

    USER_URL = "https://api.github.com/users/{username}"
    SEARCH_URL = "https://api.github.com/search/users"

    async def query(
        self,
        input_entity,
        credentials: dict | None,
        context: PluginContext,
    ) -> QueryResult:
        term = input_entity.label.strip()
        if not term:
            return QueryResult()

        is_email = input_entity.type == EntityType.EMAIL.value
        if is_email:
            url = f"{self.SEARCH_URL}?{urlencode({'q': f'{term} in:email'})}"
        else:
            url = self.USER_URL.format(username=quote(term, safe=""))

        raw_bytes = b""
        parsed: Any = None
        fetch_status = "ok"
        try:
            raw_bytes, parsed, status_code = await self._fetch(context.http_client, url)
            if status_code == 404:
                fetch_status = "not_found"
                parsed = None
        except httpx.HTTPStatusError:
            raise
        except httpx.HTTPError:
            fetch_status = "error"

        entities: list[EntityProposal] = []
        relationships: list[RelationshipProposal] = []
        match_count = 0

        if fetch_status == "ok" and parsed is not None:
            if is_email:
                items = parsed.get("items") if isinstance(parsed, dict) else None
                if isinstance(items, list):
                    for i, item in enumerate(items):
                        if not isinstance(item, dict):
                            continue
                        login = item.get("login")
                        if not isinstance(login, str) or not login:
                            continue
                        ref = f"gh-{i}"
                        entities.append(
                            EntityProposal(
                                ref=ref,
                                type=EntityType.PERSON,
                                label=login,
                                attrs={
                                    "discovered_via": "github_public",
                                    "github_login": login,
                                    "github_id": item.get("id"),
                                    "github_url": item.get("html_url"),
                                },
                                confidence=0.7,
                            )
                        )
                        relationships.append(
                            RelationshipProposal(
                                src={"ref": ref},
                                dst={"input": True},
                                rel_type=RelationshipType.ASSOCIATED_WITH,
                                attrs={"source": "github_public"},
                                confidence=0.7,
                            )
                        )
                        match_count += 1
            elif isinstance(parsed, dict):
                login = parsed.get("login")
                if isinstance(login, str) and login:
                    ref = "gh-0"
                    entities.append(
                        EntityProposal(
                            ref=ref,
                            type=EntityType.PERSON,
                            label=login,
                            attrs={
                                "discovered_via": "github_public",
                                "github_login": login,
                                "github_id": parsed.get("id"),
                                "bio": parsed.get("bio"),
                                "company": parsed.get("company"),
                                "location": parsed.get("location"),
                                "github_url": parsed.get("html_url"),
                                "created_at": parsed.get("created_at"),
                            },
                            confidence=0.9,
                        )
                    )
                    relationships.append(
                        RelationshipProposal(
                            src={"ref": ref},
                            dst={"input": True},
                            rel_type=RelationshipType.ASSOCIATED_WITH,
                            attrs={"source": "github_public"},
                            confidence=0.9,
                        )
                    )
                    match_count = 1

        evidence = [
            EvidenceProposal(
                query=f"GitHub public lookup for {term}",
                payload=raw_bytes or b"{}",
                content_type="application/json",
                reproducibility_spec={
                    "url": url,
                    "method": "GET",
                    "queried_at": datetime.now(timezone.utc).isoformat(),
                    "match_count": match_count,
                    "fetch_status": fetch_status,
                },
                link_to_input=True,
            )
        ]

        return QueryResult(
            entities=entities, relationships=relationships, evidence=evidence
        )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((httpx.TransportError, httpx.TimeoutException)),
        reraise=True,
    )
    async def _fetch(
        self, client: httpx.AsyncClient, url: str
    ) -> tuple[bytes, Any, int]:
        """Returns (raw_bytes, parsed_json_or_None, status_code).

        404 responses return cleanly (status=404, parsed=None) instead of raising,
        since "user not found" is a legitimate outcome of lookup. Other 4xx/5xx
        statuses raise HTTPStatusError via raise_for_status.
        """
        chunks: list[bytes] = []
        total = 0
        async with client.stream(
            "GET",
            url,
            headers={
                "User-Agent": "sleuthgraph/0.1",
                "Accept": "application/vnd.github+json",
            },
        ) as resp:
            status_code = resp.status_code
            if status_code == 404:
                # Drain body but don't raise
                async for chunk in resp.aiter_bytes():
                    total += len(chunk)
                    if total > MAX_RESPONSE_BYTES:
                        raise httpx.HTTPError(
                            f"github response exceeded {MAX_RESPONSE_BYTES} bytes"
                        )
                    chunks.append(chunk)
                return b"".join(chunks), None, 404
            resp.raise_for_status()
            async for chunk in resp.aiter_bytes():
                total += len(chunk)
                if total > MAX_RESPONSE_BYTES:
                    raise httpx.HTTPError(
                        f"github response exceeded {MAX_RESPONSE_BYTES} bytes"
                    )
                chunks.append(chunk)
        raw = b"".join(chunks)
        try:
            parsed: Any = json.loads(raw)
        except json.JSONDecodeError:
            parsed = None
        return raw, parsed, status_code
