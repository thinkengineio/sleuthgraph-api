"""github_public plugin: PERSON|EMAIL → GitHub profile."""

import json
import uuid

import httpx
import pytest

from sleuthgraph.entities.models import Entity
from sleuthgraph.entities.types import EntityType
from sleuthgraph.plugins.base import PluginContext
from sleuthgraph.plugins.builtin.github_public import GithubPublicPlugin
from sleuthgraph.relationships.types import RelationshipType


def _entity(type_, label):
    return Entity(
        id=uuid.uuid4(),
        case_id=uuid.uuid4(),
        type=type_.value,
        label=label,
        attrs={},
        confidence=1.0,
    )


def _transport(handler):
    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_person_username_lookup():
    def handler(request):
        assert "/users/" in str(request.url)
        return httpx.Response(
            200,
            content=json.dumps(
                {
                    "login": "octocat",
                    "id": 1,
                    "bio": "a person",
                    "company": "GitHub",
                    "location": "SF",
                    "html_url": "https://github.com/octocat",
                    "created_at": "2011-01-25T18:44:36Z",
                }
            ).encode(),
        )

    plugin = GithubPublicPlugin()
    async with httpx.AsyncClient(transport=_transport(handler)) as client:
        ent = _entity(EntityType.PERSON, "octocat")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, None, ctx)

    assert len(result.entities) == 1
    e = result.entities[0]
    assert e.type == EntityType.PERSON
    assert e.label == "octocat"
    assert e.attrs["github_login"] == "octocat"
    assert e.attrs["bio"] == "a person"
    assert e.attrs["company"] == "GitHub"
    assert e.attrs["discovered_via"] == "github_public"

    # One ASSOCIATED_WITH relationship back to input
    assert len(result.relationships) == 1
    assert result.relationships[0].rel_type == RelationshipType.ASSOCIATED_WITH
    assert result.relationships[0].dst == {"input": True}


@pytest.mark.asyncio
async def test_email_search_endpoint():
    captured = {}

    def handler(request):
        captured["url"] = str(request.url)
        # search API returns items list
        return httpx.Response(
            200,
            content=json.dumps(
                {
                    "total_count": 1,
                    "items": [
                        {
                            "login": "someone",
                            "id": 42,
                            "html_url": "https://github.com/someone",
                        }
                    ],
                }
            ).encode(),
        )

    plugin = GithubPublicPlugin()
    async with httpx.AsyncClient(transport=_transport(handler)) as client:
        ent = _entity(EntityType.EMAIL, "foo@example.com")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, None, ctx)

    assert "search/users" in captured["url"]
    assert "in%3Aemail" in captured["url"] or "in:email" in captured["url"]
    assert len(result.entities) == 1
    assert result.entities[0].attrs["github_login"] == "someone"


@pytest.mark.asyncio
async def test_404_user_returns_evidence_only():
    def handler(request):
        return httpx.Response(404, content=b'{"message":"Not Found"}')

    plugin = GithubPublicPlugin()
    async with httpx.AsyncClient(transport=_transport(handler)) as client:
        ent = _entity(EntityType.PERSON, "no-such-user")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, None, ctx)

    assert result.entities == []
    assert result.relationships == []
    assert len(result.evidence) == 1
    assert result.evidence[0].reproducibility_spec["fetch_status"] == "not_found"


@pytest.mark.asyncio
async def test_rate_limit_403_raises():
    def handler(request):
        return httpx.Response(
            403,
            content=b'{"message":"rate limited"}',
            headers={"X-RateLimit-Remaining": "0"},
        )

    plugin = GithubPublicPlugin()
    async with httpx.AsyncClient(transport=_transport(handler)) as client:
        ent = _entity(EntityType.PERSON, "octocat")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        with pytest.raises(httpx.HTTPStatusError):
            await plugin.query(ent, None, ctx)


@pytest.mark.asyncio
async def test_empty_label_returns_empty_result():
    plugin = GithubPublicPlugin()

    def handler(request):
        return httpx.Response(200, content=b"{}")

    async with httpx.AsyncClient(transport=_transport(handler)) as client:
        ent = _entity(EntityType.PERSON, "   ")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, None, ctx)
    assert result.entities == []
    assert result.evidence == []
