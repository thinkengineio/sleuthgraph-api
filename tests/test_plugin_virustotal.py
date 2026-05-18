"""VirusTotalPlugin -- BYOK enrichment for DOMAIN / IP_ADDRESS / URL."""

import json
import uuid
from pathlib import Path

import httpx
import pytest

from sleuthgraph.entities.models import Entity
from sleuthgraph.entities.types import EntityType
from sleuthgraph.plugins.base import PluginContext
from sleuthgraph.plugins.builtin.virustotal import MAX_ENTITIES, VirusTotalPlugin
from sleuthgraph.relationships.types import RelationshipType


FIXTURE_DIR = Path(__file__).parent / "fixtures"
CREDS = {"api_key": "test-vt-key-abc123"}


def _entity(type_: EntityType, label: str) -> Entity:
    return Entity(
        id=uuid.uuid4(),
        case_id=uuid.uuid4(),
        type=type_.value,
        label=label,
        attrs={},
        confidence=1.0,
    )


def _transport(status: int = 200, body: bytes | None = None, fixture: str | None = None):
    if body is None and fixture is not None:
        body = (FIXTURE_DIR / fixture).read_bytes()
    if body is None:
        body = b"{}"

    def handler(request: httpx.Request) -> httpx.Response:
        # Verify auth header is present
        assert request.headers.get("x-apikey") == CREDS["api_key"]
        return httpx.Response(status, content=body)

    return httpx.MockTransport(handler)


# -- Domain tests --

@pytest.mark.asyncio
async def test_domain_extracts_ips_from_dns_records():
    plugin = VirusTotalPlugin()
    transport = _transport(fixture="virustotal_domain.json")
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity(EntityType.DOMAIN, "example.com")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, CREDS, ctx)

    ip_entities = [e for e in result.entities if e.type == EntityType.IP_ADDRESS]
    assert len(ip_entities) == 2
    labels = {e.label for e in ip_entities}
    assert "93.184.216.34" in labels
    assert "2606:2800:220:1:248:1893:25c8:1946" in labels
    for e in ip_entities:
        assert e.attrs["discovered_via"] == "virustotal"


@pytest.mark.asyncio
async def test_domain_extracts_subdomains_via_cname():
    plugin = VirusTotalPlugin()
    transport = _transport(fixture="virustotal_domain.json")
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity(EntityType.DOMAIN, "example.com")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, CREDS, ctx)

    subdomain_entities = [e for e in result.entities if e.type == EntityType.DOMAIN]
    labels = {e.label for e in subdomain_entities}
    assert "www.example.com" in labels

    subdomain_rels = [
        r for r in result.relationships if r.rel_type == RelationshipType.SUBDOMAIN_OF
    ]
    assert len(subdomain_rels) >= 1
    for r in subdomain_rels:
        assert r.dst == {"input": True}


@pytest.mark.asyncio
async def test_domain_resolves_to_relationships():
    plugin = VirusTotalPlugin()
    transport = _transport(fixture="virustotal_domain.json")
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity(EntityType.DOMAIN, "example.com")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, CREDS, ctx)

    resolves_rels = [
        r for r in result.relationships if r.rel_type == RelationshipType.RESOLVES_TO
    ]
    assert len(resolves_rels) == 2  # one per IP (A + AAAA)
    for r in resolves_rels:
        assert r.src == {"input": True}


@pytest.mark.asyncio
async def test_domain_evidence_carries_raw_response():
    plugin = VirusTotalPlugin()
    raw = (FIXTURE_DIR / "virustotal_domain.json").read_bytes()
    transport = _transport(body=raw)
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity(EntityType.DOMAIN, "example.com")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, CREDS, ctx)

    assert len(result.evidence) == 1
    ev = result.evidence[0]
    assert ev.payload == raw
    assert ev.content_type == "application/json"
    assert "VirusTotal domain lookup for example.com" in ev.query
    assert ev.reproducibility_spec["method"] == "GET"


# -- IP tests --

@pytest.mark.asyncio
async def test_ip_extracts_domains_from_certificate():
    plugin = VirusTotalPlugin()
    transport = _transport(fixture="virustotal_ip.json")
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity(EntityType.IP_ADDRESS, "93.184.216.34")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, CREDS, ctx)

    domain_entities = [e for e in result.entities if e.type == EntityType.DOMAIN]
    labels = {e.label for e in domain_entities}
    assert "example.com" in labels
    assert "www.example.com" in labels
    assert "api.example.com" in labels

    rels = [r for r in result.relationships if r.rel_type == RelationshipType.RESOLVES_TO]
    assert len(rels) == 3
    for r in rels:
        assert r.dst == {"input": True}


@pytest.mark.asyncio
async def test_ip_evidence_has_correct_query():
    plugin = VirusTotalPlugin()
    transport = _transport(fixture="virustotal_ip.json")
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity(EntityType.IP_ADDRESS, "93.184.216.34")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, CREDS, ctx)

    assert len(result.evidence) == 1
    assert "93.184.216.34" in result.evidence[0].query


# -- URL tests --

@pytest.mark.asyncio
async def test_url_returns_evidence_only():
    """URL analysis produces evidence but no new entities."""
    plugin = VirusTotalPlugin()
    transport = _transport(fixture="virustotal_url.json")
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity(EntityType.URL, "https://example.com/malware")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, CREDS, ctx)

    assert result.entities == []
    assert result.relationships == []
    assert len(result.evidence) == 1
    ev = result.evidence[0]
    assert "VirusTotal URL analysis" in ev.query
    assert ev.reproducibility_spec["entity_count"] == 0


# -- Error handling --

@pytest.mark.asyncio
async def test_http_error_not_retried():
    """500 is not retried (retry predicate limited to transport/timeout errors)."""
    plugin = VirusTotalPlugin()
    call_count = {"n": 0}

    def handler(request):
        call_count["n"] += 1
        return httpx.Response(500, content=b"server error")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity(EntityType.DOMAIN, "example.com")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        with pytest.raises(httpx.HTTPStatusError):
            await plugin.query(ent, CREDS, ctx)

    assert call_count["n"] == 1


@pytest.mark.asyncio
async def test_http_403_not_retried():
    """403 (bad API key) is not retried (retry predicate limited to transport/timeout)."""
    plugin = VirusTotalPlugin()
    call_count = {"n": 0}

    def handler(request):
        call_count["n"] += 1
        return httpx.Response(403, content=b'{"error": "Forbidden"}')

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity(EntityType.DOMAIN, "example.com")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        with pytest.raises(httpx.HTTPStatusError):
            await plugin.query(ent, CREDS, ctx)

    assert call_count["n"] == 1


# -- Empty results --

@pytest.mark.asyncio
async def test_empty_response_produces_no_entities():
    plugin = VirusTotalPlugin()
    empty_data = {"data": {"attributes": {}}}
    transport = _transport(body=json.dumps(empty_data).encode())
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity(EntityType.DOMAIN, "empty.example.com")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, CREDS, ctx)

    assert result.entities == []
    assert result.relationships == []
    assert len(result.evidence) == 1


@pytest.mark.asyncio
async def test_empty_label_returns_empty_result():
    plugin = VirusTotalPlugin()
    transport = _transport()
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity(EntityType.DOMAIN, "   ")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, CREDS, ctx)

    assert result.entities == []
    assert result.evidence == []


# -- Credential access --

@pytest.mark.asyncio
async def test_credentials_api_key_used_in_header():
    """Verify the plugin reads api_key from credentials dict and passes it as x-apikey."""
    plugin = VirusTotalPlugin()
    header_seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        header_seen["x-apikey"] = request.headers.get("x-apikey")
        return httpx.Response(200, content=b'{"data":{"attributes":{}}}')

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity(EntityType.DOMAIN, "example.com")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        await plugin.query(ent, {"api_key": "my-secret-key"}, ctx)

    assert header_seen["x-apikey"] == "my-secret-key"


# -- Cap at MAX_ENTITIES --

@pytest.mark.asyncio
async def test_cap_at_max_entities():
    """Entities are capped at MAX_ENTITIES and evidence marks truncated."""
    plugin = VirusTotalPlugin()
    # Build a response with more IPs than the cap
    dns_records = [
        {"type": "A", "value": f"10.0.{i // 256}.{i % 256}"}
        for i in range(MAX_ENTITIES + 10)
    ]
    data = {"data": {"attributes": {"last_dns_records": dns_records}}}
    transport = _transport(body=json.dumps(data).encode())
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity(EntityType.DOMAIN, "example.com")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, CREDS, ctx)

    assert len(result.entities) == MAX_ENTITIES
    assert result.evidence[0].reproducibility_spec["truncated"] is True


# -- Plugin class attributes --

# -- Input validation (path injection prevention) --

@pytest.mark.asyncio
async def test_rejects_injected_path_in_domain():
    """Domain labels with '/' must be rejected before URL construction (CWE-74)."""
    plugin = VirusTotalPlugin()
    transport = _transport()
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity(EntityType.DOMAIN, "example.com/../admin")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, CREDS, ctx)

    assert result.entities == []
    assert result.relationships == []
    assert result.evidence == []


@pytest.mark.asyncio
async def test_rejects_query_param_in_domain():
    """Domain with embedded '?' must be rejected (prevents query-string injection)."""
    plugin = VirusTotalPlugin()
    transport = _transport()
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity(EntityType.DOMAIN, "example.com?evil=1")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, CREDS, ctx)

    assert result.entities == []
    assert result.evidence == []


@pytest.mark.asyncio
async def test_rejects_injected_path_in_ip():
    """IP labels with injection chars must be rejected before URL construction."""
    plugin = VirusTotalPlugin()
    transport = _transport()
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity(EntityType.IP_ADDRESS, "1.2.3.4?evil=1")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, CREDS, ctx)

    assert result.entities == []
    assert result.evidence == []


@pytest.mark.asyncio
async def test_rejects_path_traversal_in_ip():
    """IP labels with '/' must be rejected."""
    plugin = VirusTotalPlugin()
    transport = _transport()
    async with httpx.AsyncClient(transport=transport) as client:
        ent = _entity(EntityType.IP_ADDRESS, "1.2.3.4/../../admin")
        ctx = PluginContext(case_id="x", input_entity=ent, http_client=client)
        result = await plugin.query(ent, CREDS, ctx)

    assert result.entities == []
    assert result.evidence == []


def test_plugin_class_attributes():
    plugin = VirusTotalPlugin()
    assert plugin.name == "virustotal"
    assert plugin.version == "0.1.0"
    assert plugin.requires_credentials is True
    assert plugin.credential_name == "virustotal"
    assert EntityType.DOMAIN in plugin.entity_types_accepted
    assert EntityType.IP_ADDRESS in plugin.entity_types_accepted
    assert EntityType.URL in plugin.entity_types_accepted
