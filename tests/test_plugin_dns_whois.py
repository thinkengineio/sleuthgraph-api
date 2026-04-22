"""dns_whois plugin: A/AAAA/NS/MX resolution + RDAP evidence."""

import uuid
from types import SimpleNamespace

import httpx
import pytest

import dns.exception
import dns.resolver

from sleuthgraph.entities.models import Entity
from sleuthgraph.entities.types import EntityType
from sleuthgraph.plugins.base import PluginContext
from sleuthgraph.plugins.builtin.dns_whois import DnsWhoisPlugin
from sleuthgraph.relationships.types import RelationshipType


def _make_input_domain(label="example.com"):
    return Entity(
        id=uuid.uuid4(),
        case_id=uuid.uuid4(),
        type=EntityType.DOMAIN.value,
        label=label,
        attrs={},
        confidence=1.0,
    )


class _FakeAnswer:
    def __init__(self, text):
        self._text = text

    def to_text(self):
        return self._text


class _FakeMxAnswer:
    def __init__(self, preference, exchange):
        self.preference = preference
        self.exchange = SimpleNamespace(to_text=lambda: exchange)


def _install_fake_resolver(monkeypatch, responses):
    """responses: {rdtype: list_of_answers_or_exception}"""

    async def _resolve(name, rdtype, lifetime=5.0):
        val = responses.get(rdtype)
        if val is None:
            raise dns.resolver.NoAnswer()
        if isinstance(val, Exception):
            raise val
        return val

    import dns.asyncresolver

    monkeypatch.setattr(dns.asyncresolver, "resolve", _resolve)


def _rdap_transport(status=200, body=b'{"objectClassName":"domain"}'):
    def handler(request):
        return httpx.Response(status, content=body)

    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_resolves_a_records_to_ip_entities(monkeypatch):
    _install_fake_resolver(
        monkeypatch,
        {
            "A": [_FakeAnswer("93.184.216.34")],
            "AAAA": dns.resolver.NoAnswer(),
            "NS": dns.resolver.NoAnswer(),
            "MX": dns.resolver.NoAnswer(),
        },
    )
    plugin = DnsWhoisPlugin()
    async with httpx.AsyncClient(transport=_rdap_transport()) as client:
        ctx = PluginContext(case_id="x", input_entity=_make_input_domain(), http_client=client)
        result = await plugin.query(_make_input_domain(), None, ctx)

    ips = [e for e in result.entities if e.type == EntityType.IP_ADDRESS]
    assert len(ips) == 1
    assert ips[0].label == "93.184.216.34"
    assert ips[0].attrs["discovered_via"] == "dns_whois"
    assert ips[0].attrs["rdtype"] == "A"
    assert ips[0].confidence == 0.95

    rels = [r for r in result.relationships if r.rel_type == RelationshipType.RESOLVES_TO]
    assert len(rels) == 1
    assert rels[0].dst == {"input": True}


@pytest.mark.asyncio
async def test_nxdomain_returns_empty_success(monkeypatch):
    _install_fake_resolver(
        monkeypatch,
        {
            "A": dns.resolver.NXDOMAIN(),
            "AAAA": dns.resolver.NXDOMAIN(),
            "NS": dns.resolver.NXDOMAIN(),
            "MX": dns.resolver.NXDOMAIN(),
        },
    )
    plugin = DnsWhoisPlugin()
    async with httpx.AsyncClient(transport=_rdap_transport(status=404, body=b"{}")) as client:
        ctx = PluginContext(case_id="x", input_entity=_make_input_domain(), http_client=client)
        result = await plugin.query(_make_input_domain(), None, ctx)

    assert result.entities == []
    assert result.relationships == []
    # Evidence row is still emitted (records the query + null RDAP)
    assert len(result.evidence) == 1
    assert result.evidence[0].reproducibility_spec["rdap_status"] == "unavailable"


@pytest.mark.asyncio
async def test_ns_and_mx_emit_domain_entities(monkeypatch):
    _install_fake_resolver(
        monkeypatch,
        {
            "A": dns.resolver.NoAnswer(),
            "AAAA": dns.resolver.NoAnswer(),
            "NS": [_FakeAnswer("ns1.example.com."), _FakeAnswer("ns2.example.com.")],
            "MX": [
                _FakeMxAnswer(10, "mail.example.com."),
                _FakeMxAnswer(20, "mail2.example.com."),
            ],
        },
    )
    plugin = DnsWhoisPlugin()
    async with httpx.AsyncClient(transport=_rdap_transport()) as client:
        ctx = PluginContext(case_id="x", input_entity=_make_input_domain(), http_client=client)
        result = await plugin.query(_make_input_domain(), None, ctx)

    ns_entities = [
        e for e in result.entities if e.type == EntityType.DOMAIN and e.attrs.get("role") == "nameserver"
    ]
    mx_entities = [
        e for e in result.entities if e.type == EntityType.DOMAIN and e.attrs.get("role") == "mx"
    ]
    assert {e.label for e in ns_entities} == {"ns1.example.com", "ns2.example.com"}
    assert {e.label for e in mx_entities} == {"mail.example.com", "mail2.example.com"}
    # MX preference preserved
    assert {e.attrs["preference"] for e in mx_entities} == {10, 20}

    # All 4 produce ASSOCIATED_WITH rels
    assoc_rels = [
        r for r in result.relationships if r.rel_type == RelationshipType.ASSOCIATED_WITH
    ]
    assert len(assoc_rels) == 4


@pytest.mark.asyncio
async def test_rdap_404_does_not_fail(monkeypatch):
    _install_fake_resolver(
        monkeypatch,
        {
            "A": [_FakeAnswer("1.2.3.4")],
            "AAAA": dns.resolver.NoAnswer(),
            "NS": dns.resolver.NoAnswer(),
            "MX": dns.resolver.NoAnswer(),
        },
    )
    plugin = DnsWhoisPlugin()
    async with httpx.AsyncClient(transport=_rdap_transport(status=404, body=b"not found")) as client:
        ctx = PluginContext(case_id="x", input_entity=_make_input_domain(), http_client=client)
        result = await plugin.query(_make_input_domain(), None, ctx)

    # DNS data still came through
    assert any(e.type == EntityType.IP_ADDRESS for e in result.entities)
    assert result.evidence[0].reproducibility_spec["rdap_status"] == "unavailable"


@pytest.mark.asyncio
async def test_empty_domain_returns_empty_result(monkeypatch):
    plugin = DnsWhoisPlugin()
    async with httpx.AsyncClient(transport=_rdap_transport()) as client:
        ctx = PluginContext(
            case_id="x",
            input_entity=_make_input_domain(label="  "),
            http_client=client,
        )
        result = await plugin.query(_make_input_domain(label="   "), None, ctx)
    assert result.entities == []
    assert result.relationships == []
    assert result.evidence == []


@pytest.mark.asyncio
async def test_dns_timeout_tolerated(monkeypatch):
    _install_fake_resolver(
        monkeypatch,
        {
            "A": dns.exception.Timeout(),
            "AAAA": dns.exception.Timeout(),
            "NS": dns.exception.Timeout(),
            "MX": dns.exception.Timeout(),
        },
    )
    plugin = DnsWhoisPlugin()
    async with httpx.AsyncClient(transport=_rdap_transport()) as client:
        ctx = PluginContext(case_id="x", input_entity=_make_input_domain(), http_client=client)
        result = await plugin.query(_make_input_domain(), None, ctx)

    assert result.entities == []


@pytest.mark.asyncio
async def test_evidence_reproducibility_spec_has_required_fields(monkeypatch):
    _install_fake_resolver(
        monkeypatch,
        {
            "A": [_FakeAnswer("1.2.3.4")],
            "AAAA": dns.resolver.NoAnswer(),
            "NS": [_FakeAnswer("ns1.example.com.")],
            "MX": dns.resolver.NoAnswer(),
        },
    )
    plugin = DnsWhoisPlugin()
    async with httpx.AsyncClient(transport=_rdap_transport()) as client:
        ctx = PluginContext(case_id="x", input_entity=_make_input_domain(), http_client=client)
        result = await plugin.query(_make_input_domain(), None, ctx)

    spec = result.evidence[0].reproducibility_spec
    assert spec["method"] == "GET"
    assert "rdap.org" in spec["url"]
    assert "queried_at" in spec
    assert spec["dns_record_counts"]["a"] == 1
    assert spec["dns_record_counts"]["ns"] == 1
