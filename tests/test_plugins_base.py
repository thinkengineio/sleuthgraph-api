"""OSINTPlugin base class + proposal type shape tests."""

import pytest
from pydantic import ValidationError

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


def test_osint_plugin_cannot_be_instantiated():
    with pytest.raises(TypeError):
        OSINTPlugin()


class _StubPlugin(OSINTPlugin):
    name = "stub"
    version = "0.0.1"
    entity_types_accepted = [EntityType.DOMAIN]
    entity_types_produced = [EntityType.DOMAIN]

    async def query(self, input_entity, credentials, context):
        return QueryResult()


def test_subclass_can_be_instantiated():
    p = _StubPlugin()
    assert p.name == "stub"
    assert p.version == "0.0.1"
    assert p.full_name == "stub@0.0.1"
    assert p.requires_credentials is False
    assert p.http_timeout_seconds == 30.0


def test_entity_proposal_requires_type_and_label():
    with pytest.raises(ValidationError):
        EntityProposal(ref="x")

    p = EntityProposal(ref="sub-0", type=EntityType.DOMAIN, label="a.example.com")
    assert p.confidence == 1.0
    assert p.attrs == {}


def test_entity_proposal_confidence_bounded():
    with pytest.raises(ValidationError):
        EntityProposal(ref="x", type=EntityType.DOMAIN, label="x.com", confidence=1.5)


def test_relationship_proposal_shape():
    r = RelationshipProposal(
        src={"input": True},
        dst={"ref": "sub-0"},
        # TODO: switch to SUBDOMAIN_OF when Task 5.4 lands
        rel_type=RelationshipType.ASSOCIATED_WITH,
    )
    assert r.rel_type == RelationshipType.ASSOCIATED_WITH
    assert r.confidence == 1.0


def test_evidence_proposal_payload_is_bytes():
    e = EvidenceProposal(query="crt.sh lookup for example.com", payload=b"{}")
    assert isinstance(e.payload, bytes)
    assert e.link_to_input is True


def test_evidence_proposal_rejects_empty_query():
    with pytest.raises(ValidationError):
        EvidenceProposal(query="", payload=b"")


def test_query_result_defaults_empty_lists():
    qr = QueryResult()
    assert qr.entities == []
    assert qr.relationships == []
    assert qr.evidence == []


def test_query_result_composes_proposals():
    qr = QueryResult(
        entities=[EntityProposal(ref="a", type=EntityType.DOMAIN, label="a.com")],
        relationships=[
            RelationshipProposal(
                src={"input": True}, dst={"ref": "a"},
                # TODO: switch to SUBDOMAIN_OF when Task 5.4 lands
                rel_type=RelationshipType.ASSOCIATED_WITH,
            )
        ],
        evidence=[EvidenceProposal(query="q", payload=b"{}")],
    )
    assert len(qr.entities) == 1
    assert len(qr.relationships) == 1
    assert len(qr.evidence) == 1


def test_plugin_context_accepts_arbitrary_input_entity():
    import httpx
    ctx = PluginContext(
        case_id="case-uuid",
        input_entity=object(),
        http_client=httpx.AsyncClient(),
    )
    assert ctx.case_id == "case-uuid"
