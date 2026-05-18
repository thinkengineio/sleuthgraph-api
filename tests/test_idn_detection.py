"""Tests for IDN / Punycode detection in entity schemas and validators."""

import uuid
from datetime import datetime, timezone

import pytest

from sleuthgraph.entities.schemas import EntityRead
from sleuthgraph.entities.types import EntityType
from sleuthgraph.entities.validators import is_idn_domain


# ---------------------------------------------------------------------------
# is_idn_domain helper
# ---------------------------------------------------------------------------

class TestIsIdnDomain:
    def test_plain_ascii_domain(self):
        assert is_idn_domain("example.com") is False

    def test_punycode_encoded_label(self):
        # xn--e1afmapc.xn--p1ai  ==  example.rf  (Cyrillic)
        assert is_idn_domain("xn--e1afmapc.xn--p1ai") is True

    def test_punycode_subdomain(self):
        assert is_idn_domain("sub.xn--nxasmq6b.com") is True

    def test_unicode_domain(self):
        # Direct Unicode: should flag as IDN
        assert is_idn_domain("üñîçöðé.com") is True

    def test_mixed_ascii_unicode(self):
        assert is_idn_domain("example.рф") is True

    def test_case_insensitive_xn_prefix(self):
        # Punycode prefix is case-insensitive per spec; our lowering handles it
        assert is_idn_domain("XN--E1AFMAPC.XN--P1AI") is True

    def test_xn_in_middle_of_label_not_prefix(self):
        # "foxn--bar" does not start with "xn--"
        assert is_idn_domain("foxn--bar.com") is False

    def test_empty_string(self):
        assert is_idn_domain("") is False

    def test_single_label_punycode(self):
        assert is_idn_domain("xn--nxasmq6b") is True

    def test_ip_address_not_idn(self):
        assert is_idn_domain("192.168.1.1") is False


# ---------------------------------------------------------------------------
# EntityRead.is_idn computed field
# ---------------------------------------------------------------------------

class TestEntityReadIsIdn:
    def _make_entity_read(self, etype: EntityType, label: str) -> EntityRead:
        now = datetime.now(timezone.utc)
        return EntityRead(
            id=uuid.uuid4(),
            case_id=uuid.uuid4(),
            type=etype,
            label=label,
            attrs={},
            confidence=1.0,
            created_by=None,
            created_at=now,
            updated_at=now,
        )

    def test_domain_plain_ascii(self):
        er = self._make_entity_read(EntityType.DOMAIN, "example.com")
        assert er.is_idn is False

    def test_domain_punycode(self):
        er = self._make_entity_read(EntityType.DOMAIN, "xn--e1afmapc.xn--p1ai")
        assert er.is_idn is True

    def test_domain_unicode(self):
        er = self._make_entity_read(EntityType.DOMAIN, "üñîçöðé.com")
        assert er.is_idn is True

    def test_non_domain_type_always_false(self):
        """is_idn is only meaningful for DOMAIN entities."""
        er = self._make_entity_read(EntityType.PERSON, "xn--e1afmapc.xn--p1ai")
        assert er.is_idn is False

    def test_email_type_always_false(self):
        er = self._make_entity_read(EntityType.EMAIL, "user@xn--e1afmapc.xn--p1ai")
        assert er.is_idn is False

    def test_is_idn_serialized_in_json(self):
        """Computed field must appear in model_dump() / JSON output."""
        er = self._make_entity_read(EntityType.DOMAIN, "xn--nxasmq6b.com")
        data = er.model_dump()
        assert "is_idn" in data
        assert data["is_idn"] is True

    def test_is_idn_false_serialized(self):
        er = self._make_entity_read(EntityType.DOMAIN, "example.com")
        data = er.model_dump()
        assert data["is_idn"] is False
