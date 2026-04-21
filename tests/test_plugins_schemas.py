"""PluginInfo / PluginRunRead / PluginRunList shape tests."""

import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from sleuthgraph.entities.types import EntityType
from sleuthgraph.plugins.schemas import PluginInfo, PluginRunList, PluginRunRead


def test_plugin_info_shape():
    info = PluginInfo(
        name="crtsh", version="0.1.0",
        entity_types_accepted=[EntityType.DOMAIN],
        entity_types_produced=[EntityType.DOMAIN],
        requires_credentials=False,
    )
    assert info.name == "crtsh"


def test_plugin_info_rejects_bad_entity_type():
    with pytest.raises(ValidationError):
        PluginInfo(
            name="x", version="0.0.1",
            entity_types_accepted=["GHOST"],
            entity_types_produced=[],
            requires_credentials=False,
        )


def test_plugin_run_read_shape():
    now = datetime.now(timezone.utc)
    r = PluginRunRead(
        id=uuid.uuid4(), case_id=uuid.uuid4(), input_entity_id=None,
        plugin_name="x", plugin_version="0.1",
        started_at=now, finished_at=now, status="succeeded",
        error_message=None, entities_created_count=2,
        relationships_created_count=2, evidence_count=1,
        created_by=None,
    )
    assert r.status == "succeeded"


def test_plugin_run_list_shape():
    now = datetime.now(timezone.utc)
    row = PluginRunRead(
        id=uuid.uuid4(), case_id=uuid.uuid4(), input_entity_id=None,
        plugin_name="x", plugin_version="0.1",
        started_at=now, finished_at=None, status="running",
        error_message=None, entities_created_count=0,
        relationships_created_count=0, evidence_count=0,
        created_by=None,
    )
    lst = PluginRunList(items=[row], total=1, limit=50, offset=0)
    assert lst.total == 1
