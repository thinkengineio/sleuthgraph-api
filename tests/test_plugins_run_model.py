"""PluginRun model shape tests."""

from sleuthgraph.plugins.models import PluginRun


def test_plugin_run_tablename():
    assert PluginRun.__tablename__ == "plugin_runs"


def test_plugin_run_columns():
    cols = {c.name for c in PluginRun.__table__.columns}
    required = {
        "id",
        "case_id",
        "input_entity_id",
        "plugin_name",
        "plugin_version",
        "started_at",
        "finished_at",
        "status",
        "error_message",
        "entities_created_count",
        "relationships_created_count",
        "evidence_count",
        "created_by",
    }
    assert required <= cols, f"missing: {required - cols}"


def test_case_id_fk_cascade():
    col = PluginRun.__table__.c.case_id
    fks = list(col.foreign_keys)
    assert len(fks) == 1
    assert fks[0]._colspec == "cases.id"
    assert fks[0].ondelete == "CASCADE"
    assert col.nullable is False


def test_input_entity_id_fk_set_null_nullable():
    col = PluginRun.__table__.c.input_entity_id
    fks = list(col.foreign_keys)
    assert fks[0]._colspec == "entities.id"
    assert fks[0].ondelete == "SET NULL"
    assert col.nullable is True


def test_created_by_fk_set_null():
    col = PluginRun.__table__.c.created_by
    fks = list(col.foreign_keys)
    assert fks[0]._colspec == "users.id"
    assert fks[0].ondelete == "SET NULL"


def test_status_has_default():
    col = PluginRun.__table__.c.status
    assert col.default is not None or col.server_default is not None


def test_counts_default_zero():
    for name in ("entities_created_count", "relationships_created_count", "evidence_count"):
        col = PluginRun.__table__.c[name]
        assert col.default is not None or col.server_default is not None, f"{name} has no default"
