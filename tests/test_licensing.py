"""Tests for the community-edition licensing gate."""

import pytest

from sleuthgraph.licensing import (
    FeatureUnavailable,
    _install_test_provider,
    _reset_provider_for_tests,
    assert_plugin_allowed,
    enterprise_enabled,
    feature_enabled,
    require_feature,
)


@pytest.fixture(autouse=True)
def _reset_provider():
    _reset_provider_for_tests()
    yield
    _reset_provider_for_tests()


def test_community_default_disables_everything():
    assert enterprise_enabled() is False
    assert feature_enabled("ai-pivot") is False
    assert feature_enabled("anything-else") is False


def test_require_feature_raises_on_community():
    with pytest.raises(FeatureUnavailable) as exc:
        require_feature("ai-pivot")
    assert "Cloud" in str(exc.value)


def test_enterprise_provider_unlocks_features():
    _install_test_provider(enterprise=True, features={"ai-pivot", "rbac"})
    assert enterprise_enabled() is True
    assert feature_enabled("ai-pivot") is True
    assert feature_enabled("rbac") is True
    assert feature_enabled("not-licensed") is False
    require_feature("ai-pivot")  # does not raise


def test_require_feature_raises_on_unlicensed_feature_even_with_enterprise():
    _install_test_provider(enterprise=True, features={"rbac"})
    with pytest.raises(FeatureUnavailable):
        require_feature("ai-pivot")


def test_premium_plugin_blocked_on_community():
    with pytest.raises(FeatureUnavailable) as exc:
        assert_plugin_allowed(plugin_name="virustotal", premium=True)
    assert "premium plugin" in str(exc.value)


def test_premium_plugin_runs_on_enterprise():
    _install_test_provider(enterprise=True)
    assert_plugin_allowed(plugin_name="virustotal", premium=True)  # no raise


def test_non_premium_plugin_runs_on_community():
    # Default community — free plugins must always work.
    assert_plugin_allowed(plugin_name="crtsh", premium=False)  # no raise
