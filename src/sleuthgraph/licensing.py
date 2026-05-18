"""Licensing + edition gate.

Community Edition = this repository, Apache 2.0, features available to
anyone who self-hosts.

Cloud Edition = the hosted service at sleuthgraph.io.  Premium plugins and
gated features require Cloud.  Cloud-only integrations register themselves at
import time via ``register_edition_provider``.  Without a registered provider
the hooks below return ``False`` and Cloud-gated features raise
``FeatureUnavailable``.

This module is intentionally small and purpose-built:
  - Community code calls ``enterprise_enabled()`` to decide whether to expose
    a UI option / endpoint.
  - Premium plugins set ``premium = True`` and the runner refuses to execute
    them unless ``enterprise_enabled()`` is true.
  - The real edition-validation logic is injected via
    ``register_edition_provider`` (used by the Cloud deployment).

Self-hosters see Community features only.  The hosted Cloud service on
sleuthgraph.io calls ``register_edition_provider`` on startup.
"""

from __future__ import annotations

import logging
from typing import Protocol

log = logging.getLogger(__name__)


class FeatureUnavailable(RuntimeError):
    """Raised when code attempts to use a Cloud-only feature on a Community install."""


class EditionProvider(Protocol):
    """Interface the Cloud deployment implements and registers at startup."""

    def enterprise_enabled(self) -> bool: ...

    def feature_enabled(self, feature_slug: str) -> bool: ...


class _CommunityEditionProvider:
    """Default provider when no Cloud edition provider is registered."""

    def enterprise_enabled(self) -> bool:
        return False

    def feature_enabled(self, feature_slug: str) -> bool:
        return False


_provider: EditionProvider = _CommunityEditionProvider()


def register_edition_provider(provider: EditionProvider) -> None:
    """Install a custom edition provider.

    Called by the Cloud deployment on startup.  Community deployments never
    call this and stay on the default Community provider.
    """
    global _provider
    log.info("edition provider registered: %s", type(provider).__name__)
    _provider = provider


def enterprise_enabled() -> bool:
    """Return True if the Cloud edition provider is registered and active."""
    return _provider.enterprise_enabled()


def feature_enabled(feature_slug: str) -> bool:
    """Return True if a specific gated feature is licensed.

    Slugs:
      - ``ai-pivot`` — Phase 10 AI pivot suggestions
      - ``cross-case-memory`` — entity resolution across a tenant's cases
      - ``report-export`` — branded PDF report generation
      - ``watchers`` — continuous monitoring + alerting
      - ``rbac`` — granular role-based access control
      - ``audit-export`` — SIEM streaming of audit events
      - ``compliance`` — legal hold, retention policy, court-ready export
    """
    return _provider.feature_enabled(feature_slug)


def require_feature(feature_slug: str) -> None:
    """Raise FeatureUnavailable if the feature is not licensed."""
    if not feature_enabled(feature_slug):
        raise FeatureUnavailable(
            f"Feature '{feature_slug}' requires Sleuthgraph Cloud. "
            f"See https://sleuthgraph.com/pricing"
        )


# Plugin-level gate — used by the plugin runner to refuse to execute
# premium plugins on Community installs.
def assert_plugin_allowed(*, plugin_name: str, premium: bool) -> None:
    if premium and not enterprise_enabled():
        raise FeatureUnavailable(
            f"Plugin '{plugin_name}' is a premium plugin and requires "
            f"Sleuthgraph Cloud. Community installs cannot run it."
        )


# ---------------------------------------------------------------------------
# Test helpers — used by the test suite (and by the Cloud package's
# own tests) to swap providers.  Not part of the public API.
# ---------------------------------------------------------------------------


def _reset_provider_for_tests() -> None:
    global _provider
    _provider = _CommunityEditionProvider()


def _install_test_provider(*, enterprise: bool, features: set[str] | None = None) -> None:
    class _TestProvider:
        def enterprise_enabled(self) -> bool:
            return enterprise

        def feature_enabled(self, feature_slug: str) -> bool:
            return feature_slug in (features or set())

    register_edition_provider(_TestProvider())


__all__ = [
    "FeatureUnavailable",
    "EditionProvider",
    "register_edition_provider",
    "enterprise_enabled",
    "feature_enabled",
    "require_feature",
    "assert_plugin_allowed",
]
