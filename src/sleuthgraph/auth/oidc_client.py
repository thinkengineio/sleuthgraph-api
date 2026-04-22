"""OIDC client factory.

Returns a configured ``httpx_oauth.clients.openid.OpenID`` instance when the
three ``OIDC_*`` env vars are set, else ``None``.  Callers (routes) use the
None case to short-circuit with 404 when SSO isn't wired.
"""

from __future__ import annotations

from httpx_oauth.clients.openid import OpenID

from sleuthgraph.config import Settings, get_settings


def is_oidc_configured(settings: Settings | None = None) -> bool:
    """True iff all three OIDC env vars are set.

    Single source of truth for the "is SSO wired?" check — previously
    duplicated inline in oidc.py (status, login, callback) and here.
    """
    s = settings or get_settings()
    return bool(s.oidc_issuer and s.oidc_client_id and s.oidc_client_secret)


def get_oidc_client() -> OpenID | None:
    s = get_settings()
    if not is_oidc_configured(s):
        return None
    # is_oidc_configured guarantees all three are non-None strings.
    assert s.oidc_issuer is not None
    assert s.oidc_client_id is not None
    assert s.oidc_client_secret is not None
    # httpx-oauth auto-discovers endpoints from the well-known config URL.
    well_known = s.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration"
    return OpenID(
        client_id=s.oidc_client_id,
        client_secret=s.oidc_client_secret,
        openid_configuration_endpoint=well_known,
        name="sleuthgraph-oidc",
    )
