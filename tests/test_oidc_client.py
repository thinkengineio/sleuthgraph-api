"""Tests for the OIDC client factory."""

from unittest.mock import MagicMock, patch

from sleuthgraph.auth.oidc_client import get_oidc_client


def test_returns_none_when_unconfigured(monkeypatch):
    monkeypatch.delenv("OIDC_ISSUER", raising=False)
    monkeypatch.delenv("OIDC_CLIENT_ID", raising=False)
    monkeypatch.delenv("OIDC_CLIENT_SECRET", raising=False)
    assert get_oidc_client() is None


def test_returns_client_when_configured(monkeypatch):
    monkeypatch.setenv("OIDC_ISSUER", "https://id.example.com")
    monkeypatch.setenv("OIDC_CLIENT_ID", "cid")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "csec")

    # OpenID.__init__ makes a sync HTTP call to fetch well-known config.
    # Mock it out so we don't need a live IdP in unit tests.
    fake_config = {
        "authorization_endpoint": "https://id.example.com/authorize",
        "token_endpoint": "https://id.example.com/token",
        "userinfo_endpoint": "https://id.example.com/userinfo",
    }
    mock_response = MagicMock()
    mock_response.json.return_value = fake_config
    mock_response.raise_for_status.return_value = None

    with patch("httpx.Client") as mock_client_cls:
        mock_http = MagicMock()
        mock_http.__enter__ = MagicMock(return_value=mock_http)
        mock_http.__exit__ = MagicMock(return_value=False)
        mock_http.get.return_value = mock_response
        mock_client_cls.return_value = mock_http

        client = get_oidc_client()

    assert client is not None
    assert client.client_id == "cid"
