# OIDC Single Sign-On

Sleuthgraph supports any OIDC-compliant IdP. It uses Authorization Code + PKCE
and issues the usual session cookie on success — OIDC is an alternate login
front door, not a second session system.

## Required env vars

    OIDC_ISSUER=https://your-idp.example.com
    OIDC_CLIENT_ID=sleuthgraph
    OIDC_CLIENT_SECRET=...
    # REQUIRED when OIDC_ISSUER is set. Must be the absolute URL
    # registered at your IdP. We do NOT derive this from the incoming
    # request: relying on Host/X-Forwarded-Host lets an attacker
    # redirect the authorization code to their own domain.
    OIDC_REDIRECT_URL=https://sleuthgraph.yourcompany.com/auth/oidc/callback
    # Optional — comma-separated, default: openid,email,profile
    OIDC_SCOPES=openid,email,profile

If `OIDC_ISSUER` is set but `OIDC_REDIRECT_URL` is not, the app fails
fast at startup with a Pydantic ValidationError.

Redirect URI registered in your IdP must be:

    https://<your-sleuthgraph-domain>/auth/oidc/callback

## Account linking policy

When a user completes IdP login:

1. If a local user has `oidc_sub` matching the IdP subject → log them in.
2. If a local user matches by email and has no `oidc_sub` → link and log in.
3. If a local user matches by email but has a *different* `oidc_sub` → 409
   conflict. Resolve manually (admin edits the DB row or deletes the stale account).
4. If no local user matches:
   - Signup enabled (`AUTH_ALLOW_SIGNUP=true`) → auto-provision.
   - Signup disabled → 403 "account not linked". Create the local account first
     (either admin-bootstrapped via `AUTH_ADMIN_EMAIL`/`AUTH_ADMIN_PASSWORD` or
     through a separate signup flow), then sign in via SSO; Sleuthgraph will link
     on first successful OIDC login.

## Provider examples

### Keycloak

1. Realm → Clients → Create → `sleuthgraph`
2. Client authentication: ON · Authorization: OFF
3. Valid redirect URIs: `https://<domain>/auth/oidc/callback`
4. Web origins: `https://<domain>`
5. Copy the client secret to `OIDC_CLIENT_SECRET`
6. `OIDC_ISSUER=https://<keycloak>/realms/<realm>`

### Authentik

1. Applications → Providers → Create → OAuth2/OpenID Provider (`sleuthgraph`)
2. Authentication flow: default-authentication-flow
3. Client type: Confidential · Redirect URIs: `https://<domain>/auth/oidc/callback`
4. Scopes: email, profile, openid
5. Applications → Create → link to provider · Slug `sleuthgraph`
6. `OIDC_ISSUER=https://<authentik>/application/o/sleuthgraph/`

### Google

1. Cloud Console → APIs & Services → Credentials → OAuth 2.0 Client ID (Web application)
2. Authorized redirect URIs: `https://<domain>/auth/oidc/callback`
3. Copy client ID + secret
4. `OIDC_ISSUER=https://accounts.google.com`

## Troubleshooting

- **Getting redirected in a loop** — your `OIDC_REDIRECT_URL` (or the IdP's
  registered URI) probably doesn't match what the callback endpoint expects.
  Token exchange includes `redirect_uri` which must byte-for-byte match the
  value used in the authorization request.
- **"oidc_account_not_linked"** — user has no local account, and signup is disabled.
- **"oidc_account_conflict"** — email matches a local account, but that account
  was previously linked to a *different* IdP subject. Manual cleanup required.
