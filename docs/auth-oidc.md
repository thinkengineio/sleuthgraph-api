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
2. If a local user matches by email and has no `oidc_sub` → link and log in,
   **provided the id_token asserts `email_verified=true`**. The local password
   is rotated to a random value at this point (see "Password invalidation on
   linking" below).
3. If a local user matches by email but has a *different* `oidc_sub` → 409
   conflict. Resolve manually (admin edits the DB row or deletes the stale account).
4. If no local user matches:
   - Signup enabled (`AUTH_ALLOW_SIGNUP=true`) **and `email_verified=true`**
     → auto-provision.
   - Signup disabled, or `email_verified=false` → 403 "account not linked".
     Create the local account first (either admin-bootstrapped via
     `AUTH_ADMIN_EMAIL`/`AUTH_ADMIN_PASSWORD` or through a separate signup
     flow), then sign in via SSO; Sleuthgraph will link on first successful
     OIDC login once the email is verified at the IdP.

### email_verified requirement

Sleuthgraph only auto-links or auto-provisions when the IdP's id_token
asserts `email_verified=true`. This prevents an attacker who can cause
their IdP account to claim any unverified email from silently
hijacking a local Sleuthgraph account with the same address.

### Password invalidation on linking

When an existing local account is auto-linked to an IdP subject (branch 2
above), the account's local password is replaced with a random value.
Rationale: before linking, anyone who set a password for that email
(including a squatting attacker who registered first) could continue
signing in by password after SSO is wired up. Rotating the password at
link time closes that gap. The legitimate owner can recover password
access via the standard password-reset email flow if they need it.

### id_token validation

Every callback validates the id_token:

- Signature is verified against the IdP's JWKS (`jwks_uri` from discovery).
- `iss` must equal `OIDC_ISSUER`, `aud` must contain `OIDC_CLIENT_ID`.
- `exp` must be in the future (with 60 s leeway); `iat` must be present.
- `nonce` must equal the per-request value we sent in the authorize URL
  (replay protection — OIDC Core 1.0 §15.5.2).
- `alg=none` is unconditionally rejected.

`sub`, `email`, and `email_verified` are read from the validated id_token
payload, never from the userinfo endpoint directly. If an IdP only emits
`email` via userinfo (e.g. Auth0 with custom profile scopes), the email
string is accepted from userinfo but `email_verified` still comes from the
id_token — which for that IdP typically means you need to explicitly add
the verified claim to the id_token (Auth0 action / Okta claim / etc).

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
- **"oidc_account_not_linked"** — user has no local account, or signup is
  disabled, or the IdP did not assert `email_verified=true`. Check the
  userinfo / id_token response and ensure your IdP emits
  `"email_verified": true` for the user.
- **"oidc_account_conflict"** — email matches a local account, but that account
  was previously linked to a *different* IdP subject. Manual cleanup required.
- **"oidc_missing_id_token"** — the token response from the IdP did not
  include an `id_token`. Check that your client is registered as an OIDC
  client (not a bare OAuth2 client) and that `openid` is in the scope list.
- **"oidc_invalid_id_token"** — signature, issuer, audience, expiry, or
  nonce mismatch. Inspect app logs for the specific reason.
