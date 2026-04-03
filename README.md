# Toy OAuth Server

A toy OAuth 2.0 / OpenID Connect Identity Provider built from first principles in Flask. Intended as a learning tool — every protocol step is implemented explicitly so reviewers can trace the full flow through the source code.

**DO NOT USE FOR PRODUCTION UNDER ANY CIRCUMSTANCES.**

---

## What is implemented

### OAuth 2.0 (RFC 6749)
- Authorization Code grant (`response_type=code`)
- Refresh Token grant with token rotation
- Scope validation (RFC 6749 §3.3)
- Token introspection (RFC 7662)
- Token revocation (RFC 7009) — tokens are marked inactive, not deleted (audit trail)
- HTTP Basic Auth at the token endpoint (RFC 6749 §2.3.1)
- Correct `WWW-Authenticate` headers on 401 responses (RFC 6750)

### PKCE (RFC 7636)
- `code_challenge` and `code_challenge_method` accepted at `/oauth/authorize`
- S256 and plain methods supported
- `code_verifier` verified at token exchange
- Backward-compatible — flows without PKCE continue to work

### OpenID Connect
- ID token issuance as a signed JWT (RS256)
- `openid`, `profile`, and `email` scopes
- `nonce` support (replay protection)
- OIDC Discovery document (`/.well-known/openid-configuration`)
- JSON Web Key Set (`/.well-known/jwks.json`)

### JWT Infrastructure (`jwt_utils.py`)
- JWT encoding and decoding implemented from scratch using only the Python standard library
- RS256 signing — the only non-stdlib call is `private_key.sign()`
- JWK export — RSA public key components (`n`, `e`) encoded as base64url integers
- Key persistence — RSA-2048 key pair generated once and saved to `keys/private.pem`
- PKCE S256 challenge verification (`verify_pkce_challenge`) — stdlib only

### RFC 8693 Token Exchange
- `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`
- Accepts ID tokens as `subject_token`
- Validates signature, issuer, audience, and expiry explicitly

### ID-JAG (draft-ietf-oauth-identity-assertion-authz-grant)
- Issues Identity Assertion JWT Authorization Grants
- 5-minute expiry, includes `jti` for replay protection
- IdP-level access policy: Resource Servers must be registered and each client must be explicitly granted access before an ID-JAG can be issued

### Admin panel
- User management (create, edit, toggle admin)
- Application management — creation and editing is admin-only; users see their applications read-only
- Resource Server registration and client access mapping

### Audit logging
- Every security-relevant event written to `audit.log` and the console
- Fixed-width event names with `key=value` pairs — easy to `grep`
- Implemented with Python's built-in `logging` module, no external dependencies

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                 Identity Provider (IdP)              │
│                    localhost:5000                    │
│                                                      │
│  /oauth/authorize     /oauth/token                  │
│  /oauth/userinfo      /oauth/introspect             │
│  /oauth/revoke        /.well-known/jwks.json        │
│  /.well-known/openid-configuration                  │
│                                                      │
│  Admin: /admin/users  /admin/applications           │
│         /admin/resource_servers                     │
└─────────────────────────────────────────────────────┘
         ▲                          ▲
         │ Authorization Code       │ Token Exchange
         │ ID token (PKCE)          │ (ID-JAG)
         ▼                          ▼
┌──────────────────┐      ┌──────────────────────┐
│  Requesting App  │      │  Resource AS         │
│  localhost:5001  │─────▶│  localhost:5002      │
│  test_apps/      │ JAG  │  test_apps/          │
│  client.py       │      │  resource_as.py      │
└──────────────────┘      └──────────────────────┘
```

### Full ID-JAG flow

```
1. User visits the Requesting App
2. App redirects to IdP /oauth/authorize  (with PKCE code_challenge)
3. User authenticates and approves the consent screen
4. IdP redirects back with authorization code
5. App exchanges code → access_token + id_token  (POST /oauth/token, with code_verifier)
6. App exchanges id_token → ID-JAG              (POST /oauth/token, token-exchange)
7. App presents ID-JAG to Resource AS → access_token   (POST localhost:5002/token)
8. App calls protected resource with access_token       (GET  localhost:5002/resource)
```

---

## Prerequisites

- Python 3.9+
- pip

---

## Installation

```bash
pip install -r toy_oauth_server/requirements.txt
```

---

## Running the IdP

```bash
./toy_oauth_server/run_app.sh
```

The server starts at `http://localhost:5000`.

On first run, an RSA-2048 key pair is generated and saved to `keys/private.pem`.
The SQLite database `test.db` is created automatically.

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `SECRET_KEY` | `dev-secret-key-change-in-production` | Flask session signing key |
| `ISSUER_URL` | `http://localhost:5000` | JWT `iss` claim and discovery document base URL |
| `ADMIN_EMAIL` | *(unset)* | Promotes this user to admin on startup |
| `FLASK_DEBUG` | `1` (set in run_app.sh) | Enable debug mode |

---

## Admin setup

1. Register an account at `http://localhost:5000/register`
2. Set `ADMIN_EMAIL=<your email>` in `run_app.sh` and restart
3. Sign in and visit `http://localhost:5000/admin`

Application registration is admin-only. From the admin panel, create an application and assign it to a user as owner.

---

## Running the test apps

The test apps demonstrate the full ID-JAG flow end-to-end. They require the IdP to be running first.

### Configuration

Both apps read from `test_apps/config.py` (gitignored). Copy and fill in your values:

```python
# test_apps/config.py
CONFIG = {
    'client': {
        'client_id':                '',   # from IdP application registration
        'client_secret':            '',
        'idp_url':                  'http://localhost:5000',
        'idp_auth_endpoint':        'http://localhost:5000/oauth/authorize',
        'idp_token_endpoint':       'http://localhost:5000/oauth/token',
        'idp_end_session_endpoint': '',   # OIDC logout (RFC 9177), leave blank if unsupported
        'resource':                 '',   # required by Azure AD v1, blank for OIDC servers
        'resource_as_url':          'http://localhost:5002',
        'resource_token_endpoint':  'http://localhost:5002/token',
        'client_secret_key':        'client-dev-secret-key',
    },
    'resource_as': {
        'idp_url':         'http://localhost:5000',
        'resource_as_uri': 'http://localhost:5002',
    },
}
```

### One-time setup on the IdP

1. Register an account and sign in
2. In the admin panel, create an application with redirect URL `http://localhost:5001/callback` — note the `client_id` and `client_secret`
3. Create a Resource Server with URI `http://localhost:5002`
4. Grant the application access to that Resource Server
5. Add `client_id` and `client_secret` to `test_apps/config.py`

### Start the Resource AS

```bash
python3 toy_oauth_server/test_apps/resource_as.py
```

Runs at `http://localhost:5002`.

### Start the Requesting App

```bash
python3 toy_oauth_server/test_apps/client.py
```

Runs at `http://localhost:5001`. Open this URL in a browser and click **Start OAuth Flow**.

### Test app features

| Feature | Detail |
|---|---|
| PKCE (RFC 7636) | S256 challenge generated automatically on every flow |
| Verbose HTTP logging | Every request/response logged to console via `requests.Session` hook |
| Logout | `GET /logout` — clears local state and redirects to IdP end-session endpoint if configured |
| Third-party IdP support | All endpoints configurable in `config.py`; `resource` parameter supported for Azure AD v1 |

---

## Endpoints

### User-facing

| Method | Path | Description |
|---|---|---|
| GET | `/` `/index` | Home page |
| GET | `/register` | Registration form |
| POST | `/registeruser` | Create account |
| GET | `/signin` | Sign-in form |
| POST | `/signuserin` | Authenticate |
| GET | `/profile` | User profile + applications (read-only) |
| GET | `/logout` | Sign out |

### OAuth 2.0 / OIDC

| Method | Path | Description |
|---|---|---|
| GET | `/oauth/authorize` | Authorization endpoint — shows consent screen; accepts `code_challenge` |
| POST | `/oauth/authorize` | Approve or deny the authorisation request |
| POST | `/oauth/token` | Token endpoint — `authorization_code` (with optional `code_verifier`), `refresh_token`, `token-exchange` |
| GET | `/oauth/userinfo` | Returns user claims for a valid Bearer token |
| POST | `/oauth/introspect` | Token introspection (RFC 7662) |
| POST | `/oauth/revoke` | Token revocation (RFC 7009) |
| GET | `/.well-known/openid-configuration` | OIDC Discovery document |
| GET | `/.well-known/jwks.json` | Public key (JWK Set) |

### Admin (requires admin role)

| Method | Path | Description |
|---|---|---|
| GET | `/admin` | Dashboard |
| GET/POST | `/admin/users` `/admin/users/create` | List and create users |
| GET/POST | `/admin/users/<id>/edit` `/admin/users/<id>/update` | Edit user |
| GET | `/admin/applications` | List all applications |
| GET/POST | `/admin/applications/new` `/admin/applications/create` | Create application (assign to any user) |
| GET/POST | `/admin/applications/<id>/edit` `/admin/applications/<id>/update` | Edit application |
| GET/POST | `/admin/resource_servers` `/admin/resource_servers/create` | List and create resource servers |
| GET/POST | `/admin/resource_servers/<id>/edit` `/admin/resource_servers/<id>/update` | Edit resource server |
| POST | `/admin/resource_servers/<id>/grant` | Grant a client access to a resource server |
| POST | `/admin/resource_servers/<id>/revoke/<app_id>` | Revoke client access |

---

## Project structure

```
toy_oauth_server/
├── main.py              # Flask application — all routes
├── models.py            # SQLAlchemy models
├── database.py          # Database engine and session setup
├── jwt_utils.py         # JWT creation, verification, JWKS export, PKCE (from scratch)
├── run_app.sh           # Development server startup script
├── requirements.txt     # Python dependencies
├── test_oauth_flow.py   # End-to-end test script (uses requests)
├── test_apps/
│   ├── config.py        # Shared configuration for both test apps (gitignored)
│   ├── client.py        # Test requesting app (port 5001)
│   └── resource_as.py   # Test Resource Authorization Server (port 5002)
├── templates/
│   ├── base.html
│   ├── index.html  register.html  signin.html
│   ├── user_profile.html  user_registered.html
│   ├── consent.html
│   └── admin/
│       ├── dashboard.html  forbidden.html
│       ├── users.html  user_form.html
│       ├── applications.html  application_form.html
│       └── resource_servers.html  resource_server_form.html
├── audit.log            # Audit trail (auto-created, gitignored)
└── keys/
    └── private.pem      # RSA key pair (auto-generated, gitignored)
```

### Database tables

| Table | Purpose |
|---|---|
| `users` | Accounts — email, hashed password, `is_admin` flag |
| `application` | Registered OAuth applications — `client_id`, `client_secret`, `redirect_url` |
| `authorization_codes` | Short-lived (10 min) single-use codes; stores `code_challenge` for PKCE |
| `access_tokens` | Access tokens (1 hr) and refresh tokens (30 days) with `is_active` flag |
| `resource_servers` | Registered Resource Authorization Servers — name, URI |
| `client_resource_access` | Policy mapping: which applications may request ID-JAGs for which resource servers |

---

## Audit logging

Every security-relevant event is written to `audit.log` (project directory) and the console. Each line has a timestamp, a fixed-width event name, and `key=value` pairs:

```
2026-03-30 14:23:01  SIGN_IN_OK                 email=ada@example.com  ip=127.0.0.1
2026-03-30 14:23:04  CODE_ISSUED                user=ada@example.com  client=abc123  scope=openid profile
2026-03-30 14:23:05  TOKEN_ISSUED               grant=authorization_code  user=1  client=abc123  scope=openid profile
2026-03-30 14:23:05  ID_TOKEN_ISSUED            user=ada@example.com  client=abc123  scope=openid profile
2026-03-30 14:23:06  TOKEN_EXCHANGED            user=1  client=abc123  subject_type=id_token  requested=...id-jag
2026-03-30 14:23:06  ID_JAG_ISSUED              user=1  client=abc123  audience=https://ras.example.com  scope=profile
2026-03-30 14:24:10  SIGN_IN_FAIL               email=unknown@example.com  ip=127.0.0.1  reason=user_not_found
2026-03-30 14:25:00  POLICY_DENIED              user=1  client=abc123  audience=https://evil.example.com
```

### Logged events

| Event | Trigger |
|---|---|
| `USER_REGISTERED` | New account created |
| `SIGN_IN_OK` | Successful authentication |
| `SIGN_IN_FAIL` | Unknown user or wrong password (includes `reason=`) |
| `SIGN_OUT` | User logs out |
| `CONSENT_DENIED` | User denies the OAuth consent screen |
| `CODE_ISSUED` | User approves and authorization code is written to DB |
| `TOKEN_ISSUED` | Access token issued via authorization_code grant |
| `ID_TOKEN_ISSUED` | ID token issued (when `openid` scope is granted) |
| `TOKEN_REFRESHED` | Access token refreshed (old token rotated out) |
| `TOKEN_EXCHANGED` | Subject token validated in token exchange |
| `ID_JAG_ISSUED` | ID-JAG issued after policy check passes |
| `POLICY_DENIED` | Token exchange blocked — client not authorised for audience |
| `TOKEN_REJECTED` | Invalid/expired/revoked token presented at userinfo |
| `TOKEN_REVOKED` | Token deactivated via revocation endpoint |
| `ADMIN_USER_CREATED` | Admin creates a user |
| `ADMIN_USER_UPDATED` | Admin edits a user |
| `ADMIN_APP_CREATED` | Admin creates an application |
| `ADMIN_RS_CREATED` | Admin registers a Resource Server |
| `ADMIN_ACCESS_GRANTED` | Admin grants a client access to a Resource Server |
| `ADMIN_ACCESS_REVOKED` | Admin revokes a client's access to a Resource Server |

`audit.log` is gitignored and created automatically on first server start.

---

## Running the OAuth test suite

```bash
python3 toy_oauth_server/test_oauth_flow.py
```

Requires the IdP to be running and `ADMIN_EMAIL` set in `run_app.sh`. Tests registration, sign-in, admin application creation, the full Authorization Code + PKCE flow, OIDC claims, refresh tokens, introspection, revocation, and error cases.
