#!/usr/bin/env python3
"""
Test OAuth Requesting Client  —  port 5001

Walks through the full ID-JAG flow end-to-end and displays every step:
  1. Authorization Code grant with PKCE (RFC 7636)  →  access_token + id_token
  2. Token Exchange                                  →  ID-JAG (targeting the Resource AS)
  3. ID-JAG → Resource AS token endpoint             →  resource access_token
  4. Fetch protected resource                        →  response payload

Configuration:
  Edit test_apps/config.py — CONFIG['client'] dict.

Startup:
  python3 test_apps/client.py
"""

import os
import json
import base64
import hashlib
import logging
import secrets
import urllib.parse
import importlib.util

import requests
from flask import Flask, request, redirect, render_template_string

# ── Configuration ─────────────────────────────────────────────────────────────

_spec = importlib.util.spec_from_file_location(
    '_config', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_config.py')
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
_c = _mod.CONFIG.get('client', {})

IDP_URL                   = _mod.CONFIG.get('idp_url',           'http://localhost:5000')
IDP_AUTH_ENDPOINT         = _c.get('idp_auth_endpoint',         'http://localhost:5000/oauth/authorize')
IDP_TOKEN_ENDPOINT        = _c.get('idp_token_endpoint',        'http://localhost:5000/oauth/token')
IDP_END_SESSION_ENDPOINT  = _c.get('idp_end_session_endpoint',  '')
RESOURCE                = _c.get('resource',             'http://localhost:5002/resource')
RESOURCE_AS_URL         = _mod.CONFIG.get('resource_as_url', 'http://localhost:5002')
RESOURCE_TOKEN_ENDPOINT = _c.get('resource_token_endpoint', 'http://localhost:5002/token')
CLIENT_ID               = _c.get('client_id',           '')
CLIENT_SECRET           = _c.get('client_secret',       '')
REDIRECT_URI            = 'http://localhost:5001/callback'

app = Flask(__name__)
app.secret_key = _c.get('client_secret_key', 'client-dev-secret-key')

# Server-side state store — keyed by the state value sent to the IdP.
# Using a server-side dict instead of the Flask session cookie avoids
# browser SameSite/cross-port issues that break OAuth flows on localhost:
# the session cookie set during /start may not be sent back on the redirect
# from the IdP (different port → different origin → cookie may be blocked).
import threading
_pending_states   = {}    # state → {nonce, audience, scope, code_verifier}
_states_lock      = threading.Lock()
_current_id_token = None  # stored after a successful flow; used as id_token_hint on logout


# ── HTTP logging ──────────────────────────────────────────────────────────────

_http_log = logging.getLogger('http')
_http_log.setLevel(logging.DEBUG)
_log_handler = logging.StreamHandler()
_log_handler.setFormatter(logging.Formatter('%(asctime)s  %(message)s', datefmt='%H:%M:%S'))
_http_log.addHandler(_log_handler)


def _log_response(r, **_):
    """
    requests response hook — fires after every request made through _session.
    Logs the outgoing request and the incoming response.
    The Authorization header value is truncated to avoid printing credentials.
    """
    req = r.request

    # Sanitize headers — show Authorization prefix only, not the full token
    auth = req.headers.get('Authorization', '')
    auth_display = (auth[:20] + '…') if auth else '(none)'

    _http_log.debug('→ %s %s', req.method, req.url)
    _http_log.debug('  Authorization: %s', auth_display)
    if req.body:
        body_str = req.body if isinstance(req.body, str) else req.body.decode('utf-8', errors='replace')
        _http_log.debug('  body: %s', body_str[:400])

    _http_log.debug('← %s %s', r.status_code, r.reason)
    _http_log.debug('  body: %s', r.text[:600])


_session = requests.Session()
_session.hooks['response'].append(_log_response)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _b64url_decode(s):
    pad = (4 - len(s) % 4) % 4
    return base64.urlsafe_b64decode(s + '=' * pad)


def decode_jwt_claims(token):
    """
    Decode the payload of a JWT without verifying the signature.
    Used for display only — the IdP already verified these claims
    before issuing the token.
    """
    parts = token.split('.')
    if len(parts) != 3:
        return {}
    try:
        return json.loads(_b64url_decode(parts[1]))
    except Exception:
        return {}


def fmt(obj):
    """Pretty-print a dict as indented JSON."""
    return json.dumps(obj, indent=2, default=str)


# ── HTML templates ────────────────────────────────────────────────────────────

INDEX_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <title>Test OAuth Client</title>
</head>
<body class="bg-light">
<div class="container mt-5">
<div class="row justify-content-center"><div class="col-md-7">

  <h2 class="mb-1">Test OAuth Client</h2>
  <p class="text-muted mb-4">Demonstrates the full ID-JAG cross-domain delegation flow.</p>

  {% if not configured %}
  <div class="alert alert-warning">
    <strong>Not configured.</strong>
    Set <code>client_id</code> and <code>client_secret</code> in
    <code>test_apps/client_config.py</code> and restart.
  </div>
  {% endif %}

  <div class="card shadow-sm mb-4">
    <div class="card-body p-4">
      <form action="/start" method="GET">
        <div class="mb-3">
          <label class="form-label fw-semibold">Scope</label>
          <input type="text" class="form-control font-monospace"
                 name="scope" value="openid profile email">
          <div class="form-text">Space-separated OIDC scopes to request from the IdP.</div>
        </div>
        <div class="mb-4">
          <label class="form-label fw-semibold">Audience — Resource AS URI</label>
          <input type="text" class="form-control font-monospace"
                 name="audience" value="{{ the_audience }}">
          <div class="form-text">
            Must exactly match the URI registered in the IdP's admin panel
            and in the Resource AS configuration.
          </div>
        </div>
        <button type="submit" class="btn btn-primary"
                {{ 'disabled' if not configured }}>
          Start OAuth Flow →
        </button>
      </form>
    </div>
  </div>

  <div class="card bg-white shadow-sm">
    <div class="card-body p-4">
      <h6 class="fw-semibold mb-3">Setup checklist</h6>
      <ol class="mb-0 small text-muted">
        <li class="mb-1">
          Register an application on the <a href="{{ idp_url }}" target="_blank">IdP</a>
          with redirect URL <code>http://localhost:5001/callback</code>.
        </li>
        <li class="mb-1">
          On the IdP admin panel, register a Resource Server with
          URI <code>{{ resource_as_url }}</code>.
        </li>
        <li class="mb-1">
          Grant the client application access to that resource server.
        </li>
        <li class="mb-1">
          Set <code>client_id</code> and <code>client_secret</code> in
          <code>test_apps/client_config.py</code> and restart this app.
        </li>
        <li>Start the Resource AS: <code>python3 test_apps/resource_as.py</code></li>
      </ol>
    </div>
  </div>

</div></div>
</div>
</body>
</html>
"""

RESULT_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <title>Flow Results — Test OAuth Client</title>
</head>
<body class="bg-light">
<div class="container mt-4 mb-5">

  <div class="d-flex justify-content-between align-items-center mb-4">
    <h2 class="mb-0">ID-JAG Flow Results</h2>
    <div class="d-flex gap-2">
      <a href="/" class="btn btn-sm btn-outline-secondary">← Start Again</a>
      <a href="/logout" class="btn btn-sm btn-outline-danger">Log Out</a>
    </div>
  </div>

  {% if error %}
  <div class="alert alert-danger">{{ error }}</div>
  {% endif %}

  {% for step in steps %}
  <div class="card shadow-sm mb-4 {{ 'border-success' if step.success else 'border-danger' }}">
    <div class="card-header d-flex justify-content-between align-items-center">
      <span class="fw-semibold">{{ step.title }}</span>
      <span class="badge {{ 'bg-success' if step.success else 'bg-danger' }}">
        {{ step.status }}
      </span>
    </div>
    <div class="card-body p-3">

      <p class="font-monospace text-muted small mb-2">
        {{ step.method }} {{ step.url }}
      </p>

      {% if step.request_params %}
      <p class="text-muted small mb-1">Request params:</p>
      <pre class="bg-light border rounded p-2 small mb-3" style="white-space:pre-wrap">{{ step.request_params }}</pre>
      {% endif %}

      <p class="text-muted small mb-1">Response:</p>
      <pre class="bg-light border rounded p-2 small mb-0" style="white-space:pre-wrap">{{ step.response_str }}</pre>

      {% if step.claims %}
      <hr class="my-3">
      <p class="text-muted small mb-1">Decoded JWT claims:</p>
      <pre class="bg-light border rounded p-2 small mb-0" style="white-space:pre-wrap">{{ step.claims_str }}</pre>
      {% endif %}

    </div>
  </div>
  {% endfor %}

</div>
</body>
</html>
"""


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template_string(INDEX_HTML,
        configured=bool(CLIENT_ID and CLIENT_SECRET),
        idp_url=IDP_URL,
        the_audience=RESOURCE_AS_URL,
    )


@app.route('/start')
def start():
    """
    Kick off the Authorization Code flow.
    Save nonce/state/audience in the server-side state store so /callback can retrieve them.
    """
    scope    = request.args.get('scope', 'openid profile email')
    audience = request.args.get('audience', RESOURCE_AS_URL)
    nonce    = secrets.token_urlsafe(16)
    state    = secrets.token_urlsafe(16)

    # PKCE (RFC 7636) — generate verifier and derive S256 challenge.
    # code_verifier  = random URL-safe string (43 chars from 32 bytes)
    # code_challenge = BASE64URL(SHA256(code_verifier))
    # Only the challenge is sent to the IdP now; the verifier is sent
    # at token-exchange time, proving this client initiated the flow.
    code_verifier  = secrets.token_urlsafe(32)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode('ascii')).digest()
    ).rstrip(b'=').decode('ascii')

    with _states_lock:
        _pending_states[state] = {
            'nonce':         nonce,
            'audience':      audience,
            'scope':         scope,
            'code_verifier': code_verifier,
        }

    auth_params = {
        'client_id':             CLIENT_ID,
        'redirect_uri':          REDIRECT_URI,
        'response_type':         'code',
        'scope':                 scope,
        'state':                 state,
        'nonce':                 nonce,
        'code_challenge':        code_challenge,
        'code_challenge_method': 'S256',
    }


    return redirect(f'{IDP_AUTH_ENDPOINT}?{urllib.parse.urlencode(auth_params)}')


@app.route('/logout')
def logout():
    """
    Clear local state and redirect to the IdP end-session endpoint.

    OIDC RP-Initiated Logout (RFC 9177):
      GET {end_session_endpoint}?id_token_hint=<token>&post_logout_redirect_uri=http://localhost:5001/

    The id_token_hint tells the IdP which session to terminate.
    If IDP_END_SESSION_ENDPOINT is not configured, just returns to the home page.
    """
    global _current_id_token

    token = _current_id_token
    _current_id_token = None

    with _states_lock:
        _pending_states.clear()

    if IDP_END_SESSION_ENDPOINT:
        params = {'post_logout_redirect_uri': 'http://localhost:5001/'}
        if token:
            params['id_token_hint'] = token
        return redirect(f'{IDP_END_SESSION_ENDPOINT}?{urllib.parse.urlencode(params)}')

    return redirect('/')


@app.route('/callback')
def callback():
    """
    Receive the authorization code from the IdP and drive steps 1-4.
    """
    error = request.args.get('error')
    if error:
        desc = request.args.get('error_description', '')
        return f'<p>Error from IdP: <strong>{error}</strong> — {desc}</p><a href="/">Back</a>'

    code  = request.args.get('code')
    state = request.args.get('state')

    with _states_lock:
        state_data = _pending_states.pop(state, None)

    if not state_data:
        return 'Invalid or expired state — flow may have timed out or been replayed', 400

    audience      = state_data['audience']
    scope         = state_data['scope']
    code_verifier = state_data['code_verifier']
    steps         = []

    # ── Step 1: Exchange authorization code for tokens (with PKCE verifier) ──
    token_data = {
        'grant_type':    'authorization_code',
        'code':          code,
        'redirect_uri':  REDIRECT_URI,
        'client_id':     CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'code_verifier': code_verifier,
    }


    r = _session.post(IDP_TOKEN_ENDPOINT, data=token_data)
    td = r.json() if r.headers.get('content-type', '').startswith('application/json') else {}
    id_token        = td.get('id_token', '')
    id_token_claims = decode_jwt_claims(id_token) if id_token else {}

    global _current_id_token
    _current_id_token = id_token or None  # stored for use as id_token_hint on logout

    print('\n── Token endpoint response ──────────────────────────', flush=True)
    print(f'Status : {r.status_code}', flush=True)
    print(f'Body   : {json.dumps(td, indent=2)}', flush=True)
    if id_token:
        print(f'ID token claims:', flush=True)
        print(json.dumps(id_token_claims, indent=2), flush=True)
    print('─────────────────────────────────────────────────────\n', flush=True)

    steps.append({
        'title':  'Step 1 — Authorization Code → Tokens (PKCE)',
        'method': 'POST',
        'url':    IDP_TOKEN_ENDPOINT,
        'request_params': 'grant_type=authorization_code\ncode_verifier=<verifier>',
        'status':  r.status_code,
        'success': r.status_code == 200,
        'response_str': fmt({k: (v[:40] + '…' if isinstance(v, str) and len(v) > 40
                                 and k != 'scope' else v)
                              for k, v in td.items()}),
        'claims':     id_token_claims or None,
        'claims_str': fmt(id_token_claims) if id_token_claims else '',
    })

    if r.status_code != 200 or not id_token:
        return render_template_string(RESULT_HTML, steps=steps,
                                      error='Token exchange failed — see Step 1.')

    # ── Step 2: Exchange ID token for ID-JAG ──────────────────────────────────
    auth = base64.b64encode((CLIENT_ID+':'+CLIENT_SECRET).encode()).decode()

    exchange_data = {
        'grant_type':           'urn:ietf:params:oauth:grant-type:token-exchange',
        'subject_token':        id_token,
        'subject_token_type':   'urn:ietf:params:oauth:token-type:id_token',
        'requested_token_type': 'urn:ietf:params:oauth:token-type:id-jag',
        'audience':             audience,
        'scope':                scope,
        'resource':             RESOURCE
    }

    r = _session.post(
        IDP_TOKEN_ENDPOINT, 
        headers={'Authorization': f'Basic {auth}'},           
        data=exchange_data)
    jd = r.json() if r.headers.get('content-type', '').startswith('application/json') else {}
    id_jag        = jd.get('access_token', '')
    id_jag_claims = decode_jwt_claims(id_jag) if id_jag else {}

    if id_jag:
        print(f'ID JAG claims:', flush=True)
        print(json.dumps(id_jag_claims, indent=2), flush=True)
    print('─────────────────────────────────────────────────────\n', flush=True)


    steps.append({
        'title':  'Step 2 — ID Token → ID-JAG',
        'method': 'POST',
        'url':    IDP_TOKEN_ENDPOINT,
        'request_params': (
            f'grant_type=token-exchange\n'
            f'subject_token_type=id_token\n'
            f'requested_token_type=id-jag\n'
            f'audience={audience}'
        ),
        'status':  r.status_code,
        'success': r.status_code == 200,
        'response_str': fmt({k: (v[:40] + '…' if isinstance(v, str) and len(v) > 40
                                 and k not in ('issued_token_type', 'token_type') else v)
                              for k, v in jd.items()}),
        'claims':     id_jag_claims or None,
        'claims_str': fmt(id_jag_claims) if id_jag_claims else '',
    })

    if r.status_code != 200 or not id_jag:
        return render_template_string(RESULT_HTML, steps=steps,
                                      error='ID-JAG exchange failed — see Step 2.')

    # ── Step 3: Present ID-JAG to the Resource AS ─────────────────────────────
    auth2 = base64.b64encode((CLIENT_ID+':'+CLIENT_SECRET).encode()).decode()
    r = _session.post(RESOURCE_TOKEN_ENDPOINT, 
          headers={'Authorization': f'Basic {auth2}'},           
          data={
          'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
          'assertion':  id_jag,
          'scope':      scope,

    }
    )
    rd = r.json() if r.headers.get('content-type', '').startswith('application/json') else {}
    resource_token = rd.get('access_token', '')

    steps.append({
        'title':  'Step 3 — ID-JAG → Resource Access Token',
        'method': 'POST',
        'url':    RESOURCE_TOKEN_ENDPOINT,
        'request_params': 'grant_type=id-jag\nassertion=<id_jag>',
        'status':  r.status_code,
        'success': r.status_code == 200,
        'response_str': fmt({k: (v[:24] + '…' if isinstance(v, str) and len(v) > 24
                                 and k == 'access_token' else v)
                              for k, v in rd.items()}),
        'claims': None, 'claims_str': '',
    })

    if r.status_code != 200 or not resource_token:
        return render_template_string(RESULT_HTML, steps=steps,
                                      error='Resource AS token exchange failed — see Step 3.')

    # ── Step 4: Fetch the protected resource ──────────────────────────────────
    r = _session.get(f'{RESOURCE}',
                     headers={'Authorization': f'Bearer {resource_token}'})
    res_data = r.json() if r.headers.get('content-type', '').startswith('application/json') else r.text

    steps.append({
        'title':  'Step 4 — Fetch Protected Resource',
        'method': 'GET',
        'url':    f'{RESOURCE}',
        'request_params': 'Authorization: Bearer <resource_access_token>',
        'status':  r.status_code,
        'success': r.status_code == 200,
        'response_str': fmt(res_data) if isinstance(res_data, dict) else str(res_data),
        'claims': None, 'claims_str': '',
    })

    return render_template_string(RESULT_HTML, steps=steps, error=None)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    if not CLIENT_ID or not CLIENT_SECRET:
        print('WARNING: CLIENT_ID and/or CLIENT_SECRET not set.')
        print('Set them as environment variables before starting.')
    print(f'Client app running at http://localhost:5001')
    print(f'Redirect URI:      {REDIRECT_URI}')
    print(f'IdP URL:           {IDP_URL}')
    print(f'Auth endpoint:     {IDP_AUTH_ENDPOINT}')
    print(f'Token endpoint:    {IDP_TOKEN_ENDPOINT}')
    if IDP_END_SESSION_ENDPOINT:
        print(f'End-session EP:    {IDP_END_SESSION_ENDPOINT}')
    if RESOURCE:
        print(f'Resource:          {RESOURCE}')
    print(f'Resource AS URL:   {RESOURCE_AS_URL}')
    print(f'Resource token EP: {RESOURCE_TOKEN_ENDPOINT}')
    app.run(port=5001, debug=True)
