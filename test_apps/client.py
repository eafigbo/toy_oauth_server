#!/usr/bin/env python3
"""
Test OAuth Requesting Client  —  port 5001

Walks through the full ID-JAG flow end-to-end and displays every step:
  1. Authorization Code grant  →  access_token + id_token
  2. Token Exchange             →  ID-JAG (targeting the Resource AS)
  3. ID-JAG → Resource AS token endpoint  →  resource access_token
  4. Fetch protected resource   →  response payload

Configuration (environment variables):
  CLIENT_ID       — client_id of the application registered on the IdP
  CLIENT_SECRET   — client_secret of the same application
  IDP_URL         — base URL of the IdP            (default: http://localhost:5000)
  RESOURCE_AS_URL — base URL of the Resource AS    (default: http://localhost:5002)

Startup:
  export CLIENT_ID=<id>  CLIENT_SECRET=<secret>
  python3 test_apps/client.py
"""

import os
import json
import base64
import secrets
import urllib.parse

import requests
from flask import Flask, request, redirect, render_template_string

# ── Configuration ─────────────────────────────────────────────────────────────

IDP_URL         = os.environ.get('IDP_URL',         'http://localhost:5000')
RESOURCE_AS_URL = os.environ.get('RESOURCE_AS_URL', 'http://localhost:5002')
CLIENT_ID       = os.environ.get('CLIENT_ID',       '')
CLIENT_SECRET   = os.environ.get('CLIENT_SECRET',   '')
REDIRECT_URI    = 'http://localhost:5001/callback'

app = Flask(__name__)
app.secret_key = os.environ.get('CLIENT_SECRET_KEY', 'client-dev-secret-key')

# Server-side state store — keyed by the state value sent to the IdP.
# Using a server-side dict instead of the Flask session cookie avoids
# browser SameSite/cross-port issues that break OAuth flows on localhost:
# the session cookie set during /start may not be sent back on the redirect
# from the IdP (different port → different origin → cookie may be blocked).
import threading
_pending_states = {}         # state → {nonce, audience, scope}
_states_lock    = threading.Lock()


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
    Set the <code>CLIENT_ID</code> and <code>CLIENT_SECRET</code> environment variables and restart.
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
                 name="audience" value="{{ resource_as_url }}">
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
          Set <code>CLIENT_ID</code> and <code>CLIENT_SECRET</code> and restart this app.
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
    <a href="/" class="btn btn-sm btn-outline-secondary">← Start Again</a>
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
        resource_as_url=RESOURCE_AS_URL,
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

    with _states_lock:
        _pending_states[state] = {
            'nonce':    nonce,
            'audience': audience,
            'scope':    scope,
        }

    params = urllib.parse.urlencode({
        'client_id':     CLIENT_ID,
        'redirect_uri':  REDIRECT_URI,
        'response_type': 'code',
        'scope':         scope,
        'state':         state,
        'nonce':         nonce,
    })
    return redirect(f'{IDP_URL}/oauth/authorize?{params}')


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

    audience = state_data['audience']
    scope    = state_data['scope']
    steps    = []

    # ── Step 1: Exchange authorization code for tokens ────────────────────────
    r = requests.post(f'{IDP_URL}/oauth/token', data={
        'grant_type':    'authorization_code',
        'code':          code,
        'redirect_uri':  REDIRECT_URI,
        'client_id':     CLIENT_ID,
        'client_secret': CLIENT_SECRET,
    })
    td = r.json() if r.headers.get('content-type', '').startswith('application/json') else {}
    id_token    = td.get('id_token', '')
    id_token_claims = decode_jwt_claims(id_token) if id_token else {}

    steps.append({
        'title':  'Step 1 — Authorization Code → Tokens',
        'method': 'POST',
        'url':    f'{IDP_URL}/oauth/token',
        'request_params': 'grant_type=authorization_code',
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
    r = requests.post(f'{IDP_URL}/oauth/token', data={
        'grant_type':           'urn:ietf:params:oauth:grant-type:token-exchange',
        'subject_token':        id_token,
        'subject_token_type':   'urn:ietf:params:oauth:token-type:id_token',
        'requested_token_type': 'urn:ietf:params:oauth:token-type:id-jag',
        'audience':             audience,
        'scope':                'profile',
        'client_id':            CLIENT_ID,
        'client_secret':        CLIENT_SECRET,
    })
    jd = r.json() if r.headers.get('content-type', '').startswith('application/json') else {}
    id_jag        = jd.get('access_token', '')
    id_jag_claims = decode_jwt_claims(id_jag) if id_jag else {}

    steps.append({
        'title':  'Step 2 — ID Token → ID-JAG',
        'method': 'POST',
        'url':    f'{IDP_URL}/oauth/token',
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
    r = requests.post(f'{RESOURCE_AS_URL}/token', data={
        'grant_type': 'urn:ietf:params:oauth:token-type:id-jag',
        'assertion':  id_jag,
        'client_id':  CLIENT_ID,
    })
    rd = r.json() if r.headers.get('content-type', '').startswith('application/json') else {}
    resource_token = rd.get('access_token', '')

    steps.append({
        'title':  'Step 3 — ID-JAG → Resource Access Token',
        'method': 'POST',
        'url':    f'{RESOURCE_AS_URL}/token',
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
    r = requests.get(f'{RESOURCE_AS_URL}/resource',
                     headers={'Authorization': f'Bearer {resource_token}'})
    res_data = r.json() if r.headers.get('content-type', '').startswith('application/json') else r.text

    steps.append({
        'title':  'Step 4 — Fetch Protected Resource',
        'method': 'GET',
        'url':    f'{RESOURCE_AS_URL}/resource',
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
    print(f'Redirect URI:    {REDIRECT_URI}')
    print(f'IdP URL:         {IDP_URL}')
    print(f'Resource AS URL: {RESOURCE_AS_URL}')
    app.run(port=5001, debug=True)
