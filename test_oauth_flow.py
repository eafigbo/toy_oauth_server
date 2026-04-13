#!/usr/bin/env python3
"""
End-to-end test script for the Toy OAuth Server.

Covers:
  - User registration
  - Admin setup and application registration via admin panel
  - Authorization Code flow with OIDC (RFC 6749 §4.1, OpenID Connect)
  - Refresh token grant (RFC 6749 §6)
  - Token introspection (RFC 7662)
  - Token revocation (RFC 7009)
  - Error cases

Usage:
    pip install requests
    python3 test_oauth_flow.py

The server must be running first:
    ./run_app.sh

Prerequisites:
    ADMIN_EMAIL must be set in config.py and the server restarted so that
    the admin user is promoted on startup.  Defaults match the value already
    in config.py (admin@test.com).
"""

import re
import sys
import base64
import hashlib
import secrets
import requests
from urllib.parse import urlparse, parse_qs

from config import ADMIN_EMAIL, ISSUER_URL

BASE_URL     = ISSUER_URL
REDIRECT_URI = 'http://localhost:9999/callback'   # dummy — we capture the code from the Location header

# Admin credentials — must match ADMIN_EMAIL in config.py
ADMIN_PASSWORD = 'Admin-Password-123!'

# Unique test-user credentials per run so tests never interfere with each other
_run_id       = secrets.token_hex(3)
USER_EMAIL    = f'testuser_{_run_id}@example.com'
USER_PASSWORD = 'Test-Password-123!'
APP_NAME      = f'Test App {_run_id}'


# ── Reporting ────────────────────────────────────────────────────────────────

_passed = 0
_failed = 0

def _ok(label):
    global _passed
    _passed += 1
    print(f'  [PASS] {label}')

def _fail(label, detail=''):
    global _failed
    _failed += 1
    suffix = f' — {detail}' if detail else ''
    print(f'  [FAIL] {label}{suffix}')

def check(label, condition, detail=''):
    if condition:
        _ok(label)
    else:
        _fail(label, detail)
    return condition

def section(title):
    print(f'\n{title}')
    print('─' * len(title))

def abort(reason):
    print(f'\n  Stopping: {reason}\n')
    _summary()
    sys.exit(1)

def _summary():
    print(f'\n{"=" * 45}')
    print(f'  {_passed} passed   {_failed} failed')
    print(f'{"=" * 45}\n')


# ── Test steps ───────────────────────────────────────────────────────────────

def step_register_user(s):
    section('1. Register test user')
    r = s.post(f'{BASE_URL}/registeruser', data={
        'first_name':   'Test',
        'last_name':    'User',
        'email':        USER_EMAIL,
        'home_address': '1 Test Street',
        'password':     USER_PASSWORD,
    })
    check('Returns 200',          r.status_code == 200)
    check('Success page rendered', 'registered' in r.text.lower() or 'test user' in r.text.lower())


def step_setup_admin(admin_s):
    section('2. Setup admin user')
    # Register admin (may already exist — that is fine)
    admin_s.post(f'{BASE_URL}/registeruser', data={
        'first_name':   'Admin',
        'last_name':    'User',
        'email':        ADMIN_EMAIL,
        'home_address': '1 Admin Street',
        'password':     ADMIN_PASSWORD,
    })
    r = admin_s.post(f'{BASE_URL}/signuserin', data={
        'email':    ADMIN_EMAIL,
        'password': ADMIN_PASSWORD,
    }, allow_redirects=True)
    ok = check('Admin signed in', r.url.endswith('/profile'))
    if not ok:
        abort('admin sign-in failed')

    r = admin_s.get(f'{BASE_URL}/admin')
    ok = check('Admin panel accessible (user has admin role)',
               r.status_code == 200 and 'Dashboard' in r.text)
    if not ok:
        abort(
            f'Admin panel returned {r.status_code}. '
            f'Ensure ADMIN_EMAIL={ADMIN_EMAIL} is set in run_app.sh and the server was restarted.'
        )


def step_register_app(admin_s):
    section('3. Register OAuth application via admin')

    # Find the test user's database ID from the admin users list
    users_page = admin_s.get(f'{BASE_URL}/admin/users').text
    # Table rows: <td class="text-muted small">ID</td> … <td>EMAIL</td>
    user_rows = re.findall(
        r'<td class="text-muted small">(\d+)</td>.*?<td>[^<]*</td>.*?<td>([^<]+)</td>',
        users_page, re.DOTALL
    )
    user_id = next((int(uid) for uid, email in user_rows if email.strip() == USER_EMAIL), None)
    ok = check('Test user found in admin user list', user_id is not None)
    if not ok:
        abort('could not find test user in admin panel')

    # Create the application owned by the test user
    r = admin_s.post(f'{BASE_URL}/admin/applications/create', data={
        'user_id':          user_id,
        'application_name': APP_NAME,
        'description':      'OAuth test application',
        'redirect_url':     REDIRECT_URI,
        'icon_url':         '',
        'home_page_url':    '',
        'privacy_policy_url': '',
    }, allow_redirects=True)
    check('Application created (redirected to admin list)', '/admin/applications' in r.url)

    # Locate the new application's edit page to read client_id and client_secret
    apps_page = admin_s.get(f'{BASE_URL}/admin/applications').text
    app_match = re.search(
        rf'{re.escape(APP_NAME)}.*?/admin/applications/(\d+)/edit',
        apps_page, re.DOTALL
    )
    ok = check('New application found in admin list', app_match is not None)
    if not ok:
        abort('could not locate the newly created application in admin panel')

    edit_page = admin_s.get(f'{BASE_URL}/admin/applications/{app_match.group(1)}/edit').text
    codes = re.findall(r'<code>([^<]+)</code>', edit_page)
    client_id     = next((c for c in codes if len(c) == 32), None)
    client_secret = next((c for c in codes if len(c) == 64), None)

    check('client_id found on edit page',     client_id     is not None, f'codes: {codes}')
    check('client_secret found on edit page', client_secret is not None, f'codes: {codes}')

    if not client_id or not client_secret:
        abort('could not extract client credentials from admin edit page')

    return client_id, client_secret


def step_sign_in(s):
    section('4. Sign in as test user')
    r = s.post(f'{BASE_URL}/signuserin', data={
        'email':    USER_EMAIL,
        'password': USER_PASSWORD,
    }, allow_redirects=True)
    ok = check('Redirected to /profile', r.url.endswith('/profile'))
    if not ok:
        abort('sign-in failed — cannot continue')

    # Application should be visible read-only (no Add / Edit buttons)
    profile = s.get(f'{BASE_URL}/profile')
    check('App visible on profile (read-only)', APP_NAME in profile.text)
    check('No Add button on profile',           'Add New Application' not in profile.text)
    check('No Edit button on profile',          'edit_application' not in profile.text)


def step_authorization_code_flow(s, client_id, client_secret):
    section('5. Authorization Code flow (openid profile email)')

    # 5a — consent screen
    r = s.get(f'{BASE_URL}/oauth/authorize', params={
        'client_id':     client_id,
        'redirect_uri':  REDIRECT_URI,
        'response_type': 'code',
        'scope':         'openid profile email',
        'state':         'test-state-xyz',
        'nonce':         'test-nonce-abc',
    })
    check('Consent screen shown (200)',   r.status_code == 200)
    check('Approve button present',       'approve' in r.text.lower())

    # 5b — user approves
    r = s.post(f'{BASE_URL}/oauth/authorize', data={
        'client_id':    client_id,
        'redirect_uri': REDIRECT_URI,
        'scope':        'openid profile email',
        'state':        'test-state-xyz',
        'nonce':        'test-nonce-abc',
        'approved':     '1',
    }, allow_redirects=False)
    check('Approve redirects (302)',        r.status_code == 302)
    check('Redirect targets redirect_uri', r.headers.get('Location', '').startswith(REDIRECT_URI))

    location = r.headers.get('Location', '')
    qs        = parse_qs(urlparse(location).query)
    code      = qs.get('code',  [None])[0]
    state     = qs.get('state', [None])[0]

    check('Authorization code present', code  is not None, f'Location: {location}')
    check('State preserved',            state == 'test-state-xyz')

    if not code:
        abort('no authorization code — cannot continue')

    # 5c — exchange code for tokens
    r = requests.post(f'{BASE_URL}/oauth/token', data={
        'grant_type':    'authorization_code',
        'code':          code,
        'redirect_uri':  REDIRECT_URI,
        'client_id':     client_id,
        'client_secret': client_secret,
    })
    ok = check('Token exchange returns 200', r.status_code == 200,
               f'status={r.status_code} body={r.text[:300]}')
    if not ok:
        abort(f'token exchange failed (status={r.status_code}): {r.text[:300]}')
    td = r.json()
    check('access_token present',  'access_token'  in td)
    check('refresh_token present', 'refresh_token' in td)
    check('id_token present',      'id_token'      in td)
    check('token_type is Bearer',  td.get('token_type') == 'Bearer')
    check('expires_in present',    'expires_in'    in td)
    check('scope contains openid', 'openid' in td.get('scope', ''))

    # 5d — code cannot be reused (single-use)
    r2 = requests.post(f'{BASE_URL}/oauth/token', data={
        'grant_type':    'authorization_code',
        'code':          code,
        'redirect_uri':  REDIRECT_URI,
        'client_id':     client_id,
        'client_secret': client_secret,
    })
    check('Reusing code returns 400 (single-use)', r2.status_code == 400)
    check('Error is invalid_grant',                r2.json().get('error') == 'invalid_grant')

    return td.get('access_token'), td.get('refresh_token')


def step_userinfo(access_token):
    section('6. Userinfo endpoint')
    r = requests.get(f'{BASE_URL}/oauth/userinfo', headers={
        'Authorization': f'Bearer {access_token}'
    })
    check('Returns 200',           r.status_code == 200)
    d = r.json()
    check('sub present',           'sub'         in d)
    check('given_name present',    'given_name'  in d)
    check('family_name present',   'family_name' in d)
    check('email correct',         d.get('email') == USER_EMAIL)


def step_refresh_token(client_id, client_secret, refresh_token):
    section('7. Refresh token grant')

    r = requests.post(f'{BASE_URL}/oauth/token', data={
        'grant_type':    'refresh_token',
        'refresh_token': refresh_token,
        'client_id':     client_id,
        'client_secret': client_secret,
    })
    check('Refresh returns 200',       r.status_code == 200)
    d = r.json()
    check('New access_token issued',   'access_token'  in d)
    check('New refresh_token issued',  'refresh_token' in d)

    # Old refresh token must be rejected after rotation
    r2 = requests.post(f'{BASE_URL}/oauth/token', data={
        'grant_type':    'refresh_token',
        'refresh_token': refresh_token,
        'client_id':     client_id,
        'client_secret': client_secret,
    })
    check('Old refresh_token rejected after rotation (400)', r2.status_code == 400)
    check('Error is invalid_grant', r2.json().get('error') == 'invalid_grant')

    return d.get('access_token'), d.get('refresh_token')


def step_introspection(client_id, client_secret, access_token):
    section('8. Token introspection (RFC 7662)')
    r = requests.post(f'{BASE_URL}/oauth/introspect', data={
        'token':         access_token,
        'client_id':     client_id,
        'client_secret': client_secret,
    })
    check('Returns 200',       r.status_code == 200)
    d = r.json()
    check('active is True',    d.get('active') is True)
    check('scope present',     'scope'     in d)
    check('client_id present', 'client_id' in d)
    check('username present',  'username'  in d)
    check('exp present',       'exp'       in d)
    check('sub present',       'sub'       in d)


def step_revocation(client_id, client_secret, access_token):
    section('9. Token revocation (RFC 7009)')
    r = requests.post(f'{BASE_URL}/oauth/revoke', data={
        'token':         access_token,
        'client_id':     client_id,
        'client_secret': client_secret,
    })
    check('Revoke returns 200', r.status_code == 200)

    r2 = requests.get(f'{BASE_URL}/oauth/userinfo',
                      headers={'Authorization': f'Bearer {access_token}'})
    check('Revoked token rejected at userinfo (401)', r2.status_code == 401)

    r3 = requests.post(f'{BASE_URL}/oauth/introspect', data={
        'token':         access_token,
        'client_id':     client_id,
        'client_secret': client_secret,
    })
    check('Introspect shows active=False after revoke', r3.json().get('active') is False)

    r4 = requests.post(f'{BASE_URL}/oauth/revoke', data={
        'token':         access_token,
        'client_id':     client_id,
        'client_secret': client_secret,
    })
    check('Revoking again is idempotent (200)', r4.status_code == 200)


def step_pkce_flow(s, client_id, client_secret):
    section('10. PKCE — Proof Key for Code Exchange (RFC 7636)')

    # ── Generate a code_verifier and derive the S256 code_challenge ───────────
    #
    # code_verifier  = cryptographically random URL-safe string (43-128 chars)
    # code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))
    #
    # Using only stdlib: secrets for randomness, hashlib for SHA-256,
    # base64 for encoding — no external library.

    code_verifier  = secrets.token_urlsafe(32)   # 43 URL-safe chars
    digest         = hashlib.sha256(code_verifier.encode('ascii')).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')
    wrong_verifier = secrets.token_urlsafe(32)   # different random value

    # ── Get an authorisation code with the PKCE challenge ────────────────────
    s.get(f'{BASE_URL}/oauth/authorize', params={
        'client_id':             client_id,
        'redirect_uri':          REDIRECT_URI,
        'response_type':         'code',
        'scope':                 'profile',
        'state':                 'pkce-state',
        'code_challenge':        code_challenge,
        'code_challenge_method': 'S256',
    })
    r = s.post(f'{BASE_URL}/oauth/authorize', data={
        'client_id':             client_id,
        'redirect_uri':          REDIRECT_URI,
        'scope':                 'profile',
        'state':                 'pkce-state',
        'code_challenge':        code_challenge,
        'code_challenge_method': 'S256',
        'approved':              '1',
    }, allow_redirects=False)
    qs   = parse_qs(urlparse(r.headers.get('Location', '')).query)
    code = qs.get('code', [None])[0]
    check('Authorization code issued with PKCE challenge', code is not None)
    if not code:
        abort('no PKCE authorization code — cannot continue')

    def token_exchange(**extra):
        return requests.post(f'{BASE_URL}/oauth/token', data={
            'grant_type':    'authorization_code',
            'code':          code,
            'redirect_uri':  REDIRECT_URI,
            'client_id':     client_id,
            'client_secret': client_secret,
            **extra,
        })

    # ── Wrong verifier must be rejected ──────────────────────────────────────
    r = token_exchange(code_verifier=wrong_verifier)
    check('Wrong code_verifier → 400',         r.status_code == 400)
    check('Error is invalid_grant',            r.json().get('error') == 'invalid_grant')
    check('Mismatch described in response',    'match' in r.json().get('error_description', ''))

    # ── Missing verifier must be rejected ────────────────────────────────────
    r = token_exchange()   # no code_verifier
    check('Missing code_verifier → 400',       r.status_code == 400)
    check('Error is invalid_grant',            r.json().get('error') == 'invalid_grant')
    check('Required described in response',    'required' in r.json().get('error_description', ''))

    # ── Correct verifier must succeed ─────────────────────────────────────────
    r = token_exchange(code_verifier=code_verifier)
    ok = check('Correct code_verifier → 200',  r.status_code == 200,
               f'body={r.text[:200]}')
    if ok:
        td = r.json()
        check('access_token present',          'access_token' in td)
        check('refresh_token present',         'refresh_token' in td)

    # ── verifier sent when no challenge was registered must be rejected ───────
    # Get a plain (non-PKCE) code first
    s.get(f'{BASE_URL}/oauth/authorize', params={
        'client_id': client_id, 'redirect_uri': REDIRECT_URI,
        'response_type': 'code', 'scope': 'profile', 'state': 's2',
    })
    r2 = s.post(f'{BASE_URL}/oauth/authorize', data={
        'client_id': client_id, 'redirect_uri': REDIRECT_URI,
        'scope': 'profile', 'state': 's2', 'approved': '1',
    }, allow_redirects=False)
    plain_code = parse_qs(urlparse(r2.headers.get('Location', '')).query).get('code', [None])[0]
    if plain_code:
        r3 = requests.post(f'{BASE_URL}/oauth/token', data={
            'grant_type': 'authorization_code', 'code': plain_code,
            'redirect_uri': REDIRECT_URI,
            'client_id': client_id, 'client_secret': client_secret,
            'code_verifier': code_verifier,   # unexpected — no challenge registered
        })
        check('Unexpected code_verifier on non-PKCE code → 400', r3.status_code == 400)
        check('Error is invalid_request', r3.json().get('error') == 'invalid_request')


def step_error_cases(client_id, client_secret):
    section('11. Error cases')

    # Wrong client secret
    r = requests.post(f'{BASE_URL}/oauth/token', data={
        'grant_type':    'authorization_code',
        'code':          'fake-code',
        'redirect_uri':  REDIRECT_URI,
        'client_id':     client_id,
        'client_secret': 'wrong-secret',
    })
    check('Wrong client_secret → 401',      r.status_code == 401)
    check('WWW-Authenticate header on 401', 'WWW-Authenticate' in r.headers)
    check('Error is invalid_client',        r.json().get('error') == 'invalid_client')

    # HTTP Basic Auth (RFC 6749 §2.3.1)
    creds = base64.b64encode(f'{client_id}:{client_secret}'.encode()).decode()
    r = requests.post(f'{BASE_URL}/oauth/token',
                      data={'grant_type': 'refresh_token', 'refresh_token': 'fake'},
                      headers={'Authorization': f'Basic {creds}'})
    check('Basic Auth accepted (400 not 401)', r.status_code == 400)  # invalid_grant, not invalid_client

    # Unsupported grant type
    r = requests.post(f'{BASE_URL}/oauth/token', data={
        'grant_type':    'client_credentials',
        'client_id':     client_id,
        'client_secret': client_secret,
    })
    check('Unsupported grant type → 400',    r.status_code == 400)
    check('Error is unsupported_grant_type', r.json().get('error') == 'unsupported_grant_type')

    # Invalid scope — checked before login, so no auth needed
    r = requests.get(f'{BASE_URL}/oauth/authorize', params={
        'client_id':     client_id,
        'redirect_uri':  REDIRECT_URI,
        'response_type': 'code',
        'scope':         'admin',
        'state':         'xyz',
    }, allow_redirects=False)
    check('Invalid scope → 302',                   r.status_code == 302)
    check('Redirect contains error=invalid_scope', 'invalid_scope' in r.headers.get('Location', ''))

    # Unsupported response_type (implicit — not supported)
    r = requests.get(f'{BASE_URL}/oauth/authorize', params={
        'client_id':     client_id,
        'redirect_uri':  REDIRECT_URI,
        'response_type': 'token',
        'state':         'xyz',
    }, allow_redirects=False)
    check('Unsupported response_type → 302', r.status_code == 302)
    check('Redirect contains error=unsupported_response_type',
          'unsupported_response_type' in r.headers.get('Location', ''))

    # Missing Bearer token
    r = requests.get(f'{BASE_URL}/oauth/userinfo')
    check('Missing Bearer → 401',              r.status_code == 401)
    check('WWW-Authenticate on missing token', 'WWW-Authenticate' in r.headers)

    # Invalid Bearer token
    r = requests.get(f'{BASE_URL}/oauth/userinfo',
                     headers={'Authorization': 'Bearer definitely-not-a-valid-token'})
    check('Invalid Bearer → 401', r.status_code == 401)

    # Invalid client at introspect
    r = requests.post(f'{BASE_URL}/oauth/introspect', data={
        'token': 'anything', 'client_id': client_id, 'client_secret': 'wrong',
    })
    check('Bad client at introspect → 401', r.status_code == 401)

    # Invalid client at revoke
    r = requests.post(f'{BASE_URL}/oauth/revoke', data={
        'token': 'anything', 'client_id': client_id, 'client_secret': 'wrong',
    })
    check('Bad client at revoke → 401', r.status_code == 401)


# ── Main ─────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print(f'Toy OAuth Server — end-to-end test')
    print(f'Base URL   : {BASE_URL}')
    print(f'Test user  : {USER_EMAIL}')
    print(f'Admin user : {ADMIN_EMAIL}')

    try:
        requests.get(BASE_URL, timeout=3)
    except requests.exceptions.ConnectionError:
        print(f'\nERROR: Cannot reach {BASE_URL}. Is the server running?\n')
        sys.exit(1)

    s       = requests.Session()   # test user session
    admin_s = requests.Session()   # admin session

    step_register_user(s)
    step_setup_admin(admin_s)
    client_id, client_secret = step_register_app(admin_s)

    step_sign_in(s)

    access_token, refresh_token = step_authorization_code_flow(s, client_id, client_secret)
    if not access_token:
        abort('authorization code flow produced no access token')

    step_userinfo(access_token)

    new_access, new_refresh = step_refresh_token(client_id, client_secret, refresh_token)

    step_introspection(client_id, client_secret, new_access)
    step_revocation(client_id, client_secret, new_access)
    step_pkce_flow(s, client_id, client_secret)
    step_error_cases(client_id, client_secret)

    _summary()
    sys.exit(0 if _failed == 0 else 1)
