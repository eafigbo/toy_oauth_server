#!/usr/bin/env python3
"""
End-to-end test script for the Toy OAuth Server.

Covers:
  - User registration and sign-in
  - OAuth application registration
  - Authorization Code flow (RFC 6749 §4.1)
  - Refresh token grant (RFC 6749 §6)
  - Token introspection (RFC 7662)
  - Token revocation (RFC 7009)
  - Error cases

Usage:
    pip install requests
    python3 test_oauth_flow.py

The server must be running first:
    ./toy_oauth_server/run_app.sh
"""

import re
import sys
import secrets
import requests
from urllib.parse import urlparse, parse_qs

BASE_URL     = 'http://localhost:5000'
REDIRECT_URI = 'http://localhost:9999/callback'   # dummy — we capture the code from the Location header

# Unique credentials per run so tests are always independent
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
    section('1. Register user')
    r = s.post(f'{BASE_URL}/registeruser', data={
        'first_name': 'Test',
        'last_name':  'User',
        'email':       USER_EMAIL,
        'home_address': '1 Test Street',
        'password':    USER_PASSWORD,
    })
    check('Returns 200',          r.status_code == 200)
    check('Success page rendered', 'registered' in r.text.lower() or 'test user' in r.text.lower())


def step_sign_in(s):
    section('2. Sign in')
    r = s.post(f'{BASE_URL}/signuserin', data={
        'email':    USER_EMAIL,
        'password': USER_PASSWORD,
    }, allow_redirects=True)
    ok = check('Redirected to /profile', r.url.endswith('/profile'))
    if not ok:
        abort('sign-in failed — cannot continue')


def step_register_app(s):
    section('3. Register OAuth application')
    r = s.post(f'{BASE_URL}/save_application', data={
        'application_name': APP_NAME,
        'description':      'OAuth test application',
        'redirect_url':     REDIRECT_URI,
        'icon_url':         '',
        'home_page_url':    '',
        'privacy_policy_url': '',
    }, allow_redirects=True)
    check('Redirected to /profile after save', r.url.endswith('/profile'))

    # Read credentials from the profile page HTML
    profile = s.get(f'{BASE_URL}/profile')
    check('Profile page loads', profile.status_code == 200)

    codes = re.findall(r'<code>([^<]+)</code>', profile.text)
    # client_id  = token_hex(16) = 32 hex chars
    # client_secret = token_hex(32) = 64 hex chars
    client_id     = next((c for c in codes if len(c) == 32), None)
    client_secret = next((c for c in codes if len(c) == 64), None)

    check('client_id found',     client_id     is not None, f'codes on page: {codes}')
    check('client_secret found', client_secret is not None, f'codes on page: {codes}')

    if not client_id or not client_secret:
        abort('could not extract client credentials from profile page')

    return client_id, client_secret


def step_authorization_code_flow(s, client_id, client_secret):
    section('4. Authorization Code flow')

    # 4a — consent screen
    r = s.get(f'{BASE_URL}/oauth/authorize', params={
        'client_id':     client_id,
        'redirect_uri':  REDIRECT_URI,
        'response_type': 'code',
        'scope':         'profile',
        'state':         'test-state-xyz',
    })
    check('Consent screen shown (200)',   r.status_code == 200)
    check('Approve button present',       'approve' in r.text.lower())

    # 4b — user approves
    r = s.post(f'{BASE_URL}/oauth/authorize', data={
        'client_id':    client_id,
        'redirect_uri': REDIRECT_URI,
        'scope':        'profile',
        'state':        'test-state-xyz',
        'approved':     '1',
    }, allow_redirects=False)
    check('Approve redirects (302)',            r.status_code == 302)
    check('Redirect targets redirect_uri',      r.headers.get('Location', '').startswith(REDIRECT_URI))

    location = r.headers.get('Location', '')
    qs        = parse_qs(urlparse(location).query)
    code      = qs.get('code',  [None])[0]
    state     = qs.get('state', [None])[0]

    check('Authorization code present', code  is not None, f'Location: {location}')
    check('State preserved',            state == 'test-state-xyz')

    if not code:
        abort('no authorization code — cannot continue')

    # 4c — exchange code for tokens
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
    check('access_token present',        'access_token'  in td)
    check('refresh_token present',       'refresh_token' in td)
    check('token_type is Bearer',        td.get('token_type') == 'Bearer')
    check('expires_in present',          'expires_in'    in td)
    check('scope is profile',            td.get('scope') == 'profile')

    # 4d — code cannot be reused (single-use)
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
    section('5. Userinfo endpoint')
    r = requests.get(f'{BASE_URL}/oauth/userinfo', headers={
        'Authorization': f'Bearer {access_token}'
    })
    check('Returns 200',        r.status_code == 200)
    d = r.json()
    check('email correct',      d.get('email') == USER_EMAIL)
    check('first_name present', 'first_name' in d)
    check('last_name present',  'last_name'  in d)
    check('id present',         'id'         in d)


def step_refresh_token(client_id, client_secret, refresh_token):
    section('6. Refresh token grant')

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
    section('7. Token introspection (RFC 7662)')
    r = requests.post(f'{BASE_URL}/oauth/introspect', data={
        'token':         access_token,
        'client_id':     client_id,
        'client_secret': client_secret,
    })
    check('Returns 200',         r.status_code == 200)
    d = r.json()
    check('active is True',      d.get('active') is True)
    check('scope present',       'scope'     in d)
    check('client_id present',   'client_id' in d)
    check('username present',    'username'  in d)
    check('exp present',         'exp'       in d)
    check('sub present',         'sub'       in d)


def step_revocation(client_id, client_secret, access_token):
    section('8. Token revocation (RFC 7009)')
    r = requests.post(f'{BASE_URL}/oauth/revoke', data={
        'token':         access_token,
        'client_id':     client_id,
        'client_secret': client_secret,
    })
    check('Revoke returns 200', r.status_code == 200)

    # Token must now be inactive
    r2 = requests.get(f'{BASE_URL}/oauth/userinfo',
                      headers={'Authorization': f'Bearer {access_token}'})
    check('Revoked token rejected at userinfo (401)', r2.status_code == 401)

    r3 = requests.post(f'{BASE_URL}/oauth/introspect', data={
        'token':         access_token,
        'client_id':     client_id,
        'client_secret': client_secret,
    })
    check('Introspect shows active=False after revoke', r3.json().get('active') is False)

    # Revoking an already-revoked token must still return 200
    r4 = requests.post(f'{BASE_URL}/oauth/revoke', data={
        'token':         access_token,
        'client_id':     client_id,
        'client_secret': client_secret,
    })
    check('Revoking again is idempotent (200)', r4.status_code == 200)


def step_error_cases(s, client_id, client_secret):
    section('9. Error cases')

    # Wrong client secret
    r = requests.post(f'{BASE_URL}/oauth/token', data={
        'grant_type':    'authorization_code',
        'code':          'fake-code',
        'redirect_uri':  REDIRECT_URI,
        'client_id':     client_id,
        'client_secret': 'wrong-secret',
    })
    check('Wrong client_secret → 401',           r.status_code == 401)
    check('WWW-Authenticate header on 401',       'WWW-Authenticate' in r.headers)
    check('Error is invalid_client',              r.json().get('error') == 'invalid_client')

    # HTTP Basic Auth (RFC 6749 §2.3.1)
    import base64
    creds = base64.b64encode(f'{client_id}:{client_secret}'.encode()).decode()
    r = requests.post(f'{BASE_URL}/oauth/token',
                      data={'grant_type': 'refresh_token', 'refresh_token': 'fake'},
                      headers={'Authorization': f'Basic {creds}'})
    check('Basic Auth accepted (400 not 401)',    r.status_code == 400)   # invalid_grant, not invalid_client

    # Unsupported grant type
    r = requests.post(f'{BASE_URL}/oauth/token', data={
        'grant_type':    'client_credentials',
        'client_id':     client_id,
        'client_secret': client_secret,
    })
    check('Unsupported grant type → 400',         r.status_code == 400)
    check('Error is unsupported_grant_type',      r.json().get('error') == 'unsupported_grant_type')

    # Invalid scope — scope check happens before login check, so no auth needed
    r = requests.get(f'{BASE_URL}/oauth/authorize', params={
        'client_id':     client_id,
        'redirect_uri':  REDIRECT_URI,
        'response_type': 'code',
        'scope':         'admin',
        'state':         'xyz',
    }, allow_redirects=False)
    check('Invalid scope → 302',                  r.status_code == 302)
    check('Redirect contains error=invalid_scope','invalid_scope' in r.headers.get('Location', ''))

    # Unsupported response_type
    r = requests.get(f'{BASE_URL}/oauth/authorize', params={
        'client_id':     client_id,
        'redirect_uri':  REDIRECT_URI,
        'response_type': 'token',   # implicit — not supported
        'state':         'xyz',
    }, allow_redirects=False)
    check('Unsupported response_type → 302',      r.status_code == 302)
    check('Redirect contains error=unsupported_response_type',
          'unsupported_response_type' in r.headers.get('Location', ''))

    # Missing Bearer token
    r = requests.get(f'{BASE_URL}/oauth/userinfo')
    check('Missing Bearer → 401',                 r.status_code == 401)
    check('WWW-Authenticate on missing token',     'WWW-Authenticate' in r.headers)

    # Invalid Bearer token
    r = requests.get(f'{BASE_URL}/oauth/userinfo',
                     headers={'Authorization': 'Bearer definitely-not-a-valid-token'})
    check('Invalid Bearer → 401',                 r.status_code == 401)

    # Invalid client at introspect
    r = requests.post(f'{BASE_URL}/oauth/introspect', data={
        'token':         'anything',
        'client_id':     client_id,
        'client_secret': 'wrong',
    })
    check('Bad client at introspect → 401',       r.status_code == 401)

    # Invalid client at revoke
    r = requests.post(f'{BASE_URL}/oauth/revoke', data={
        'token':         'anything',
        'client_id':     client_id,
        'client_secret': 'wrong',
    })
    check('Bad client at revoke → 401',           r.status_code == 401)


# ── Main ─────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print(f'Toy OAuth Server — end-to-end test')
    print(f'Base URL  : {BASE_URL}')
    print(f'Test user : {USER_EMAIL}')

    try:
        requests.get(BASE_URL, timeout=3)
    except requests.exceptions.ConnectionError:
        print(f'\nERROR: Cannot reach {BASE_URL}. Is the server running?\n')
        sys.exit(1)

    s = requests.Session()

    step_register_user(s)
    step_sign_in(s)
    client_id, client_secret = step_register_app(s)

    access_token, refresh_token = step_authorization_code_flow(s, client_id, client_secret)
    if not access_token:
        abort('authorization code flow produced no access token')

    step_userinfo(access_token)

    new_access, new_refresh = step_refresh_token(client_id, client_secret, refresh_token)

    step_introspection(client_id, client_secret, new_access)
    step_revocation(client_id, client_secret, new_access)
    step_error_cases(s, client_id, client_secret)

    _summary()
    sys.exit(0 if _failed == 0 else 1)
