#!/usr/bin/env python3
"""
Test Resource Authorization Server  —  port 5002

Accepts ID-JAGs issued by the IdP and exchanges them for its own access tokens,
which can then be used to call the protected /resource endpoint.

This app demonstrates the Resource AS side of the ID-JAG flow:
  - Fetches the IdP's public key from its JWKS endpoint
  - Reconstructs the RSA public key from the JWK n and e components
    (inverse of jwt_utils.public_key_to_jwk())
  - Verifies the ID-JAG signature, expiry, issuer, and audience
  - Enforces jti uniqueness to prevent replay attacks
  - Issues its own opaque access token

Configuration:
  Edit test_apps/config.py — CONFIG['resource_as'] dict.

Startup:
  python3 test_apps/resource_as.py
"""

import os
import json
import base64
import secrets
import time
import importlib.util

import requests as http_client
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.backends import default_backend

# ── Configuration ─────────────────────────────────────────────────────────────

_spec = importlib.util.spec_from_file_location(
    '_config', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.py')
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
_c = _mod.CONFIG.get('resource_as', {})

IDP_URL         = _c.get('idp_url',         'http://localhost:5000')
RESOURCE_AS_URI = _c.get('resource_as_uri', 'http://localhost:5002')

app = Flask(__name__)

# ── In-memory stores (reset on restart — this is a test app) ──────────────────

_issued_tokens   = {}    # access_token  →  token metadata dict
_used_jtis       = set() # jti values already redeemed (replay protection)

# ── JWKS cache ────────────────────────────────────────────────────────────────

_public_keys     = {}    # kid → RSA public key object
_keys_fetched_at = 0.0   # Unix timestamp of last successful fetch


# ── Key utilities ─────────────────────────────────────────────────────────────

def _b64url_decode(s):
    """Decode a base64url string (with or without padding) to bytes."""
    pad = (4 - len(s) % 4) % 4
    return base64.urlsafe_b64decode(s + '=' * pad)


def _b64url_to_int(s):
    """
    Convert a base64url-encoded big-endian integer to a Python int.
    Used for the RSA modulus (n) and exponent (e) from a JWK.
    This is the inverse of jwt_utils._int_to_base64url().
    """
    return int.from_bytes(_b64url_decode(s), byteorder='big')


def _jwk_to_public_key(jwk):
    """
    Reconstruct an RSA public key object from a JWK dict.

    A JWK for RSA contains:
      n  — the modulus   (base64url big-endian integer)
      e  — the exponent  (base64url big-endian integer, almost always 65537)

    RSAPublicNumbers(e, n) builds the key from these two values.
    This is the exact inverse of jwt_utils.public_key_to_jwk().
    """
    n = _b64url_to_int(jwk['n'])
    e = _b64url_to_int(jwk['e'])
    return RSAPublicNumbers(e, n).public_key(default_backend())


def _fetch_public_keys(force=False):
    """
    Fetch and cache the IdP's public keys from its JWKS endpoint.

    The JWKS is cached for one hour (matching the Cache-Control header the IdP
    sets on /.well-known/jwks.json).  Pass force=True to bypass the cache —
    used when an incoming token references a kid we haven't seen before,
    which may indicate a key rotation.
    """
    global _public_keys, _keys_fetched_at

    if not force and _public_keys and time.time() - _keys_fetched_at < 3600:
        return _public_keys

    resp = http_client.get(f'{IDP_URL}/.well-known/jwks.json', timeout=5)
    resp.raise_for_status()
    jwks = resp.json()

    _public_keys     = {k['kid']: _jwk_to_public_key(k) for k in jwks['keys']}
    _keys_fetched_at = time.time()
    return _public_keys


# ── ID-JAG verification ───────────────────────────────────────────────────────

def _verify_id_jag(token):
    """
    Verify an incoming ID-JAG JWT.

    Steps:
      1. Parse the header to get the key ID (kid).
      2. Fetch (or cache-hit) the matching RSA public key from the IdP's JWKS.
      3. Verify the RSA-PKCS1v15-SHA256 signature.
      4. Decode the payload claims.
      5. Validate exp, iss, aud.
      6. Enforce jti uniqueness — reject replay attacks.

    Returns the claims dict on success.
    Raises ValueError with a descriptive message on any failure.
    """
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError('Malformed JWT: expected 3 dot-separated segments')

    header_b64, payload_b64, sig_b64 = parts

    # Step 1 — decode header
    try:
        header = json.loads(_b64url_decode(header_b64))
    except Exception:
        raise ValueError('Cannot decode JWT header')

    if header.get('alg') != 'RS256':
        raise ValueError(f'Unsupported algorithm: {header.get("alg")!r}')

    kid = header.get('kid', '')

    # Step 2 — fetch the matching public key
    public_keys = _fetch_public_keys()
    if kid not in public_keys:
        # May be a key rotation — retry once with a forced JWKS refresh
        public_keys = _fetch_public_keys(force=True)
    if kid not in public_keys:
        raise ValueError(f'No public key found for kid {kid!r}')

    # Step 3 — verify signature
    # The signed data is exactly the bytes of "header_b64.payload_b64"
    signing_input = f'{header_b64}.{payload_b64}'.encode('ascii')
    signature     = _b64url_decode(sig_b64)
    try:
        public_keys[kid].verify(signature, signing_input,
                                padding.PKCS1v15(), hashes.SHA256())
    except Exception:
        raise ValueError('JWT signature verification failed')

    # Step 4 — decode payload
    try:
        claims = json.loads(_b64url_decode(payload_b64))
    except Exception:
        raise ValueError('Cannot decode JWT payload')

    now = int(time.time())

    # Step 5a — expiry
    if claims.get('exp', 0) < now:
        raise ValueError('ID-JAG has expired')

    # Step 5b — issuer must be our trusted IdP
    if claims.get('iss') != IDP_URL:
        raise ValueError(
            f'Unexpected issuer {claims.get("iss")!r} (expected {IDP_URL!r})'
        )

    # Step 5c — audience must be this Resource AS
    # This prevents a JAG issued for a different RAS from being replayed here
    if claims.get('aud') != RESOURCE_AS_URI:
        raise ValueError(
            f'Unexpected audience {claims.get("aud")!r} (expected {RESOURCE_AS_URI!r})'
        )

    # Step 6 — jti replay protection
    jti = claims.get('jti')
    if not jti:
        raise ValueError('Missing jti claim — replay protection requires a unique token ID')
    if jti in _used_jtis:
        raise ValueError(f'Replay detected: jti {jti!r} has already been redeemed')
    _used_jtis.add(jti)

    return claims


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.route('/token', methods=['POST'])
def token():
    """
    Token endpoint — accepts an ID-JAG and issues a resource access token.

    Per ID-JAG draft §4.4, the client MUST use the JWT Bearer grant (RFC 7523):
      grant_type   urn:ietf:params:oauth:grant-type:jwt-bearer  (required)
      assertion    the ID-JAG JWT                                (required)
    """
    grant_type = request.form.get('grant_type')

    if grant_type != 'urn:ietf:params:oauth:grant-type:jwt-bearer':
        return jsonify(error='unsupported_grant_type',
                       error_description='grant_type must be urn:ietf:params:oauth:grant-type:jwt-bearer'), 400

    assertion = request.form.get('assertion')
    if not assertion:
        return jsonify(error='invalid_request',
                       error_description='"assertion" parameter is required'), 400

    try:
        claims = _verify_id_jag(assertion)
    except ValueError as exc:
        return jsonify(error='invalid_grant', error_description=str(exc)), 401

    # Issue an opaque resource access token
    access_token = secrets.token_urlsafe(32)
    _issued_tokens[access_token] = {
        'sub':        claims['sub'],
        'client_id':  claims.get('client_id'),
        'scope':      claims.get('scope', 'profile'),
        'expires_at': int(time.time()) + 3600,
    }

    return jsonify(
        access_token=access_token,
        token_type='Bearer',
        expires_in=3600,
        sub=claims['sub'],
        scope=claims.get('scope', 'profile'),
    )


@app.route('/resource')
def resource():
    """
    Protected resource endpoint.
    Requires a valid Bearer token issued by this server's /token endpoint.
    """
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return jsonify(error='unauthorized'), 401, \
               {'WWW-Authenticate': f'Bearer realm="{RESOURCE_AS_URI}"'}

    token_value = auth[len('Bearer '):]
    token_data  = _issued_tokens.get(token_value)

    if not token_data:
        return jsonify(error='invalid_token',
                       error_description='token not found'), 401

    if token_data['expires_at'] < int(time.time()):
        return jsonify(error='invalid_token',
                       error_description='token has expired'), 401

    return jsonify(
        message='Access granted to protected resource.',
        sub=token_data['sub'],
        client_id=token_data['client_id'],
        scope=token_data['scope'],
        resource_data={
            'server': RESOURCE_AS_URI,
            'items':  ['item-alpha', 'item-beta', 'item-gamma'],
        },
    )


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print(f'Resource AS running at {RESOURCE_AS_URI}')
    print(f'Trusting IdP at:       {IDP_URL}')
    print(f'JWKS endpoint:         {IDP_URL}/.well-known/jwks.json')
    app.run(port=5002, debug=True)
