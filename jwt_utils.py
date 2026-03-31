"""
JWT utilities — first-principles implementation.

A JWT has three parts, each base64url-encoded and joined by dots:

    base64url(header) + "." + base64url(payload) + "." + base64url(signature)

Header  — JSON object describing the token type and signing algorithm.
Payload — JSON object containing the claims (the actual data).
Signature — RSA-PKCS1v15(SHA-256(header_b64 + "." + payload_b64))

This module implements the encoding, signing, and verification from scratch
using only the Python standard library plus the `cryptography` package for the
RSA primitive (key generation and sign/verify operations — the one step that
cannot be done safely without a vetted library).
"""

import os
import json
import base64
import hashlib
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


# ── Base64url encoding / decoding ─────────────────────────────────────────────
#
# Standard base64 uses '+' and '/' and pads with '='.
# Base64url substitutes '-' for '+' and '_' for '/' and drops padding.
# Python's base64.urlsafe_b64encode handles the character substitution;
# we strip padding on encode and restore it on decode.

def base64url_encode(data):
    """Encode bytes (or a str) to an unpadded base64url ASCII string."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def base64url_decode(s):
    """Decode an unpadded base64url string to bytes."""
    # base64 requires the input length to be a multiple of 4.
    # (4 - n % 4) % 4 gives the number of '=' characters needed.
    padding = (4 - len(s) % 4) % 4
    return base64.urlsafe_b64decode(s + '=' * padding)


# ── JWT creation ──────────────────────────────────────────────────────────────

def create_jwt(payload, private_key, kid):
    """
    Build and sign a JWT.

    Steps:
      1. Encode the fixed header (alg=RS256, typ=JWT) as base64url JSON.
      2. Encode the caller-supplied payload dict as base64url JSON.
      3. Form the signing input:  header_b64 + "." + payload_b64
      4. Sign with RSA-PKCS1v15 + SHA-256 (the only non-stdlib call).
      5. Append the base64url-encoded signature as the third segment.

    Returns the complete JWT string.
    """
    header = {'alg': 'RS256', 'typ': 'JWT', 'kid': kid}

    header_b64  = base64url_encode(json.dumps(header,  separators=(',', ':')))
    payload_b64 = base64url_encode(json.dumps(payload, separators=(',', ':')))

    # The data fed to the RSA function is the ASCII bytes of "header.payload".
    signing_input = f'{header_b64}.{payload_b64}'.encode('ascii')

    # RSA-PKCS1v15 with SHA-256 — the single call that requires the
    # cryptography library.  Everything else in this function is plain Python.
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())

    return f'{header_b64}.{payload_b64}.{base64url_encode(signature)}'


# ── JWT verification ──────────────────────────────────────────────────────────

def verify_jwt(token, public_key):
    """
    Verify a JWT's signature and expiry.

    Steps:
      1. Split on '.' — a valid JWT always has exactly three segments.
      2. Decode the header; confirm alg == RS256.
      3. Reconstruct the signing input from the first two segments.
      4. Decode and verify the signature with the RSA public key.
      5. Decode the payload JSON.
      6. Check the 'exp' claim against the current UTC time.

    Returns the payload claims dict on success.
    Raises ValueError with a descriptive message on any failure.
    """
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError('Malformed JWT: expected exactly 3 dot-separated segments')

    header_b64, payload_b64, signature_b64 = parts

    # Step 2 — decode and inspect the header
    try:
        header = json.loads(base64url_decode(header_b64))
    except Exception:
        raise ValueError('Malformed JWT: cannot decode header')

    if header.get('alg') != 'RS256':
        raise ValueError(f'Unsupported signing algorithm: {header.get("alg")!r}')

    # Step 3 — signing input is exactly the bytes that were signed
    signing_input = f'{header_b64}.{payload_b64}'.encode('ascii')

    # Step 4 — RSA signature verification (raises if invalid)
    try:
        signature = base64url_decode(signature_b64)
        public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
    except Exception:
        raise ValueError('JWT signature verification failed')

    # Step 5 — decode payload
    try:
        claims = json.loads(base64url_decode(payload_b64))
    except Exception:
        raise ValueError('Malformed JWT: cannot decode payload')

    # Step 6 — check expiry using a plain integer comparison
    # time.time() returns seconds since the Unix epoch (UTC), same unit as JWT exp.
    if claims.get('exp', 0) < int(time.time()):
        raise ValueError('JWT has expired')

    return claims


# ── JWK export ────────────────────────────────────────────────────────────────
#
# A JSON Web Key (JWK) for RSA contains the public key components:
#   n — the modulus  (product of the two private primes)
#   e — the exponent (almost always 65537)
# Both are unsigned big-endian integers encoded as base64url.

def _int_to_base64url(n):
    """Convert a non-negative integer to a big-endian base64url string."""
    byte_length = (n.bit_length() + 7) // 8
    return base64url_encode(n.to_bytes(byte_length, byteorder='big'))


def public_key_to_jwk(public_key, kid):
    """
    Export an RSA public key as a JWK dict.

    The RSA public key is fully described by two numbers: n and e.
    Everything else in the JWK (kty, use, alg, kid) is metadata.
    """
    pub_numbers = public_key.public_numbers()
    return {
        'kty': 'RSA',    # key type
        'use': 'sig',    # intended use: signature verification
        'alg': 'RS256',  # algorithm this key is used with
        'kid': kid,      # key ID — lets clients match a token to its key
        'n': _int_to_base64url(pub_numbers.n),
        'e': _int_to_base64url(pub_numbers.e),
    }


# ── Key management ────────────────────────────────────────────────────────────

_KEYS_DIR    = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'keys')
_KEY_PATH    = os.path.join(_KEYS_DIR, 'private.pem')

_private_key = None
_public_key  = None
_kid         = None


def _generate_key():
    """
    Generate a new RSA-2048 private key.
    public_exponent=65537 is the standard safe choice (Fermat prime F4).
    key_size=2048 is the minimum recommended size for RS256.
    """
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )


def _save_key(private_key):
    os.makedirs(_KEYS_DIR, exist_ok=True)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(_KEY_PATH, 'wb') as f:
        f.write(pem)


def _load_key():
    with open(_KEY_PATH, 'rb') as f:
        return serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )


def _derive_kid(public_key):
    """
    Derive a stable key ID from the public key's DER bytes.
    Using the first 16 hex chars of SHA-256(DER) gives a short,
    deterministic identifier that changes automatically when the key rotates.
    """
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).hexdigest()[:16]


def init_keys():
    """
    Load the RSA key pair from disk, or generate and persist a new one.
    Must be called once at application startup. Subsequent calls are no-ops.
    """
    global _private_key, _public_key, _kid

    if _private_key is not None:
        return

    if os.path.exists(_KEY_PATH):
        _private_key = _load_key()
    else:
        _private_key = _generate_key()
        _save_key(_private_key)

    _public_key = _private_key.public_key()
    _kid        = _derive_kid(_public_key)


def get_private_key():
    """Return the loaded RSA private key. Raises if init_keys() was not called."""
    if _private_key is None:
        raise RuntimeError('JWT keys not initialised — call init_keys() at startup')
    return _private_key


def get_public_key():
    """Return the loaded RSA public key."""
    if _public_key is None:
        raise RuntimeError('JWT keys not initialised — call init_keys() at startup')
    return _public_key


def get_kid():
    """Return the key ID for the active key pair."""
    if _kid is None:
        raise RuntimeError('JWT keys not initialised — call init_keys() at startup')
    return _kid


def get_jwks():
    """Return the JWKS dict (suitable for the /.well-known/jwks.json response)."""
    return public_key_to_jwk(get_public_key(), get_kid())
