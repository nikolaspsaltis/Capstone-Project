"""
JWT backend module.

Handles all token creation and verification for access tokens (Ed25519 / EdDSA)
and refresh tokens (HS256 via python-jose or PyJWT).

python-jose 3.3.0 does not support EdDSA, so access tokens are signed and
verified directly using the `cryptography` library. Refresh tokens continue to
use python-jose's HS256 path because they do not need asymmetric verification.

The EdDSA implementation follows RFC 8037 (CFRG Elliptic Curves for JOSE).
"""

import base64
import hashlib
import json
import logging
import os
import time
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from jose import JWTError as JoseJWTError
from jose import jwt as jose_jwt

# PyJWT is an optional alternative backend. If the package is absent the
# module falls back to python-jose for all operations.
try:
    import jwt as pyjwt
    from jwt import InvalidTokenError as PyJWTInvalidTokenError
except Exception:  # pragma: no cover - optional runtime backend
    pyjwt = None
    PyJWTInvalidTokenError = Exception

DEFAULT_BACKEND = "python-jose"

# Module-level key state. Both variables are populated once by
# load_or_generate_signing_key() during application startup.
_signing_key = None
_public_key = None

# KID is a 16-character hex fingerprint of the public key, included in every
# token header so that verifiers can select the correct key from the JWKS endpoint.
KID: str | None = None

# LRU replay cache maps jti → expiry timestamp for single-use token flows.
# The regular REST access-token path does not use this cache because those
# tokens are multi-use; only the token-exchange broker checks it to enforce
# single use on scoped tokens.
_replay_cache: OrderedDict[str, float] = OrderedDict()
_REPLAY_CACHE_MAX = 10_000


class TokenDecodeError(Exception):
    """Raised for any token verification failure, regardless of the root cause.

    Unifying all failure modes into one exception type means callers do not
    need to handle library-specific exceptions from python-jose or PyJWT.
    """
    pass


def get_jwt_backend_name() -> str:
    """Return the active JWT backend name based on the JWT_BACKEND env var.

    Defaults to python-jose. Returns pyjwt only if explicitly requested and
    the package is installed.
    """
    requested = os.getenv("JWT_BACKEND", DEFAULT_BACKEND).strip().lower()
    if requested == "pyjwt" and pyjwt is not None:
        return "pyjwt"
    return DEFAULT_BACKEND


def load_or_generate_signing_key() -> None:
    """Load the Ed25519 private key from disk, or generate and persist a new one.

    The key path is read from JWT_PRIVATE_KEY_PATH (defaults to jwt_signing.pem).
    On first run the key file does not exist, so a fresh Ed25519 key pair is
    generated, written to disk with mode 0o600 (owner-read-only), and cached
    in the module-level variables. On subsequent runs the existing key is loaded
    so tokens issued in previous sessions remain verifiable.

    KID is derived as the first 16 hex characters of the SHA-256 hash of the
    raw public key bytes, matching the value published in the JWKS endpoint.
    """
    global _signing_key, _public_key, KID
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
        load_pem_private_key,
    )

    path = os.environ.get("JWT_PRIVATE_KEY_PATH", "jwt_signing.pem")
    if os.path.exists(path):
        with open(path, "rb") as f:
            _signing_key = load_pem_private_key(f.read(), password=None)
    else:
        # Generate a new key pair and persist it so restarts use the same key.
        _signing_key = Ed25519PrivateKey.generate()
        pem = _signing_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        with open(path, "wb") as f:
            f.write(pem)
        os.chmod(path, 0o600)
        logging.warning("Generated new Ed25519 signing key at %s", path)

    _public_key = _signing_key.public_key()
    pub_bytes = _public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    # Derive a stable key ID from the public key bytes for use in JWKS and token headers.
    KID = hashlib.sha256(pub_bytes).hexdigest()[:16]


def _check_and_cache_jti(jti: str, exp: float) -> None:
    """Reject replayed JTIs and add new ones to the in-memory replay cache.

    Expired entries are evicted first to prevent unbounded memory growth.
    When the cache is at capacity the oldest entry is evicted (LRU).
    This function is only called for single-use token flows such as the
    token-exchange broker; regular access tokens are multi-use and bypass it.
    """
    now = time.time()
    # Evict expired entries before checking for replay.
    stale = [k for k, v in _replay_cache.items() if v < now]
    for k in stale:
        del _replay_cache[k]
    if jti in _replay_cache:
        raise TokenDecodeError("token_replayed")
    # Evict the oldest entry if the cache has reached its size limit.
    if len(_replay_cache) >= _REPLAY_CACHE_MAX:
        _replay_cache.popitem(last=False)
    _replay_cache[jti] = exp


# ---------------------------------------------------------------------------
# EdDSA JWT helpers — python-jose 3.3.0 does not support EdDSA, so tokens are
# built and verified manually using the cryptography library primitives.
# The format follows the standard JWT structure: base64url(header) +
# "." + base64url(payload) + "." + base64url(signature).
# ---------------------------------------------------------------------------


def _b64url_encode(data: bytes) -> str:
    """Encode bytes as unpadded base64url, as required by the JWT specification."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    """Decode an unpadded base64url string back to bytes, re-adding padding first."""
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.urlsafe_b64decode(s)


def _to_timestamp(value: Any) -> int:
    """Convert a datetime, int, or float claim value to a POSIX timestamp integer."""
    if isinstance(value, datetime):
        return int(value.timestamp())
    return int(value)


def create_access_token(
    subject: str,
    audience: str | None = None,
    extra_claims: dict | None = None,
) -> str:
    """Create and sign an Ed25519 access token with a 5-minute TTL.

    The token header carries alg=EdDSA and the kid fingerprint. The payload
    includes the standard JWT claims (sub, aud, iss, iat, exp, jti, typ)
    plus any extra_claims supplied by the caller. Extra claims are used by the
    workload identity module to embed env and type metadata, and by the broker
    to embed scope and orig_jti for scoped tokens.
    """
    if _signing_key is None:
        raise RuntimeError("Signing key not loaded — call load_or_generate_signing_key() first")
    # Use the provided audience, or fall back to the default JWT audience from env.
    aud = [audience] if audience else [os.environ.get("JWT_AUDIENCE", "capstone-client")]
    now = int(datetime.now(timezone.utc).timestamp())
    payload: dict[str, Any] = {
        "sub": subject,
        "aud": aud,
        "iss": os.environ.get("JWT_ISSUER", "capstone-project"),
        "iat": now,
        "exp": now + 300,  # 5-minute access token TTL
        "jti": str(uuid4()),
        "typ": "access",
        **(extra_claims or {}),
    }
    header = {"alg": "EdDSA", "typ": "JWT", "kid": KID}
    # Encode header and payload separately, then sign the concatenated signing input.
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = _signing_key.sign(signing_input)
    return f"{header_b64}.{payload_b64}.{_b64url_encode(signature)}"


def _decode_access_payload(token: str, audience: str, issuer: str) -> dict[str, Any]:
    """Verify an EdDSA-signed access token and return the decoded claims.

    Verification steps:
    1. Split the token into three base64url parts.
    2. Re-verify the Ed25519 signature over header + payload.
    3. Check exp (must be in the future) and optionally nbf.
    4. Check iss and aud against the expected values.

    All failures raise TokenDecodeError so callers receive a single exception
    type regardless of which check failed.
    """
    from cryptography.exceptions import InvalidSignature

    if _public_key is None:
        raise TokenDecodeError("Public key not loaded")
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise TokenDecodeError("Invalid token structure")
        header_b64, payload_b64, sig_b64 = parts

        # Reconstruct the exact signing input and verify the signature.
        signing_input = f"{header_b64}.{payload_b64}".encode()
        try:
            _public_key.verify(_b64url_decode(sig_b64), signing_input)
        except InvalidSignature:
            raise TokenDecodeError("Signature verification failed")

        payload = json.loads(_b64url_decode(payload_b64).decode())
        now = time.time()

        # Check expiry.
        exp = _to_timestamp(payload.get("exp", 0))
        if exp < now:
            raise TokenDecodeError("Token expired")

        # Check nbf (not-before) if present.
        nbf = payload.get("nbf")
        if nbf is not None and _to_timestamp(nbf) > now:
            raise TokenDecodeError("Token not yet valid")

        # Verify the issuer claim matches the expected value.
        token_iss = payload.get("iss")
        if token_iss != issuer:
            raise TokenDecodeError(f"Invalid issuer: {token_iss!r}")

        # Verify the audience claim. The JWT spec allows aud to be a string or list.
        token_aud = payload.get("aud")
        if isinstance(token_aud, list):
            if audience not in token_aud:
                raise TokenDecodeError(f"Audience {audience!r} not in {token_aud!r}")
        elif token_aud != audience:
            raise TokenDecodeError(f"Invalid audience: {token_aud!r}")

        return payload

    except TokenDecodeError:
        raise
    except Exception as exc:
        raise TokenDecodeError(str(exc)) from exc


def get_raw_payload(token: str) -> dict[str, Any]:
    """Verify an access token using the default audience and issuer from env.

    Used by the broker and workload identity modules where the caller supplies
    the token directly rather than going through the standard FastAPI dependency.
    """
    audience = os.environ.get("JWT_AUDIENCE", "capstone-client")
    issuer = os.environ.get("JWT_ISSUER", "capstone-project")
    return _decode_access_payload(token=token, audience=audience, issuer=issuer)


# ---------------------------------------------------------------------------
# HS256 helpers — used for refresh tokens and the optional PyJWT backend path.
# Refresh tokens are symmetric (HS256) because they are only verified by this
# server, so there is no need to publish a public key for them.
# ---------------------------------------------------------------------------


def encode_jwt(payload: dict[str, Any], secret: str, algorithm: str) -> str:
    """Encode a JWT using whichever backend is active (python-jose or PyJWT)."""
    backend = get_jwt_backend_name()
    if backend == "pyjwt" and pyjwt is not None:
        return pyjwt.encode(payload, secret, algorithm=algorithm)
    return jose_jwt.encode(payload, secret, algorithm=algorithm)


def decode_jwt(
    token: str,
    secret: str,
    algorithm: str,
    audience: str,
    issuer: str,
) -> dict[str, Any]:
    """Decode and verify a symmetric JWT, raising TokenDecodeError on failure.

    Wraps both python-jose and PyJWT exceptions into TokenDecodeError so
    callers do not depend on library-specific exception types.
    """
    backend = get_jwt_backend_name()
    try:
        if backend == "pyjwt" and pyjwt is not None:
            payload = pyjwt.decode(
                token,
                secret,
                algorithms=[algorithm],
                audience=audience,
                issuer=issuer,
            )
            return dict(payload)
        payload = jose_jwt.decode(
            token,
            secret,
            algorithms=[algorithm],
            audience=audience,
            issuer=issuer,
        )
        return dict(payload)
    except (JoseJWTError, PyJWTInvalidTokenError) as exc:
        raise TokenDecodeError from exc
