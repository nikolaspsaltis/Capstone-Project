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

try:
    import jwt as pyjwt
    from jwt import InvalidTokenError as PyJWTInvalidTokenError
except Exception:  # pragma: no cover - optional runtime backend
    pyjwt = None
    PyJWTInvalidTokenError = Exception

DEFAULT_BACKEND = "python-jose"

# Ed25519 key state — populated by load_or_generate_signing_key() at startup.
_signing_key = None
_public_key = None
KID: str | None = None

# LRU replay cache — stores jti → exp for recently verified access tokens.
# Available for STS / token-exchange flows (chunk 04+) that require single-use tokens.
# Not wired into the regular REST decode path because access tokens are multi-use.
_replay_cache: OrderedDict[str, float] = OrderedDict()
_REPLAY_CACHE_MAX = 10_000


class TokenDecodeError(Exception):
    pass


def get_jwt_backend_name() -> str:
    requested = os.getenv("JWT_BACKEND", DEFAULT_BACKEND).strip().lower()
    if requested == "pyjwt" and pyjwt is not None:
        return "pyjwt"
    return DEFAULT_BACKEND


def load_or_generate_signing_key() -> None:
    """Load Ed25519 private key from disk, or generate and persist a new one."""
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
        _signing_key = Ed25519PrivateKey.generate()
        pem = _signing_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        with open(path, "wb") as f:
            f.write(pem)
        os.chmod(path, 0o600)
        logging.warning("Generated new Ed25519 signing key at %s", path)

    _public_key = _signing_key.public_key()
    pub_bytes = _public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    KID = hashlib.sha256(pub_bytes).hexdigest()[:16]


def _check_and_cache_jti(jti: str, exp: float) -> None:
    """Raise TokenDecodeError if jti was seen before; otherwise add it to the cache.

    Intended for single-use token flows (STS / token exchange). Not called on
    the regular REST access-token decode path because access tokens are multi-use.
    """
    now = time.time()
    stale = [k for k, v in _replay_cache.items() if v < now]
    for k in stale:
        del _replay_cache[k]
    if jti in _replay_cache:
        raise TokenDecodeError("token_replayed")
    if len(_replay_cache) >= _REPLAY_CACHE_MAX:
        _replay_cache.popitem(last=False)
    _replay_cache[jti] = exp


# ---------------------------------------------------------------------------
# EdDSA JWT helpers — python-jose 3.3.0 doesn't support EdDSA, so we build
# and verify tokens directly with the cryptography library.
# ---------------------------------------------------------------------------


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    # Re-add stripped padding before decoding.
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.urlsafe_b64decode(s)


def _to_timestamp(value: Any) -> int:
    """Convert a datetime, int, or float to a POSIX timestamp int."""
    if isinstance(value, datetime):
        return int(value.timestamp())
    return int(value)


def create_access_token(
    subject: str,
    audience: str | None = None,
    extra_claims: dict | None = None,
) -> str:
    """Create an Ed25519-signed access token with a 5-minute TTL."""
    if _signing_key is None:
        raise RuntimeError("Signing key not loaded — call load_or_generate_signing_key() first")
    aud = [audience] if audience else [os.environ.get("JWT_AUDIENCE", "capstone-client")]
    now = int(datetime.now(timezone.utc).timestamp())
    payload: dict[str, Any] = {
        "sub": subject,
        "aud": aud,
        "iss": os.environ.get("JWT_ISSUER", "capstone-project"),
        "iat": now,
        "exp": now + 300,
        "jti": str(uuid4()),
        "typ": "access",
        **(extra_claims or {}),
    }
    header = {"alg": "EdDSA", "typ": "JWT", "kid": KID}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = _signing_key.sign(signing_input)
    return f"{header_b64}.{payload_b64}.{_b64url_encode(signature)}"


def _decode_access_payload(token: str, audience: str, issuer: str) -> dict[str, Any]:
    """Verify an EdDSA-signed access token and return the claims dict.

    Raises TokenDecodeError on any verification failure.
    """
    from cryptography.exceptions import InvalidSignature

    if _public_key is None:
        raise TokenDecodeError("Public key not loaded")
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise TokenDecodeError("Invalid token structure")
        header_b64, payload_b64, sig_b64 = parts

        signing_input = f"{header_b64}.{payload_b64}".encode()
        try:
            _public_key.verify(_b64url_decode(sig_b64), signing_input)
        except InvalidSignature:
            raise TokenDecodeError("Signature verification failed")

        payload = json.loads(_b64url_decode(payload_b64).decode())
        now = time.time()

        exp = _to_timestamp(payload.get("exp", 0))
        if exp < now:
            raise TokenDecodeError("Token expired")

        nbf = payload.get("nbf")
        if nbf is not None and _to_timestamp(nbf) > now:
            raise TokenDecodeError("Token not yet valid")

        token_iss = payload.get("iss")
        if token_iss != issuer:
            raise TokenDecodeError(f"Invalid issuer: {token_iss!r}")

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
    """Decode and verify an access token, returning the full claims dict.

    Used by later chunks (broker, workload identity) that need direct claim access.
    """
    audience = os.environ.get("JWT_AUDIENCE", "capstone-client")
    issuer = os.environ.get("JWT_ISSUER", "capstone-project")
    return _decode_access_payload(token=token, audience=audience, issuer=issuer)


# ---------------------------------------------------------------------------
# Legacy helpers — used for refresh tokens (HS256) and the PyJWT backend path.
# ---------------------------------------------------------------------------


def encode_jwt(payload: dict[str, Any], secret: str, algorithm: str) -> str:
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
