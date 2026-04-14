"""
Authentication module.

Handles password hashing, JWT and API key creation/verification, TOTP (MFA),
and the FastAPI dependency functions that protect routes.

Startup behaviour: _load_jwt_secret() and _load_api_keys() are called at
import time. If either check fails (missing secret, placeholder value) the
application raises StartupConfigurationError and refuses to start. This
fail-fast design prevents accidental deployment with insecure defaults.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import time
from datetime import timedelta
from typing import Callable, Optional
from uuid import uuid4

import bcrypt as bcrypt_lib
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db, utcnow, utcnow_naive
from app.jwt_backend import (
    TokenDecodeError,
    _decode_access_payload,
    decode_jwt,
    encode_jwt,
)
from app.jwt_backend import (
    create_access_token as _jwt_create_access_token,
)
from app.models import APIKey, User
from app.security import _is_token_revoked, increment_metric

# OAuth2 scheme used by auth.py's own get_current_user dependency.
# main.py defines its own scheme for route handlers; this one is for
# internal use within this module.
_auth_oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


class StartupConfigurationError(RuntimeError):
    """Raised when a required environment variable is missing or insecure.

    The application catches this at startup and exits immediately, preventing
    the server from running with broken or dangerous configuration.
    """


def _load_jwt_secret() -> str:
    """Read JWT_SECRET from the environment and reject placeholder values.

    A missing or placeholder secret means tokens could be forged by anyone
    who knows the default value, so the app refuses to start.
    """
    secret = os.getenv("JWT_SECRET", "")
    if not secret:
        raise StartupConfigurationError(
            "Intentional startup block: required env var JWT_SECRET is missing.\n"
            "How to fix:\n"
            "1) Copy .env.example to .env\n"
            "2) Set JWT_SECRET to a strong random value in .env\n"
            "3) Load env vars: set -a; . ./.env; set +a\n"
            "Reference: .env.example"
        )
    if secret == "change-this-secret-in-production":
        raise StartupConfigurationError(
            "Intentional startup block: JWT_SECRET is still set to the placeholder value.\n"
            "Update JWT_SECRET in .env (see .env.example), then reload env vars."
        )
    return secret


def _load_api_keys() -> list[str]:
    """Read API_KEYS from the environment, split on commas, and reject placeholders.

    API_KEYS is a comma-separated list of raw key strings. Each key is
    checked against a set of known placeholder values; if any match is found
    the app refuses to start. This prevents deployment with demo credentials
    that are publicly known.
    """
    raw_value = os.getenv("API_KEYS", "")
    keys = [key.strip() for key in raw_value.split(",") if key.strip()]
    if not keys:
        raise StartupConfigurationError(
            "Intentional startup block: required env var API_KEYS is missing or empty.\n"
            "How to fix:\n"
            "1) Copy .env.example to .env\n"
            "2) Set API_KEYS to one or more strong values (comma-separated)\n"
            "3) Load env vars: set -a; . ./.env; set +a\n"
            "Reference: .env.example"
        )

    placeholder_values = {
        "capstone-demo-key",
        "change-this-api-key-in-production",
    }
    if any(key in placeholder_values for key in keys):
        raise StartupConfigurationError(
            "Intentional startup block: API_KEYS is still set to a placeholder/demo value.\n"
            "Set API_KEYS in .env to strong random values before starting the app."
        )
    return keys


# These constants are loaded once at module import. Any failure here prevents
# the application from starting, rather than failing silently at first request.
SECRET_KEY = _load_jwt_secret()
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_ISSUER = os.getenv("JWT_ISSUER", "capstone-project")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "capstone-client")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "30"))
REFRESH_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_REFRESH_EXPIRE_MINUTES", "10080"))
PASSWORD_RESET_TOKEN_EXPIRE_MINUTES = int(os.getenv("PASSWORD_RESET_TOKEN_EXPIRE_MINUTES", "15"))

# API_KEYS holds the validated list of raw key strings for in-memory comparison.
# Rotation is supported by adding new keys without removing old ones until
# all clients have migrated.
API_KEYS = _load_api_keys()
DEFAULT_API_KEY_SCOPES = ["data:read"]
ALLOWED_API_KEY_SCOPES = {
    "data:read",
    "metrics:read",
    "alerts:read",
}


def _is_truthy(value: str) -> bool:
    """Return True if the string represents a truthy configuration value."""
    return value.strip().lower() in {"1", "true", "yes", "on"}


# TESTING_MODE lowers the bcrypt work factor from 12 to 4 rounds so that
# the test suite completes in seconds rather than minutes. This is set by
# conftest.py before importing the app, ensuring tests always run fast.
TESTING_MODE = _is_truthy(os.getenv("TESTING", "0"))
DEFAULT_BCRYPT_ROUNDS = 12
TEST_BCRYPT_ROUNDS = 4
bcrypt_rounds = int(os.getenv("BCRYPT_ROUNDS", str(DEFAULT_BCRYPT_ROUNDS)))
if TESTING_MODE:
    bcrypt_rounds = int(os.getenv("BCRYPT_TEST_ROUNDS", str(TEST_BCRYPT_ROUNDS)))
# Enforce a minimum of 4 rounds to prevent accidental use of an insecure value.
bcrypt_rounds = max(4, bcrypt_rounds)

# passlib CryptContext wraps the bcrypt implementation and handles hash format
# negotiation. deprecated="auto" marks old hash formats for future re-hashing.
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=bcrypt_rounds,
)


def _hash_api_key(api_key: str) -> str:
    """Return the SHA-256 hex digest of the raw API key string.

    Only the hash is stored in the database so a breach does not expose
    the raw keys. Lookups hash the incoming value and compare against stored hashes.
    """
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def _hash_reset_token(token: str) -> str:
    """Return the SHA-256 hex digest of a password reset token.

    The raw token is sent to the user; only the hash is stored.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _normalize_api_key_scopes(scopes: Optional[list[str]]) -> list[str]:
    """Validate and deduplicate a list of requested scopes.

    Returns DEFAULT_API_KEY_SCOPES when the input is empty or None.
    Raises HTTP 400 if any scope is not in ALLOWED_API_KEY_SCOPES.
    """
    if not scopes:
        return list(DEFAULT_API_KEY_SCOPES)
    normalized = sorted({scope.strip() for scope in scopes if scope and scope.strip()})
    if not normalized:
        return list(DEFAULT_API_KEY_SCOPES)
    invalid = [scope for scope in normalized if scope not in ALLOWED_API_KEY_SCOPES]
    if invalid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid API key scope(s): {', '.join(invalid)}",
        )
    return normalized


def _serialize_api_key_scopes(scopes: list[str]) -> str:
    """Serialise a scope list to a JSON string for storage in the database."""
    return json.dumps(scopes)


def _deserialize_api_key_scopes(scopes_value: str) -> list[str]:
    """Deserialise a scope string from the database back to a list.

    Expects a JSON array. Falls back to comma-split parsing to handle any
    rows written before the JSON migration. Returns DEFAULT_API_KEY_SCOPES
    if the stored value is empty or unparseable.
    """
    try:
        parsed = json.loads(scopes_value)
        if isinstance(parsed, list) and parsed:
            return parsed
    except (json.JSONDecodeError, ValueError):
        # Fallback: handle legacy comma-separated values already in the DB.
        legacy = [s for s in scopes_value.split(",") if s]
        if legacy:
            return legacy
    return list(DEFAULT_API_KEY_SCOPES)


def _pad_base32(secret: str) -> str:
    """Add the padding that base64.b32decode requires but TOTP secrets omit."""
    return secret + "=" * ((8 - len(secret) % 8) % 8)


def generate_totp_secret() -> str:
    """Generate a random 20-byte TOTP secret encoded as unpadded base32.

    The base32 alphabet is what authenticator apps (e.g. Google Authenticator)
    expect when scanning a provisioning URI QR code.
    """
    return base64.b32encode(secrets.token_bytes(20)).decode("utf-8").rstrip("=")


def generate_totp_code(secret: str, for_timestamp: int) -> str:
    """Compute the 6-digit TOTP code for the given secret and Unix timestamp.

    Implements RFC 6238 (TOTP) over HOTP (RFC 4226):
    1. Divide the timestamp by 30 to get the current time step (counter).
    2. HMAC-SHA1 the counter (big-endian 8-byte) with the decoded secret.
    3. Extract a 4-byte dynamic truncation offset from the last nibble.
    4. Read a 31-bit integer from the digest at that offset.
    5. Reduce modulo 1,000,000 and zero-pad to 6 digits.
    """
    key = base64.b32decode(_pad_base32(secret), casefold=True)
    counter = for_timestamp // 30
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    code = binary % 1_000_000
    return f"{code:06d}"


def verify_totp_code(secret: str, code: str, window: int = 1) -> bool:
    """Check a submitted TOTP code against the expected code at the current time.

    The window parameter allows one time step (30 seconds) of clock drift in
    either direction, accepting codes from the previous and next step as well.
    secrets.compare_digest prevents timing-based side-channel attacks.
    """
    now = int(time.time())
    for step in range(-window, window + 1):
        expected = generate_totp_code(secret=secret, for_timestamp=now + step * 30)
        if secrets.compare_digest(expected, code):
            return True
    return False


def get_valid_api_key_record(db: Session, raw_key: str) -> Optional[APIKey]:
    """Look up an active, non-expired API key by its raw value.

    The raw key is hashed before querying so the plain-text value is never
    compared directly against the database. Returns None if the key is not
    found, is inactive, or has passed its expiry timestamp.
    """
    hashed = _hash_api_key(raw_key)
    record = (
        db.execute(
            select(APIKey).where(
                APIKey.key_hash == hashed,
                APIKey.is_active.is_(True),
            )
        )
        .scalars()
        .first()
    )
    if not record:
        return None
    # Expiry is optional. An expires_at of None means the key never expires.
    if record.expires_at is not None and record.expires_at < utcnow_naive():
        return None
    return record


def hash_password(password: str) -> str:
    """Hash a password using bcrypt with the configured work factor.

    passlib is the primary path. The direct bcrypt fallback handles edge cases
    caused by version incompatibilities between passlib 1.7.4 and bcrypt 4.x
    where passlib's internal version detection fails.
    """
    try:
        return pwd_context.hash(password)
    except Exception:
        # Fallback keeps auth available if passlib backend init fails unexpectedly.
        hashed = bcrypt_lib.hashpw(
            password.encode("utf-8"),
            bcrypt_lib.gensalt(rounds=bcrypt_rounds),
        )
        return hashed.decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a plain-text password against a stored bcrypt hash.

    Uses the same two-path strategy as hash_password: passlib first, direct
    bcrypt as a fallback. Returns False on any exception rather than raising,
    so the login handler always produces a clean 401 for bad credentials.
    """
    try:
        return pwd_context.verify(password, password_hash)
    except Exception:
        try:
            return bcrypt_lib.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
        except ValueError:
            return False


def _create_token(
    subject: str,
    token_type: str,
    expires_minutes: int,
    refresh_version: Optional[int] = None,
) -> str:
    """Build and sign a JWT using the HS256 backend (used for refresh tokens).

    Refresh tokens carry an rv (refresh version) claim that must match the
    user's current refresh_token_version. Incrementing that counter on logout
    immediately invalidates all outstanding refresh tokens for that user.
    """
    issued_at = utcnow()
    expire = issued_at + timedelta(minutes=expires_minutes)
    payload = {
        "sub": subject,
        "exp": expire,
        "iat": issued_at,
        "jti": str(uuid4()),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "typ": token_type,
    }
    if token_type == "refresh":
        payload["rv"] = refresh_version if refresh_version is not None else 0
    return encode_jwt(payload=payload, secret=SECRET_KEY, algorithm=ALGORITHM)


def create_access_token(subject: str) -> str:
    """Create a short-lived Ed25519 access token for a user subject.

    Delegates to the jwt_backend module which manages the Ed25519 key state.
    The subject is typically the username from the users table.
    """
    return _jwt_create_access_token(subject=subject)


def create_refresh_token(user: User) -> str:
    """Create a long-lived HS256 refresh token for the given user.

    The token embeds the user's current refresh_token_version so that the
    server can detect and reject tokens from previous sessions.
    """
    return _create_token(
        subject=user.username,
        token_type="refresh",
        expires_minutes=REFRESH_TOKEN_EXPIRE_MINUTES,
        refresh_version=user.refresh_token_version,
    )


def decode_token(
    *,
    token: str,
    expected_type: str,
    is_token_revoked: Callable[[str], bool],
) -> dict:
    """Decode and fully validate a JWT, raising HTTP 401 on any failure.

    Validation steps:
    1. Decode using the appropriate backend (EdDSA for access, HS256 for refresh).
    2. Verify all required claims are present.
    3. Check the typ claim matches expected_type.
    4. Check the JTI against the revocation list via the is_token_revoked callback.

    The revocation check is supplied as a callable so callers can inject the
    appropriate database session without this function depending on the session directly.
    """
    cred_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        if expected_type == "access":
            # Access tokens use Ed25519 and are verified without a shared secret.
            payload = _decode_access_payload(
                token=token,
                audience=JWT_AUDIENCE,
                issuer=JWT_ISSUER,
            )
        else:
            # Refresh tokens use HS256 and require the server-side secret.
            payload = decode_jwt(
                token=token,
                secret=SECRET_KEY,
                algorithm=ALGORITHM,
                audience=JWT_AUDIENCE,
                issuer=JWT_ISSUER,
            )
    except TokenDecodeError:
        raise cred_exc

    # Require all standard claims to be present.
    required = ("sub", "exp", "iat", "jti", "iss", "aud", "typ")
    if not all(field in payload for field in required):
        raise cred_exc

    # The typ claim prevents an access token from being used as a refresh token
    # and vice versa.
    if payload.get("typ") != expected_type:
        raise cred_exc

    # Check the JTI against the server-side revocation list.
    if is_token_revoked(payload["jti"]):
        raise cred_exc

    return payload


def create_api_key_record(
    db: Session,
    *,
    name: str,
    created_by: str,
    scopes: Optional[list[str]] = None,
    expires_minutes: Optional[int] = None,
    rotated_from_id: Optional[int] = None,
) -> tuple[APIKey, str]:
    """Create a new API key record in the database and return the record and raw key.

    The raw key is generated as a URL-safe random string prefixed with 'cap_'.
    Only the SHA-256 hash and a 12-character prefix are stored; the raw key is
    returned once to the caller and cannot be retrieved again.

    rotated_from_id links this key to the key it replaced so the rotation
    history is preserved in the database.
    """
    raw_key = f"cap_{secrets.token_urlsafe(32)}"
    key_hash = _hash_api_key(raw_key)
    normalized_scopes = _normalize_api_key_scopes(scopes)
    expires_at = (
        utcnow_naive() + timedelta(minutes=expires_minutes)
        if expires_minutes is not None and expires_minutes > 0
        else None
    )
    key_record = APIKey(
        name=name,
        key_hash=key_hash,
        key_prefix=raw_key[:12],
        scopes=_serialize_api_key_scopes(normalized_scopes),
        is_active=True,
        created_by=created_by,
        rotated_from_id=rotated_from_id,
        expires_at=expires_at,
    )
    db.add(key_record)
    db.commit()
    db.refresh(key_record)
    return key_record, raw_key


def seed_api_keys_from_env(db: Session) -> None:
    """Ensure that every key in API_KEYS has a corresponding active database record.

    This runs at startup so admin-created keys from the environment variable
    appear in the key management endpoints. Keys already present in the database
    are skipped to prevent duplicates across restarts.
    """
    for idx, raw_key in enumerate(API_KEYS, start=1):
        if get_valid_api_key_record(db=db, raw_key=raw_key):
            continue
        db.add(
            APIKey(
                name=f"seeded-env-key-{idx}",
                key_hash=_hash_api_key(raw_key),
                key_prefix=raw_key[:12],
                scopes=_serialize_api_key_scopes(DEFAULT_API_KEY_SCOPES),
                is_active=True,
                created_by="system",
            )
        )
    db.commit()


def get_user_by_username(db: Session, username: str) -> Optional[User]:
    """Return the User row with the given username, or None if not found."""
    stmt = select(User).where(User.username == username)
    return db.execute(stmt).scalars().first()


def validate_refresh_token_version(payload: dict, user: User) -> None:
    """Reject a refresh token whose version does not match the user's current version.

    When a user logs out, refresh_token_version is incremented. Any refresh
    token issued before the logout carries the old rv value and is rejected here,
    preventing a stolen refresh token from being used after logout.
    """
    if payload.get("rv") != user.refresh_token_version:
        raise HTTPException(status_code=401, detail="Invalid refresh token")


def get_current_user(
    db: Session = Depends(get_db), token: str = Depends(_auth_oauth2_scheme)
) -> User:
    """FastAPI dependency that resolves a bearer token to a User object.

    Used internally within auth.py. main.py defines its own equivalent
    dependency to attach the lockout check and metric increments to the
    main request path.
    """
    payload = decode_token(
        token=token,
        expected_type="access",
        is_token_revoked=lambda jti: _is_token_revoked(db, jti),
    )
    username = payload["sub"]
    user = get_user_by_username(db, username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    increment_metric("jwt_auth_successes", 1)
    return user


async def get_raw_payload(
    token: str = Depends(_auth_oauth2_scheme),
) -> dict:
    """FastAPI dependency that decodes a bearer token and returns the raw claims dict.

    Used by routes that need direct access to token claims (e.g. custom
    audience or extra metadata) rather than a User model instance.
    """
    from app.jwt_backend import TokenDecodeError as _TDE
    from app.jwt_backend import get_raw_payload as _decode

    try:
        return _decode(token)
    except _TDE:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
