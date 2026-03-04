import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
from datetime import timedelta
from typing import Callable, Optional
from uuid import uuid4

import bcrypt as bcrypt_lib
from fastapi import HTTPException, status
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import utcnow, utcnow_naive
from app.jwt_backend import TokenDecodeError, decode_jwt, encode_jwt
from app.models import APIKey, User

SECRET_KEY = os.getenv("JWT_SECRET", "")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_ISSUER = os.getenv("JWT_ISSUER", "capstone-project")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "capstone-client")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "30"))
REFRESH_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_REFRESH_EXPIRE_MINUTES", "10080"))
PASSWORD_RESET_TOKEN_EXPIRE_MINUTES = int(os.getenv("PASSWORD_RESET_TOKEN_EXPIRE_MINUTES", "15"))

if not SECRET_KEY or SECRET_KEY == "change-this-secret-in-production":
    raise RuntimeError(
        "JWT_SECRET must be set to a strong value (and not the placeholder) before running the app."
    )

# API key rotation is supported by comma-separated keys in API_KEYS.
API_KEYS = [
    key.strip() for key in os.getenv("API_KEYS", "capstone-demo-key").split(",") if key.strip()
]
DEFAULT_API_KEY_SCOPES = ["data:read"]
ALLOWED_API_KEY_SCOPES = {
    "data:read",
    "metrics:read",
    "alerts:read",
}

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def _hash_reset_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _normalize_api_key_scopes(scopes: Optional[list[str]]) -> list[str]:
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
    return ",".join(scopes)


def _deserialize_api_key_scopes(scopes_value: str) -> list[str]:
    scopes = [scope for scope in scopes_value.split(",") if scope]
    return scopes or list(DEFAULT_API_KEY_SCOPES)


def _pad_base32(secret: str) -> str:
    return secret + "=" * ((8 - len(secret) % 8) % 8)


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("utf-8").rstrip("=")


def generate_totp_code(secret: str, for_timestamp: int) -> str:
    key = base64.b32decode(_pad_base32(secret), casefold=True)
    counter = for_timestamp // 30
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    code = binary % 1_000_000
    return f"{code:06d}"


def verify_totp_code(secret: str, code: str, window: int = 1) -> bool:
    now = int(time.time())
    for step in range(-window, window + 1):
        expected = generate_totp_code(secret=secret, for_timestamp=now + step * 30)
        if secrets.compare_digest(expected, code):
            return True
    return False


def get_valid_api_key_record(db: Session, raw_key: str) -> Optional[APIKey]:
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
    if record.expires_at is not None and record.expires_at < utcnow_naive():
        return None
    return record


def hash_password(password: str) -> str:
    try:
        return pwd_context.hash(password)
    except Exception:
        # Fallback keeps auth available if passlib backend init fails unexpectedly.
        hashed = bcrypt_lib.hashpw(password.encode("utf-8"), bcrypt_lib.gensalt())
        return hashed.decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
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
    return _create_token(
        subject=subject, token_type="access", expires_minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )


def create_refresh_token(user: User) -> str:
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
    cred_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = decode_jwt(
            token=token,
            secret=SECRET_KEY,
            algorithm=ALGORITHM,
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
        )
    except TokenDecodeError:
        raise cred_exc

    required = ("sub", "exp", "iat", "jti", "iss", "aud", "typ")
    if not all(field in payload for field in required):
        raise cred_exc

    if payload.get("typ") != expected_type:
        raise cred_exc

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
    stmt = select(User).where(User.username == username)
    return db.execute(stmt).scalars().first()


def validate_refresh_token_version(payload: dict, user: User) -> None:
    if payload.get("rv") != user.refresh_token_version:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
