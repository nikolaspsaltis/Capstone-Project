import os
from typing import Any

from jose import JWTError as JoseJWTError
from jose import jwt as jose_jwt

try:
    import jwt as pyjwt
    from jwt import InvalidTokenError as PyJWTInvalidTokenError
except Exception:  # pragma: no cover - optional runtime backend
    pyjwt = None
    PyJWTInvalidTokenError = Exception

DEFAULT_BACKEND = "python-jose"


class TokenDecodeError(Exception):
    pass


def get_jwt_backend_name() -> str:
    requested = os.getenv("JWT_BACKEND", DEFAULT_BACKEND).strip().lower()
    if requested == "pyjwt" and pyjwt is not None:
        return "pyjwt"
    return DEFAULT_BACKEND


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
    