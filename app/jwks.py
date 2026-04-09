import base64

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import APIRouter

from app import jwt_backend

router = APIRouter(tags=["auth"])


@router.get("/auth/jwks.json")
def get_jwks():
    pub_bytes = jwt_backend._public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    x = base64.urlsafe_b64encode(pub_bytes).rstrip(b"=").decode()
    return {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": jwt_backend.KID,
                "x": x,
                "use": "sig",
                "alg": "EdDSA",
            }
        ]
    }
