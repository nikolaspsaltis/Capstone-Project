"""
JWKS (JSON Web Key Set) endpoint.

This module exposes the server's Ed25519 public key in the standard JWKS format
defined by RFC 7517 and the OKP key type extension in RFC 8037. External clients
and services retrieve this endpoint to obtain the public key needed to verify
access tokens without having to share a symmetric secret.

Key format details:
- kty: "OKP" (Octet Key Pair) — the key type for Edwards-curve keys (RFC 8037).
- crv: "Ed25519" — the specific curve used for signing.
- x: the raw public key bytes encoded as unpadded base64url (as required by RFC 8037).
- kid: the key identifier fingerprint, derived in jwt_backend as the first 16 hex
  characters of the SHA-256 hash of the raw public key bytes. Clients use kid to
  select the correct key when a server rotates keys and publishes multiple entries.
- use: "sig" — indicates the key is used for digital signatures, not encryption.
- alg: "EdDSA" — the algorithm family; combined with crv=Ed25519 this fully
  specifies the signing algorithm for clients that perform algorithm binding.

The endpoint reads the live module-level state from jwt_backend, so if the signing
key is rotated in memory (e.g. during a key refresh), the JWKS response immediately
reflects the new public key.
"""

import base64

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import APIRouter

from app import jwt_backend

router = APIRouter(tags=["auth"])


@router.get("/auth/jwks.json")
def get_jwks():
    """Return the server's current Ed25519 public key as a JWKS document.

    Extracts the raw 32-byte public key from the jwt_backend module, encodes it
    as unpadded base64url (the encoding required by RFC 8037 for Ed25519 'x' values),
    and wraps it in the standard JWKS envelope with all required key parameters.

    The response contains a single key. Key rotation would add a second entry to
    the 'keys' array and remove the old one after all in-flight tokens signed with
    the old key have expired.

    This endpoint does not require authentication — public keys are intended to be
    freely distributed so that any relying party can verify tokens.
    """
    # Export the raw 32-byte Ed25519 public key. Raw format is required here
    # because the 'x' parameter in an OKP JWK is the bare key material, not a
    # DER or PEM wrapper.
    pub_bytes = jwt_backend._public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    # Encode the key bytes as unpadded base64url. RFC 8037 §2 specifies that
    # the 'x' parameter uses the base64urlUInt encoding without trailing '='.
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
