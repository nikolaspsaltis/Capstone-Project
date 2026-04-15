"""
Downstream service — minimal stub for docker-compose demonstration.

This service represents a downstream resource endpoint in the zero-trust flow.
It accepts requests carrying a Bearer token, verifies the token's audience
against its own service identifier, and returns a protected resource payload.

In the full zero-trust flow a caller must:
  1. Obtain a workload SVID from POST /workload/identity/issue
  2. Exchange it at POST /token/exchange with target_audience=https://data-service.internal
  3. Present the resulting scoped token to this service

This service does not perform full Ed25519 signature verification — it trusts the
upstream API server to issue correctly signed tokens and checks only that the
audience claim matches the expected value. In a production deployment this service
would fetch the JWKS from the API server and verify signatures independently.
"""

import base64
import json
import os

from fastapi import FastAPI, Header, HTTPException

app = FastAPI(title="Downstream Data Service")

# The audience this service accepts. Must match the audience registered in the
# API server's service registry and requested at /token/exchange.
EXPECTED_AUDIENCE = os.getenv("SERVICE_AUDIENCE", "https://data-service.internal")


def _decode_payload_unverified(token: str) -> dict:
    """Decode the JWT payload without signature verification.

    For demonstration purposes only. A production service would verify the
    Ed25519 signature against the JWKS endpoint before trusting any claim.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("not a JWT")
        payload_b64 = parts[1]
        # Re-add padding stripped by the unpadded base64url encoding
        pad = 4 - len(payload_b64) % 4
        if pad != 4:
            payload_b64 += "=" * pad
        return json.loads(base64.urlsafe_b64decode(payload_b64).decode())
    except Exception as exc:
        raise HTTPException(status_code=401, detail=f"token decode failed: {exc}")


@app.get("/health")
def health():
    return {"status": "ok", "service": "downstream-data-service"}


@app.get("/resource")
def get_resource(authorization: str = Header(default=None)):
    """Return a protected resource after verifying the token audience.

    Expects an Authorization: Bearer <scoped-token> header where the token
    was obtained via POST /token/exchange with target_audience matching
    EXPECTED_AUDIENCE.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")

    token = authorization.removeprefix("Bearer ")
    payload = _decode_payload_unverified(token)

    # Verify audience — the only check this stub performs
    aud = payload.get("aud", [])
    if isinstance(aud, str):
        aud = [aud]
    if EXPECTED_AUDIENCE not in aud:
        raise HTTPException(
            status_code=401,
            detail=f"invalid audience: expected {EXPECTED_AUDIENCE!r}, got {aud!r}",
        )

    # Verify scope claim embedded by the token exchange broker
    if payload.get("scope") != "service:call":
        raise HTTPException(status_code=403, detail="missing required scope: service:call")

    return {
        "resource": "protected-data-payload",
        "granted_to": payload.get("sub"),
        "audience": EXPECTED_AUDIENCE,
        "orig_jti": payload.get("orig_jti"),
    }
