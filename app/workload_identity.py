"""
Workload identity module.

This module implements a lightweight SPIFFE-inspired workload identity system.
A service proves its identity by presenting a time-limited HMAC-SHA256 attestation
token derived from a shared secret and the current UTC minute. If the attestation
is valid and the service is registered in the service registry, the server issues
a short-lived Ed25519 JWT (SVID — SPIFFE Verifiable Identity Document) scoped to
the trust-broker audience.

The issued SVID cannot be used directly against downstream services. The holder
must present it to the token-exchange broker (POST /token/exchange) to obtain a
service-scoped token for a specific target audience. This two-step design limits
the blast radius of a compromised SVID: it is only useful at the broker, not at
arbitrary service endpoints.

Clock-skew tolerance: the attestation check accepts tokens from the current minute
and up to (WORKLOAD_ATTESTATION_WINDOW_MINUTES - 1) preceding minutes. The default
window of 2 covers the current and previous minute, which is sufficient for
well-synchronised NTP clocks. Operators in environments with known clock skew can
raise the window via the WORKLOAD_ATTESTATION_WINDOW_MINUTES environment variable.
"""

import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.jwt_backend import create_access_token
from app.models import ServiceRegistry
from app.security import append_audit_event

router = APIRouter(prefix="/workload", tags=["workload-identity"])

# Number of one-minute windows accepted during attestation verification. Each
# window corresponds to one past minute (0 = current, 1 = previous, ...).
# Raising this value accommodates larger clock skew at the cost of a wider
# replay window — an attacker who intercepts an attestation token can reuse it
# for up to WORKLOAD_ATTESTATION_WINDOW_MINUTES minutes.
_ATTESTATION_WINDOW = int(os.getenv("WORKLOAD_ATTESTATION_WINDOW_MINUTES", "2"))


def _expected_hmac(service_name: str, minute_str: str) -> str:
    """Compute the expected HMAC-SHA256 attestation value for a given service and minute.

    The HMAC input is the string "service_name:minute_str" where minute_str is a
    UTC timestamp truncated to the minute (format: YYYYMMDDTHHMM). Both the service
    name and the minute are included in the message so the token is specific to one
    service for one minute only.

    WORKLOAD_ATTESTATION_SECRET must be set in the environment; a missing key raises
    a KeyError at runtime, failing the request rather than silently accepting any
    attestation.
    """
    secret = os.environ["WORKLOAD_ATTESTATION_SECRET"].encode()
    msg = f"{service_name}:{minute_str}".encode()
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


class WorkloadIdentityRequest(BaseModel):
    """Request body for the workload identity issuance endpoint.

    service_name: the service's unique identifier, matching a row in the
        service_registry table.
    attestation: the HMAC-SHA256 hex digest the service computes from the shared
        secret and the current UTC minute string.
    """

    service_name: str
    attestation: str


@router.post("/identity/issue")
def issue_workload_svid(
    req: WorkloadIdentityRequest,
    db: Session = Depends(get_db),
):
    """Verify a workload attestation and issue a short-lived SVID.

    Verification proceeds in three steps:
    1. Compute the expected HMAC for each minute in the acceptance window and
       compare against the submitted attestation using a constant-time digest
       comparison to prevent timing attacks.
    2. Look up the service in the service registry and confirm it is enabled.
    3. Issue an Ed25519 access token scoped to 'trust-broker' with 'type' and
       'env' extra claims so the broker can distinguish SVIDs from user tokens.

    Returns a bearer token valid for 300 seconds. The caller exchanges it at
    POST /token/exchange for a service-scoped token targeting a specific audience.

    Raises 401 if the attestation does not match any valid minute window.
    Raises 404 if the service_name is not in the registry or is disabled.
    """
    now = datetime.now(timezone.utc)
    # Build the list of valid minute strings for the current acceptance window.
    # i=0 is the current minute, i=1 is one minute ago, and so on.
    valid_minutes = [
        (now - timedelta(minutes=i)).strftime("%Y%m%dT%H%M")
        for i in range(_ATTESTATION_WINDOW)
    ]

    # Check the submitted attestation against every valid minute using
    # hmac.compare_digest to avoid timing side-channels.
    ok = any(
        hmac.compare_digest(
            req.attestation,
            _expected_hmac(req.service_name, m),
        )
        for m in valid_minutes
    )
    if not ok:
        raise HTTPException(401, detail={"error": "attestation_failed"})

    # Confirm the service is registered and active before issuing a token.
    svc = db.query(ServiceRegistry).filter_by(service_id=req.service_name, enabled=True).first()
    if not svc:
        raise HTTPException(404, detail={"error": "service_not_registered"})

    # Issue a short-lived SVID. The audience is fixed to 'trust-broker' so the
    # token can only be presented to the exchange endpoint, not to downstream
    # services directly.
    token = create_access_token(
        subject=f"workload:{req.service_name}",
        audience="trust-broker",
        extra_claims={
            "type": "workload-svid",
            "env": os.getenv("APP_ENV", "prod"),
        },
    )

    # Record the issuance event in the hash-chained audit log.
    append_audit_event(
        db,
        "workload_identity_issued",
        req.service_name,
        "trust-broker",
        "ALLOW",
    )

    return {"access_token": token, "token_type": "bearer", "expires_in": 300}
