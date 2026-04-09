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


def _expected_hmac(service_name: str, minute_str: str) -> str:
    secret = os.environ["WORKLOAD_ATTESTATION_SECRET"].encode()
    msg = f"{service_name}:{minute_str}".encode()
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


class WorkloadIdentityRequest(BaseModel):
    service_name: str
    attestation: str


@router.post("/identity/issue")
def issue_workload_svid(
    req: WorkloadIdentityRequest,
    db: Session = Depends(get_db),
):
    now = datetime.now(timezone.utc)
    valid_minutes = [
        now.strftime("%Y%m%dT%H%M"),
        (now - timedelta(minutes=1)).strftime("%Y%m%dT%H%M"),
    ]

    ok = any(
        hmac.compare_digest(
            req.attestation,
            _expected_hmac(req.service_name, m),
        )
        for m in valid_minutes
    )
    if not ok:
        raise HTTPException(401, detail={"error": "attestation_failed"})

    svc = db.query(ServiceRegistry).filter_by(service_id=req.service_name, enabled=True).first()
    if not svc:
        raise HTTPException(404, detail={"error": "service_not_registered"})

    token = create_access_token(
        subject=f"workload:{req.service_name}",
        audience="trust-broker",  # must be exchanged before calling any service
        extra_claims={
            "type": "workload-svid",
            "env": os.getenv("APP_ENV", "prod"),
        },
    )
    append_audit_event(
        db,
        "workload_identity_issued",
        req.service_name,
        "trust-broker",
        "ALLOW",
    )
    return {"access_token": token, "token_type": "bearer", "expires_in": 300}
