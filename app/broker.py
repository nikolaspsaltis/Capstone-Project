import json
import os
import time
from dataclasses import dataclass

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.auth import get_user_by_username
from app.database import get_db
from app.jwt_backend import TokenDecodeError, _decode_access_payload, create_access_token
from app.models import ServiceRegistry
from app.policy import PolicyContext, evaluate
from app.security import _is_token_revoked, append_audit_event, increment_metric

router = APIRouter(prefix="/token", tags=["token-exchange"])

_BROKER_SCHEME = OAuth2PasswordBearer(tokenUrl="login")


@dataclass
class _CallerIdentity:
    username: str
    role: str


def _get_broker_context(
    token: str = Depends(_BROKER_SCHEME),
    db: Session = Depends(get_db),
) -> tuple:
    """Decode tokens with JWT_AUDIENCE or trust-broker audience.

    Workload SVIDs carry audience='trust-broker' and have no DB user record.
    Regular login tokens carry audience=JWT_AUDIENCE and map to a DB User.
    """
    issuer = os.environ.get("JWT_ISSUER", "capstone-project")
    default_aud = os.environ.get("JWT_AUDIENCE", "capstone-client")

    payload = None
    for aud in [default_aud, "trust-broker"]:
        try:
            payload = _decode_access_payload(token, audience=aud, issuer=issuer)
            break
        except TokenDecodeError:
            continue

    if payload is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if _is_token_revoked(db, payload["jti"]):
        raise HTTPException(
            status_code=401,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

    sub = payload["sub"]
    if sub.startswith("workload:"):
        caller = _CallerIdentity(username=sub, role="service")
    else:
        user = get_user_by_username(db, sub)
        if not user:
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        increment_metric("jwt_auth_successes", 1)
        caller = _CallerIdentity(username=user.username, role=user.role)

    return caller, payload


class ExchangeRequest(BaseModel):
    target_audience: str


class ServiceRegistryCreate(BaseModel):
    service_id: str
    audience: str
    allowed_callers: list[str]


@router.post("/exchange")
def exchange_token(
    req: ExchangeRequest,
    broker_ctx: tuple = Depends(_get_broker_context),
    db: Session = Depends(get_db),
):
    current_user, raw_payload = broker_ctx

    remaining = raw_payload["exp"] - time.time()
    if remaining < 30:
        raise HTTPException(
            401,
            detail={
                "error": "token_near_expiry",
                "reason": "obtain a fresh token before exchanging",
            },
        )

    svc = db.query(ServiceRegistry).filter_by(audience=req.target_audience, enabled=True).first()
    if not svc:
        raise HTTPException(404, detail={"error": "unknown_audience"})

    allowed = json.loads(svc.allowed_callers)
    if current_user.username not in allowed:
        append_audit_event(
            db, "token_exchange_deny", current_user.username, req.target_audience, "DENY"
        )
        raise HTTPException(403, detail={"error": "not_authorised_for_audience"})

    policy_ctx = PolicyContext(
        role=current_user.role,
        method="POST",
        path="/token/exchange",
        token_env=raw_payload.get("env", os.getenv("APP_ENV", "prod")),
        target_audience=req.target_audience,
    )
    decision = evaluate(policy_ctx)
    if not decision.allowed:
        append_audit_event(db, "policy_deny", current_user.username, req.target_audience, "DENY")
        raise HTTPException(
            403,
            detail={
                "error": "policy_denied",
                "reason": decision.reason,
                "rule_id": decision.rule_id,
            },
        )

    new_token = create_access_token(
        subject=current_user.username,
        audience=req.target_audience,
        extra_claims={
            "scope": "service:call",
            "orig_jti": raw_payload["jti"],
        },
    )
    append_audit_event(
        db, "token_exchange_allow", current_user.username, req.target_audience, "ALLOW"
    )
    return {"access_token": new_token, "token_type": "bearer", "expires_in": 300}
