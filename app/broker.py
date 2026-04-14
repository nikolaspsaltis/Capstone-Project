"""
Token-exchange broker module.

This module implements a zero-trust token exchange service that converts a
caller's access token into a narrower, audience-scoped token for a specific
downstream service. The exchange enforces three independent authorization layers:

1. Token validity: the incoming bearer token must be a valid, non-revoked
   Ed25519 JWT. Both regular user tokens (audience=JWT_AUDIENCE) and workload
   SVIDs (audience=trust-broker) are accepted.

2. Service registry: the requested target_audience must correspond to an enabled
   entry in the service_registry table, and the caller's subject must appear in
   that entry's allowed_callers JSON array.

3. Policy engine: the request is evaluated against the file-driven YAML policy
   rules loaded by app.policy. A policy denial overrides the registry check —
   even an authorised caller is blocked if a matching rule fires.

The issued scoped token carries a 'scope: service:call' claim and an 'orig_jti'
back-reference to the originating token, providing an audit trail from exchange
to original authentication event.
"""

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

# _BROKER_SCHEME extracts the Bearer token from the Authorization header using
# the standard OAuth2 password-bearer scheme. tokenUrl is set for OpenAPI
# documentation purposes only; it does not affect token validation.
_BROKER_SCHEME = OAuth2PasswordBearer(tokenUrl="login")


@dataclass
class _CallerIdentity:
    """Holds the normalised identity of an authenticated caller.

    Both human users and machine workloads are represented with this type.
    Workload subjects take the form 'workload:<service_name>' and carry
    role='service'; human subjects use the DB username and their stored role.
    """

    username: str
    role: str


def _get_broker_context(
    token: str = Depends(_BROKER_SCHEME),
    db: Session = Depends(get_db),
) -> tuple:
    """FastAPI dependency that authenticates and resolves the broker caller.

    Accepts two token audiences:
    - JWT_AUDIENCE (default 'capstone-client'): tokens issued to human users
      via the /login endpoint.
    - 'trust-broker': tokens issued to workload identities via the
      /workload/identity/issue endpoint.

    Both audiences are tried in sequence; the first successful decode wins.
    If both fail, the token is rejected with 401.

    After signature and audience verification, the JTI is checked against the
    revocation table. A revoked token is rejected even if the signature is valid.

    For human callers the subject is resolved to a DB User row to obtain the
    current role. Workload callers have no DB record; their role is 'service'.

    Returns a (CallerIdentity, raw_payload) tuple used by the exchange endpoint.
    """
    issuer = os.environ.get("JWT_ISSUER", "capstone-project")
    default_aud = os.environ.get("JWT_AUDIENCE", "capstone-client")

    # Attempt decoding with each accepted audience; break on the first success.
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

    # Reject the token if it has been explicitly revoked (e.g. via logout).
    if _is_token_revoked(db, payload["jti"]):
        raise HTTPException(
            status_code=401,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

    sub = payload["sub"]
    if sub.startswith("workload:"):
        # Workload identities are authenticated purely by their token; there is
        # no corresponding DB user record.
        caller = _CallerIdentity(username=sub, role="service")
    else:
        # Resolve the human caller to their current DB record so role changes
        # take effect immediately rather than being baked into the token.
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
    """Request body for POST /token/exchange.

    target_audience: the audience URI of the downstream service for which the
        caller wants a scoped access token. Must match a service_registry row.
    """

    target_audience: str


class ServiceRegistryCreate(BaseModel):
    """Request body for POST /admin/service-registry.

    service_id: unique internal identifier for the service.
    audience: the JWT audience URI used by the downstream service.
    allowed_callers: list of subject strings (usernames or workload:<name>)
        permitted to exchange tokens for this audience.
    """

    service_id: str
    audience: str
    allowed_callers: list[str]


@router.post("/exchange")
def exchange_token(
    req: ExchangeRequest,
    broker_ctx: tuple = Depends(_get_broker_context),
    db: Session = Depends(get_db),
):
    """Exchange a valid access token for a narrower, audience-scoped token.

    The exchange enforces three checks in order:

    1. Near-expiry guard: if the incoming token expires in fewer than 30 seconds
       it is rejected. This prevents the caller from obtaining a new token that
       would outlive its parent, which would undermine revocation guarantees.

    2. Service registry check: the requested target_audience must exist in the
       registry (enabled=True) and the caller's username must be listed in the
       service's allowed_callers JSON array.

    3. Policy check: the request context is evaluated against the loaded YAML
       policy rules. A matching deny rule blocks the exchange even if the caller
       is in allowed_callers.

    On success, issues a new Ed25519 access token scoped to target_audience.
    The token carries scope='service:call' and orig_jti pointing back to the
    original token, enabling end-to-end audit trail reconstruction.

    All outcomes (allow and deny) are written to the hash-chained audit log.

    Raises 401 if the originating token is near expiry.
    Raises 404 if the target audience is not registered.
    Raises 403 if the caller is not in allowed_callers or a policy rule fires.
    """
    current_user, raw_payload = broker_ctx

    # Reject tokens that are about to expire; 30 seconds gives the caller time
    # to receive the response but prevents issuing tokens that outlive the parent.
    remaining = raw_payload["exp"] - time.time()
    if remaining < 30:
        raise HTTPException(
            401,
            detail={
                "error": "token_near_expiry",
                "reason": "obtain a fresh token before exchanging",
            },
        )

    # Look up the target service; fail if it is unknown or disabled.
    svc = db.query(ServiceRegistry).filter_by(audience=req.target_audience, enabled=True).first()
    if not svc:
        raise HTTPException(404, detail={"error": "unknown_audience"})

    # Check the caller against the service's allowed_callers JSON array.
    allowed = json.loads(svc.allowed_callers)
    if current_user.username not in allowed:
        append_audit_event(
            db, "token_exchange_deny", current_user.username, req.target_audience, "DENY"
        )
        raise HTTPException(403, detail={"error": "not_authorised_for_audience"})

    # Build a policy context from the caller's attributes and evaluate it.
    # The env claim comes from the token itself so that policy rules can
    # distinguish production tokens from staging or development tokens.
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

    # Issue the scoped token. orig_jti links this token back to the original
    # access token so the full authentication chain is auditable.
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
