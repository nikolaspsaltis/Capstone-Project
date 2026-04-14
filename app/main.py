"""
Main application module.

This module wires together all subsystems of the Secure API Capstone project into
a single FastAPI application. It defines:

- Application startup and lifespan hooks (schema validation, key loading, API key seeding)
- CORS middleware and structured request-logging middleware
- FastAPI dependency functions for JWT and API key authentication
- RBAC enforcement via the require_admin dependency and the policy engine
- All HTTP route handlers for auth (register, login, logout, refresh), user
  profile, protected data, admin operations, and observability endpoints

Route namespaces:
  /auth/jwks.json     — JWKS endpoint (jwks.py router)
  /token/exchange     — Token-exchange broker (broker.py router)
  /workload/identity  — Workload SVID issuance (workload_identity.py router)
  /register, /login, /logout, /refresh, /password-reset/*  — Auth lifecycle
  /profile, /data     — User-facing protected endpoints
  /admin/*            — Admin operations (users, MFA, API keys, audit, alerts, cleanup)
  /health, /healthz, /readyz, /metrics  — Observability and health checks
"""

import json
import logging
import os
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Annotated, Optional
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, ConfigDict, StringConstraints
from sqlalchemy import func, inspect, select, update
from sqlalchemy.orm import Session

from app import jwks as jwks_module
from app.auth import (
    JWT_ISSUER,
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES,
    _deserialize_api_key_scopes,
    _hash_reset_token,
    create_access_token,
    create_api_key_record,
    create_refresh_token,
    decode_token,
    generate_totp_secret,
    get_user_by_username,
    get_valid_api_key_record,
    hash_password,
    seed_api_keys_from_env,
    validate_refresh_token_version,
    verify_password,
    verify_totp_code,
)
from app.broker import ServiceRegistryCreate
from app.broker import router as broker_router
from app.database import Base as _Base
from app.database import SessionLocal, engine, get_db, utcnow, utcnow_naive
from app.jwt_backend import get_jwt_backend_name, load_or_generate_signing_key
from app.models import (
    APIKey,
    AuditLog,
    AuthFailureLog,
    PasswordResetToken,
    ServiceRegistry,
    User,
)
from app.policy import PolicyContext, evaluate
from app.security import (
    _check_login_rate_limit,
    _compute_record_hash,
    _is_token_revoked,
    _is_user_locked,
    _register_auth_failure,
    _reset_lock_state,
    _revoke_token,
    _write_audit_log,
    app_start_time,
    increment_metric,
    log_event,
    metrics,
    metrics_lock,
    ops_logger,
    request_id_ctx,
    run_cleanup_jobs,
)
from app.workload_identity import router as workload_router

# oauth2_scheme raises 401 automatically when no Authorization header is present.
# oauth2_scheme_optional returns None instead of raising, allowing endpoints to
# accept either a JWT or an API key header.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
oauth2_scheme_optional = OAuth2PasswordBearer(tokenUrl="login", auto_error=False)

# Security alert thresholds for the /admin/security-alerts endpoint. All three
# can be overridden via environment variables so operators can tune sensitivity
# without code changes. Query parameters on the endpoint override these defaults
# further on a per-request basis.
ALERT_DEFAULT_WINDOW_MINUTES = int(os.getenv("ALERT_DEFAULT_WINDOW_MINUTES", "60"))
ALERT_DEFAULT_MIN_FAILED_LOGINS = int(os.getenv("ALERT_DEFAULT_MIN_FAILED_LOGINS", "5"))
ALERT_DEFAULT_MIN_ADMIN_DENIALS = int(os.getenv("ALERT_DEFAULT_MIN_ADMIN_DENIALS", "3"))

# Re-export Base under this module so existing test modules that do
# `from app.main import Base` continue to work after the database module refactor.
Base = _Base


# ---------------------------------------------------------------------------
# Internal helpers — thin wrappers that bind DB session dependencies to the
# lower-level auth and security functions so route handlers stay concise.
# ---------------------------------------------------------------------------

def _decode_token(db: Session, token: str, expected_type: str) -> dict:
    """Decode and verify a JWT, checking revocation against the current DB session.

    Delegates to app.auth.decode_token, passing a closure over `db` as the
    revocation checker. This keeps the route handlers free of direct DB queries
    for token verification.
    """
    return decode_token(
        token=token,
        expected_type=expected_type,
        is_token_revoked=lambda jti: _is_token_revoked(db, jti),
    )


def _validate_refresh_token_version(payload: dict, user: User) -> None:
    """Check the refresh token version claim against the user's current DB value.

    Raises 401 if the token version does not match, which happens when the user
    has logged out, changed their password, or an admin has forcibly revoked
    all refresh tokens. This ensures old refresh tokens become immediately useless
    after any of those events without requiring a per-token revocation entry.
    """
    validate_refresh_token_version(payload=payload, user=user)


# ---------------------------------------------------------------------------
# FastAPI dependency functions — injected into route handlers via Depends().
# ---------------------------------------------------------------------------

def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)) -> User:
    """Resolve the bearer token to a User row, enforcing revocation and lockout.

    Steps:
    1. Decode and verify the access token (signature, expiry, type=access, revocation).
    2. Look up the user by the 'sub' claim; reject with 401 if not found.
    3. Check account lockout: if the account is locked, raise 429 with a Retry-After
       header set to the remaining lockout duration in seconds.

    Lockout is checked on every authenticated request so that an admin-initiated
    lock or an automatically triggered lockout takes effect immediately, even for
    users who hold a valid unexpired access token.

    Returns the User ORM object on success.
    """
    payload = _decode_token(db=db, token=token, expected_type="access")
    username = payload["sub"]

    user = get_user_by_username(db, username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Reject requests from locked accounts even when the token is valid.
    # Retry-After tells the client exactly when the lock expires.
    if _is_user_locked(user):
        remaining = max(1, int((user.locked_until - utcnow_naive()).total_seconds()))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Account locked. Try again later.",
            headers={"Retry-After": str(remaining)},
        )

    increment_metric("jwt_auth_successes", 1)
    return user


def _authenticate_user_or_api_key(
    *,
    db: Session,
    token: Optional[str],
    x_api_key: Optional[str],
    required_scopes: Optional[set[str]] = None,
) -> Optional[User]:
    """Authenticate a request using either a JWT bearer token or an X-API-Key header.

    API key path:
    - Look up the raw key by its SHA-256 hash. If found and active, check that the
      key's scopes cover all required_scopes. An insufficient-scope key raises 403.
      A valid key updates last_used_at and increments the api_key_auth_successes metric.
      Returns None (no User object) because API keys are not tied to a specific user row.

    JWT path (fallback when no API key is present):
    - Decode the access token and resolve the subject to a User row.
      Returns the User object.

    If neither credential is supplied, raises 401.

    required_scopes is only enforced for API key authentication. JWT-authenticated
    requests are scoped by RBAC (role) rather than explicit scopes.
    """
    if x_api_key:
        api_key_record = get_valid_api_key_record(db=db, raw_key=x_api_key)
        if api_key_record:
            api_key_scopes = set(_deserialize_api_key_scopes(api_key_record.scopes))
            if required_scopes and not required_scopes.issubset(api_key_scopes):
                # Log the insufficient-scope attempt before raising so the admin
                # can see what was requested vs what the key is authorised for.
                _write_audit_log(
                    db=db,
                    action="api_key_auth",
                    status="failed_insufficient_scope",
                    details={
                        "required_scopes": sorted(required_scopes),
                        "api_key_scopes": sorted(api_key_scopes),
                    },
                    commit=True,
                )
                raise HTTPException(status_code=403, detail="API key missing required scope")
            # Record when the key was last used for key lifecycle management.
            api_key_record.last_used_at = utcnow_naive()
            db.commit()
            increment_metric("api_key_auth_successes", 1)
            return None

    if not token:
        raise HTTPException(status_code=401, detail="Missing JWT or API key")

    payload = _decode_token(db=db, token=token, expected_type="access")
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


def get_current_user_or_api_key(
    db: Session = Depends(get_db),
    token: Optional[str] = Depends(oauth2_scheme_optional),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> Optional[User]:
    """Accept either a bearer JWT or an X-API-Key header, with no scope requirement.

    Used by endpoints that permit any authenticated access regardless of the
    credential type. Returns a User on JWT auth, or None on API key auth.
    """
    return _authenticate_user_or_api_key(
        db=db,
        token=token,
        x_api_key=x_api_key,
    )


def get_current_user_or_api_key_for_data(
    db: Session = Depends(get_db),
    token: Optional[str] = Depends(oauth2_scheme_optional),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> Optional[User]:
    """Accept either a bearer JWT or an X-API-Key header, requiring the data:read scope.

    API keys must carry the 'data:read' scope to access the /data endpoint.
    JWT-authenticated users are permitted regardless of role (all registered
    users have implicit data access).
    """
    return _authenticate_user_or_api_key(
        db=db,
        token=token,
        x_api_key=x_api_key,
        required_scopes={"data:read"},
    )


def require_admin(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> User:
    """Enforce admin role and policy rules on admin-only endpoints.

    First verifies the user is authenticated (via get_current_user). Then
    evaluates the request against the loaded YAML policy rules. A matching
    deny rule overrides the role check — an admin can still be blocked by a
    policy that restricts access based on time of day, environment, or path.

    On policy denial, the event is written to the audit log and the
    admin_access_denied metric is incremented before raising 403.
    On success, admin_access_granted is incremented and the user is returned.
    """
    ctx = PolicyContext(
        role=current_user.role,
        method=request.method,
        path=request.url.path,
    )
    decision = evaluate(ctx)
    if not decision.allowed:
        increment_metric("admin_access_denied", 1)
        _write_audit_log(
            db=db,
            action="admin_access",
            status="denied",
            request=request,
            actor_username=current_user.username,
            actor_role=current_user.role,
            details={"path": request.url.path, "rule_id": decision.rule_id},
            commit=True,
        )
        raise HTTPException(
            status_code=403,
            detail={
                "error": "policy_denied",
                "reason": decision.reason,
                "rule_id": decision.rule_id,
            },
        )
    increment_metric("admin_access_granted", 1)
    return current_user


# ---------------------------------------------------------------------------
# Pydantic request/response models — define the shape of request bodies and
# response payloads for all endpoints. StringConstraints enforce minimum and
# maximum lengths at the validation layer so route handlers receive clean data.
# ---------------------------------------------------------------------------

class RegisterIn(BaseModel):
    """Request body for POST /register."""

    username: Annotated[str, StringConstraints(min_length=3, max_length=64)]
    password: Annotated[str, StringConstraints(min_length=6, max_length=256)]


class LoginIn(BaseModel):
    """Request body for POST /login.

    totp_code is optional because only admin accounts with MFA enabled
    require it. Regular users and admins without MFA can omit the field.
    """

    username: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    password: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    totp_code: Optional[Annotated[str, StringConstraints(min_length=6, max_length=6)]] = None


class TokenOut(BaseModel):
    """Response body for login and token-refresh endpoints.

    refresh_token is None when the endpoint issues only an access token (e.g.
    after a workload identity exchange).
    """

    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"


class RefreshIn(BaseModel):
    """Request body for POST /refresh and POST /logout.

    Both endpoints require the refresh token — /refresh rotates it and /logout
    revokes it. Using the refresh token (rather than the access token) for these
    operations ensures that revocation is tied to the longer-lived credential.
    """

    refresh_token: str


class ProfileOut(BaseModel):
    """Response body for GET /profile — returns the authenticated user's own record."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    role: str


class UserOut(BaseModel):
    """Response body for admin user-list entries."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    role: str


class AuthFailureLogOut(BaseModel):
    """Single auth failure log entry, returned by GET /admin/auth-failures."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    username: Optional[str]
    ip_address: str
    reason: str
    created_at: datetime


class AuthFailureLogPageOut(BaseModel):
    """Paginated response for GET /admin/auth-failures."""

    items: list[AuthFailureLogOut]
    page: int
    page_size: int
    total: int


class AuditLogOut(BaseModel):
    """Single audit log entry, returned by GET /admin/audit-logs."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    actor_username: Optional[str]
    actor_role: Optional[str]
    action: str
    status: str
    target_username: Optional[str]
    ip_address: str
    details: Optional[str]
    created_at: datetime


class AuditLogPageOut(BaseModel):
    """Paginated response for GET /admin/audit-logs."""

    items: list[AuditLogOut]
    page: int
    page_size: int
    total: int


class SecurityAlertOut(BaseModel):
    """Single security alert generated by build_security_alerts().

    alert_type identifies the pattern (e.g. 'login_failure_spike').
    severity is 'high' when the count exceeds 2× the configured threshold,
    'medium' otherwise.
    context carries pattern-specific fields (username, IP, etc.).
    """

    alert_type: str
    severity: str
    count: int
    window_minutes: int
    first_seen: datetime
    last_seen: datetime
    context: dict[str, object]


class SecurityAlertsOut(BaseModel):
    """Response body for GET /admin/security-alerts."""

    generated_at: datetime
    window_minutes: int
    alerts: list[SecurityAlertOut]


class AdminActionOut(BaseModel):
    """Response body for admin operations that target a user account."""

    status: str
    username: str
    refresh_token_version: int


class CleanupOut(BaseModel):
    """Response body for POST /admin/maintenance/cleanup."""

    status: str
    ran_at: datetime
    revoked_tokens_deleted: int
    auth_failure_logs_deleted: int
    login_attempts_deleted: int
    password_reset_tokens_deleted: int


class PasswordResetRequestIn(BaseModel):
    """Request body for POST /password-reset/request."""

    username: Annotated[str, StringConstraints(min_length=1, max_length=64)]


class PasswordResetRequestOut(BaseModel):
    """Response body for POST /password-reset/request.

    reset_token is included in the response because this project has no email
    integration. In production this field would be omitted and the token
    delivered out-of-band.
    """

    status: str
    message: str
    reset_token: Optional[str] = None


class PasswordResetConfirmIn(BaseModel):
    """Request body for POST /password-reset/confirm."""

    token: Annotated[str, StringConstraints(min_length=20, max_length=256)]
    new_password: Annotated[str, StringConstraints(min_length=6, max_length=256)]


class MfaCodeIn(BaseModel):
    """Request body for MFA enable/disable and MFA-gated login.

    All TOTP codes are exactly 6 decimal digits as specified by RFC 6238.
    """

    code: Annotated[str, StringConstraints(min_length=6, max_length=6)]


class MfaSetupOut(BaseModel):
    """Response body for POST /admin/mfa/setup.

    provisioning_uri follows the Key URI format (otpauth://) accepted by
    authenticator apps such as Google Authenticator and Authy.
    """

    status: str
    secret: str
    provisioning_uri: str


class APIKeyCreateIn(BaseModel):
    """Request body for POST /admin/api-keys.

    expires_minutes is optional; omitting it creates a non-expiring key.
    scopes is optional; omitting it defaults to ['data:read'] inside create_api_key_record.
    """

    name: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    expires_minutes: Optional[int] = None
    scopes: Optional[list[str]] = None


class APIKeyRotateIn(BaseModel):
    """Request body for POST /admin/api-keys/{key_id}/rotate.

    All fields are optional; omitting name uses '<old_name>-rotated',
    omitting scopes carries the old key's scopes over to the replacement.
    """

    name: Optional[Annotated[str, StringConstraints(min_length=1, max_length=128)]] = None
    expires_minutes: Optional[int] = None
    scopes: Optional[list[str]] = None


class APIKeyOut(BaseModel):
    """Metadata for an existing API key, safe to return to the admin.

    The raw key is never stored or returned after creation. key_prefix allows
    admins to identify which key is which without exposing the full secret.
    """

    id: int
    name: str
    key_prefix: str
    scopes: list[str]
    is_active: bool
    created_by: str
    created_at: datetime
    last_used_at: Optional[datetime]
    rotated_from_id: Optional[int]
    expires_at: Optional[datetime]


class APIKeyCreateOut(BaseModel):
    """Response body for key creation and rotation endpoints.

    api_key contains the raw key value and is only returned once — the server
    never stores it and cannot recover it after this response.
    """

    status: str
    api_key: str
    metadata: APIKeyOut


def api_key_to_out(record: APIKey) -> APIKeyOut:
    """Convert an APIKey ORM row to the APIKeyOut response model.

    Deserialises the JSON scopes column and maps all fields to the response
    schema, keeping route handlers free of this mapping logic.
    """
    return APIKeyOut(
        id=record.id,
        name=record.name,
        key_prefix=record.key_prefix,
        scopes=_deserialize_api_key_scopes(record.scopes),
        is_active=record.is_active,
        created_by=record.created_by,
        created_at=record.created_at,
        last_used_at=record.last_used_at,
        rotated_from_id=record.rotated_from_id,
        expires_at=record.expires_at,
    )


# ---------------------------------------------------------------------------
# Application factory helpers
# ---------------------------------------------------------------------------

def _load_allowed_origins() -> list[str]:
    """Parse the ALLOWED_ORIGINS environment variable into a list of origin strings.

    Accepts a comma-separated list. Trailing slashes and leading/trailing whitespace
    are stripped. Duplicate origins are deduplicated while preserving order.
    Defaults to http://localhost:3000 if the variable is not set.
    """
    raw = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000")
    origins: list[str] = []
    seen: set[str] = set()
    for part in raw.split(","):
        origin = part.strip().rstrip("/")
        if origin and origin not in seen:
            origins.append(origin)
            seen.add(origin)
    return origins


def startup_checks() -> None:
    """Run all startup-time checks and initialisation before the server accepts requests.

    Executed once during the lifespan startup phase:
    1. Load or generate the Ed25519 signing key and derive the JWKS KID.
    2. Validate that all required database tables exist; abort if any are missing.
    3. Seed API keys from environment variables so the application is usable
       immediately after deployment without a separate setup step.
    """
    load_or_generate_signing_key()
    _validate_required_schema()
    db = SessionLocal()
    try:
        seed_api_keys_from_env(db=db)
    finally:
        db.close()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """FastAPI lifespan context manager — runs startup_checks before yield.

    FastAPI calls this at application startup. Anything before `yield` runs
    on startup; anything after would run on shutdown (nothing needed here).
    Using lifespan rather than @app.on_event is the recommended pattern for
    FastAPI 0.93+ and avoids deprecation warnings.
    """
    startup_checks()
    yield


# ---------------------------------------------------------------------------
# Application instance and middleware
# ---------------------------------------------------------------------------

app = FastAPI(title="Secure API Capstone Starter", lifespan=lifespan)

# Register the sub-routers for JWKS, token exchange, and workload identity.
app.include_router(jwks_module.router)
app.include_router(broker_router)
app.include_router(workload_router)

# CORS middleware restricts which origins browsers are allowed to make
# cross-origin requests from. The X-API-Key header is explicitly listed
# so browser clients can send it in preflight OPTIONS requests.
app.add_middleware(
    CORSMiddleware,
    allow_origins=_load_allowed_origins(),
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Request-ID"],
    expose_headers=["X-Request-ID", "Retry-After"],
    allow_credentials=False,
)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_request: Request, exc: RequestValidationError):
    """Return a 400 response with Pydantic validation error details.

    FastAPI's default behaviour for validation errors produces a 422. This
    handler overrides that to 400, which is more conventional for malformed
    request bodies (422 Unprocessable Entity is intended for semantic errors,
    not structural ones).
    """
    return JSONResponse(status_code=400, content={"detail": exc.errors()})


@app.middleware("http")
async def request_context_and_logging_middleware(request: Request, call_next):
    """Attach a request ID to each request and emit a structured JSON log line.

    The request ID is read from the X-Request-ID header if provided by the
    caller (useful for correlating client-side logs with server logs), or
    generated as a UUID4 otherwise.

    The ID is stored in the request_id_ctx ContextVar so that any code
    running within this async task can retrieve it via get_request_id()
    without needing to pass the request object through the call stack.

    Timing is measured with time.perf_counter() for sub-millisecond resolution.
    The X-Request-ID header is echoed back to the caller in the response.

    If an unexpected exception propagates out of the handler, the error is
    logged before re-raising so the operator has full context.
    """
    request_id = request.headers.get("X-Request-ID") or str(uuid4())
    token = request_id_ctx.set(request_id)
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        increment_metric("http_request_errors", 1)
        log_event(
            logger=ops_logger,
            level=logging.ERROR,
            event="http_request_error",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            client_ip=request.client.host if request.client else "unknown",
            duration_ms=round((time.perf_counter() - started) * 1000, 2),
        )
        raise
    finally:
        # Always reset the ContextVar so the slot is not leaked to the next
        # request that reuses this async task.
        request_id_ctx.reset(token)

    increment_metric("http_requests_total", 1)
    if 400 <= response.status_code < 500:
        increment_metric("http_4xx_responses", 1)
    if response.status_code >= 500:
        increment_metric("http_5xx_responses", 1)

    response.headers["X-Request-ID"] = request_id
    log_event(
        logger=ops_logger,
        level=logging.INFO,
        event="http_request",
        request_id=request_id,
        method=request.method,
        path=request.url.path,
        status_code=response.status_code,
        client_ip=request.client.host if request.client else "unknown",
        duration_ms=round((time.perf_counter() - started) * 1000, 2),
    )
    return response


# ---------------------------------------------------------------------------
# Schema and readiness helpers
# ---------------------------------------------------------------------------

def _validate_required_schema() -> None:
    """Abort startup if any required database tables are missing.

    Uses SQLAlchemy's inspect() to retrieve the current table list from the
    live database and compares it against the known-required set. If any
    tables are absent, a RuntimeError is raised with a clear message directing
    the operator to run `alembic upgrade head`.

    This guard prevents the application from starting in a partially-migrated
    state where requests would fail with opaque database errors.
    """
    with engine.connect() as conn:
        table_names = set(inspect(conn).get_table_names())
    required = {
        "users",
        "login_attempts",
        "auth_failure_logs",
        "audit_logs",
        "revoked_tokens",
        "api_keys",
        "password_reset_tokens",
    }
    missing = sorted(required - table_names)
    if missing:
        raise RuntimeError(
            "Database schema is missing required tables: "
            f"{', '.join(missing)}. Run `alembic upgrade head`."
        )


def check_readiness() -> tuple[bool, str]:
    """Perform a live readiness probe: validate schema and execute a trivial query.

    Returns (True, "ready") if the database is reachable and fully migrated,
    or (False, error_message) if either check fails. Used by GET /readyz.
    """
    try:
        _validate_required_schema()
        with SessionLocal() as db:
            db.execute(select(1))
        return True, "ready"
    except Exception as exc:
        return False, str(exc)


# ---------------------------------------------------------------------------
# Health and observability endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    """Minimal liveness probe — always returns 200 if the process is running.

    Load balancers and container runtimes use this to decide whether to restart
    or route traffic to the instance. It does not check database connectivity.
    """
    return {"status": "ok"}


@app.get("/healthz")
def healthz():
    """Alias for /health, provided for compatibility with Kubernetes conventions."""
    return {"status": "ok"}


@app.get("/readyz")
def readyz():
    """Kubernetes-style readiness probe — returns 503 until the DB is ready.

    Unlike /health, this endpoint checks whether the application is fully
    initialised and able to serve traffic. It validates the database schema
    and executes a ping query. Container orchestrators use this to delay
    sending traffic until the pod is ready.
    """
    is_ready, detail = check_readiness()
    if not is_ready:
        return JSONResponse(status_code=503, content={"status": "not_ready", "detail": detail})
    return {"status": "ready"}


@app.get("/metrics")
def get_metrics():
    """Return in-memory performance counters and uptime information.

    Reads all metrics counters under the metrics_lock to produce a consistent
    snapshot — partial reads are not possible even under concurrent writes.
    Also exposes the active JWT backend name so operators can verify which
    library is in use without inspecting environment variables.
    """
    with metrics_lock:
        counters = dict(metrics)
    return {
        "uptime_seconds": int((utcnow() - app_start_time).total_seconds()),
        "jwt_backend": get_jwt_backend_name(),
        "counters": counters,
    }


# ---------------------------------------------------------------------------
# Authentication endpoints
# ---------------------------------------------------------------------------

@app.post("/register", status_code=201)
def register(data: RegisterIn, request: Request, db: Session = Depends(get_db)):
    """Register a new user account.

    All newly registered accounts receive the 'user' role. Admin accounts must
    be promoted separately to prevent self-service privilege escalation.

    bcrypt silently truncates passwords longer than 72 bytes; the explicit
    length check raises a 400 error instead so the caller is not surprised by
    a credential that appears to work but is stored truncated.

    Duplicate username attempts are recorded in the audit log as 'failed_duplicate'
    before raising 400 so admins can detect registration spam.

    Returns 201 with the new user's id, username, and role on success.
    """
    if len(data.password.encode("utf-8")) > 72:
        raise HTTPException(
            status_code=400,
            detail="Password too long for bcrypt (max 72 bytes)",
        )

    existing = get_user_by_username(db, data.username)
    if existing:
        _write_audit_log(
            db=db,
            action="register",
            status="failed_duplicate",
            request=request,
            actor_username=data.username,
            target_username=data.username,
            commit=True,
        )
        raise HTTPException(status_code=400, detail="Username already exists")

    user = User(
        username=data.username,
        password_hash=hash_password(data.password),
        role="user",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    _write_audit_log(
        db=db,
        action="register",
        status="success",
        request=request,
        actor_username=user.username,
        actor_role=user.role,
        target_username=user.username,
        commit=True,
    )
    return {"id": user.id, "username": user.username, "role": user.role}


@app.post("/login", response_model=TokenOut)
def login(data: LoginIn, request: Request, db: Session = Depends(get_db)):
    """Authenticate a user and issue an access + refresh token pair.

    The login flow enforces several security controls in order:

    1. Cleanup: expired rows are pruned at most once per CLEANUP_INTERVAL_MINUTES
       to keep rate-limiting tables small without a separate background worker.

    2. Rate limiting: per-IP sliding window check. Exceeding the threshold raises
       429 with a Retry-After header indicating when the window resets.

    3. Lockout check: if the account is locked (too many previous failures), the
       current attempt is also recorded as a failure before rejecting with 429.
       This prevents an attacker from using the locked state to avoid leaving
       failure traces.

    4. Credential check: wrong username or password increments the failure counter
       and, if the threshold is reached, locks the account. A generic 401 is
       returned to avoid username enumeration.

    5. MFA check (admin accounts only): if the admin has MFA enabled, a valid
       TOTP code must accompany the request. A missing or wrong code counts as a
       login failure and may trigger lockout.

    On success, the lockout state is cleared, an access token and refresh token
    are issued, and the event is written to the audit log.
    """
    # Run periodic cleanup on the login path to avoid a separate cron job.
    run_cleanup_jobs(db=db, force=False)
    client_ip = _check_login_rate_limit(request=request, db=db, username=data.username)

    user = get_user_by_username(db, data.username)
    if user and _is_user_locked(user):
        # Record the attempt even when locked so the failure log reflects the
        # real number of attempts made during the lockout period.
        _register_auth_failure(
            user=user,
            db=db,
            username=data.username,
            ip_address=client_ip,
            reason="account_locked",
        )
        _write_audit_log(
            db=db,
            action="login",
            status="failed_locked",
            request=request,
            actor_username=data.username,
            actor_role=user.role,
            target_username=data.username,
            commit=True,
        )
        remaining_seconds = max(1, int((user.locked_until - utcnow_naive()).total_seconds()))
        raise HTTPException(
            status_code=429,
            headers={"Retry-After": str(remaining_seconds)},
            detail="Account locked. Try again later.",
        )

    # A single generic error message prevents username enumeration: the caller
    # cannot distinguish "user does not exist" from "wrong password".
    if not user or not verify_password(data.password, user.password_hash):
        _register_auth_failure(
            user=user,
            db=db,
            username=data.username,
            ip_address=client_ip,
            reason="invalid_credentials",
        )
        _write_audit_log(
            db=db,
            action="login",
            status="failed_invalid_credentials",
            request=request,
            actor_username=data.username,
            target_username=data.username,
            commit=True,
        )
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # MFA is enforced only for admin accounts that have completed the setup flow.
    if user.role == "admin" and user.mfa_enabled:
        if not data.totp_code or not user.mfa_secret:
            _register_auth_failure(
                user=user,
                db=db,
                username=data.username,
                ip_address=client_ip,
                reason="missing_mfa_code",
            )
            _write_audit_log(
                db=db,
                action="login",
                status="failed_missing_mfa_code",
                request=request,
                actor_username=data.username,
                actor_role=user.role,
                target_username=data.username,
                commit=True,
            )
            raise HTTPException(status_code=401, detail="MFA code required")
        if not verify_totp_code(secret=user.mfa_secret, code=data.totp_code):
            _register_auth_failure(
                user=user,
                db=db,
                username=data.username,
                ip_address=client_ip,
                reason="invalid_mfa_code",
            )
            _write_audit_log(
                db=db,
                action="login",
                status="failed_invalid_mfa_code",
                request=request,
                actor_username=data.username,
                actor_role=user.role,
                target_username=data.username,
                commit=True,
            )
            raise HTTPException(status_code=401, detail="Invalid MFA code")

    # All checks passed: clear any residual lockout state and issue tokens.
    _reset_lock_state(user, db)
    access_token = create_access_token(subject=user.username)
    refresh_token = create_refresh_token(user=user)
    increment_metric("login_successes", 1)
    _write_audit_log(
        db=db,
        action="login",
        status="success",
        request=request,
        actor_username=user.username,
        actor_role=user.role,
        target_username=user.username,
        commit=True,
    )
    return TokenOut(access_token=access_token, refresh_token=refresh_token)


@app.post("/refresh", response_model=TokenOut)
def refresh_token(data: RefreshIn, request: Request, db: Session = Depends(get_db)):
    """Rotate a refresh token and issue a new access + refresh token pair.

    The incoming refresh token is decoded, its version claim is validated against
    the user's current refresh_token_version, and then immediately revoked by
    adding its JTI to the revoked_tokens table. The new tokens are issued only
    after the old token is revoked, enforcing single-use semantics.

    Version validation detects out-of-date tokens: if the user has logged out or
    an admin has forcibly revoked tokens, the version counter is incremented and
    any token with an older version is rejected.
    """
    payload = _decode_token(db=db, token=data.refresh_token, expected_type="refresh")

    username = payload["sub"]
    user = get_user_by_username(db, username)
    if not user:
        _write_audit_log(
            db=db,
            action="refresh_token",
            status="failed_invalid_user",
            request=request,
            actor_username=username,
            target_username=username,
            commit=True,
        )
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    _validate_refresh_token_version(payload=payload, user=user)

    # Revoke the consumed refresh token before issuing the replacement so that
    # a token intercepted in transit cannot be used to obtain additional tokens.
    _revoke_token(
        db=db,
        jti=payload["jti"],
        token_type="refresh",
        exp_value=payload["exp"],
    )

    new_access_token = create_access_token(subject=user.username)
    new_refresh_token = create_refresh_token(user=user)
    _write_audit_log(
        db=db,
        action="refresh_token",
        status="success",
        request=request,
        actor_username=user.username,
        actor_role=user.role,
        target_username=user.username,
        commit=True,
    )
    return TokenOut(access_token=new_access_token, refresh_token=new_refresh_token)


@app.post("/logout")
def logout(data: RefreshIn, request: Request, db: Session = Depends(get_db)):
    """Invalidate the user's refresh token and terminate the session.

    Decodes the refresh token, verifies the version claim, then adds the JTI to
    the revoked_tokens table. Subsequent /refresh attempts with the same token
    return 401, and the access token from this session will be rejected on the
    next get_current_user call that checks revocation.

    The refresh token (rather than the access token) is used for logout so that
    the server-side revocation record is tied to the longer-lived credential.
    """
    payload = _decode_token(db=db, token=data.refresh_token, expected_type="refresh")
    user = get_user_by_username(db, payload["sub"])
    if not user:
        _write_audit_log(
            db=db,
            action="logout",
            status="failed_invalid_user",
            request=request,
            actor_username=payload["sub"],
            target_username=payload["sub"],
            commit=True,
        )
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    _validate_refresh_token_version(payload=payload, user=user)
    _revoke_token(
        db=db,
        jti=payload["jti"],
        token_type="refresh",
        exp_value=payload["exp"],
    )
    _write_audit_log(
        db=db,
        action="logout",
        status="success",
        request=request,
        actor_username=user.username,
        actor_role=user.role,
        target_username=user.username,
        commit=True,
    )
    return {"status": "ok", "message": "Refresh token revoked"}


@app.post("/password-reset/request", response_model=PasswordResetRequestOut)
def password_reset_request(
    data: PasswordResetRequestIn, request: Request, db: Session = Depends(get_db)
):
    """Generate a single-use password reset token for the given username.

    If the username does not exist, the endpoint returns the same 200 response
    as for a valid account. This prevents username enumeration by ensuring an
    attacker cannot distinguish a registered from an unregistered account based
    on the response.

    The raw token is returned directly in the response because this project has
    no email integration. In a production system the token would be sent to the
    user's registered email address and omitted from the API response.
    """
    user = get_user_by_username(db, data.username)
    if not user:
        # Return a neutral response even for unknown usernames to prevent enumeration.
        _write_audit_log(
            db=db,
            action="password_reset_request",
            status="accepted_unknown_user",
            request=request,
            actor_username=data.username,
            target_username=data.username,
            commit=True,
        )
        return PasswordResetRequestOut(
            status="ok",
            message="If the account exists, a password reset token has been generated.",
        )

    raw_token = secrets.token_urlsafe(32)
    token_hash = _hash_reset_token(raw_token)
    expires_at = utcnow_naive() + timedelta(minutes=PASSWORD_RESET_TOKEN_EXPIRE_MINUTES)
    db.add(
        PasswordResetToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=expires_at,
        )
    )
    db.commit()
    _write_audit_log(
        db=db,
        action="password_reset_request",
        status="success",
        request=request,
        actor_username=user.username,
        actor_role=user.role,
        target_username=user.username,
        commit=True,
    )

    # Demo-only: return token directly since no email integration exists.
    return PasswordResetRequestOut(
        status="ok",
        message="Password reset token generated.",
        reset_token=raw_token,
    )


@app.post("/password-reset/confirm")
def password_reset_confirm(
    data: PasswordResetConfirmIn, request: Request, db: Session = Depends(get_db)
):
    """Consume a password reset token and update the user's password.

    Token claim uses a single atomic UPDATE statement rather than a SELECT
    followed by an UPDATE. The WHERE clause includes used_at IS NULL so that
    only the first concurrent request succeeds (rowcount=1); subsequent requests
    with the same token see rowcount=0 and are rejected. This prevents a race
    condition where two simultaneous requests could both read the token as unused
    and both proceed to reset the password.

    On success, the lockout state is cleared and refresh_token_version is
    incremented to invalidate all existing sessions, forcing a fresh login with
    the new password.
    """
    if len(data.new_password.encode("utf-8")) > 72:
        raise HTTPException(
            status_code=400,
            detail="Password too long for bcrypt (max 72 bytes)",
        )

    now = utcnow_naive()
    token_hash = _hash_reset_token(data.token)

    # Atomically mark the token as used. The WHERE clause's used_at IS NULL
    # condition ensures only one concurrent caller can claim the token.
    claim_result = db.execute(
        update(PasswordResetToken)
        .where(
            PasswordResetToken.token_hash == token_hash,
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.expires_at >= now,
        )
        .values(used_at=now)
    )
    db.flush()

    if claim_result.rowcount == 0:
        # Either the token does not exist, has already been used, or has expired.
        _write_audit_log(
            db=db,
            action="password_reset_confirm",
            status="failed_invalid_or_expired_token",
            request=request,
            commit=True,
        )
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

    # Retrieve the claimed token row to look up the associated user.
    reset_row = (
        db.execute(
            select(PasswordResetToken).where(PasswordResetToken.token_hash == token_hash)
        )
        .scalars()
        .first()
    )

    user = db.execute(select(User).where(User.id == reset_row.user_id)).scalars().first()
    if not user:
        _write_audit_log(
            db=db,
            action="password_reset_confirm",
            status="failed_invalid_user",
            request=request,
            commit=True,
        )
        raise HTTPException(status_code=400, detail="Invalid reset token user")

    user.password_hash = hash_password(data.new_password)
    # Clear lockout so a user locked out due to forgotten password can log in
    # immediately after resetting it.
    user.failed_login_attempts = 0
    user.locked_until = None
    # Increment version to invalidate all existing refresh tokens across all
    # devices, forcing a fresh login with the new password.
    user.refresh_token_version += 1
    db.commit()
    _write_audit_log(
        db=db,
        action="password_reset_confirm",
        status="success",
        request=request,
        actor_username=user.username,
        actor_role=user.role,
        target_username=user.username,
        commit=True,
    )
    return {"status": "ok", "message": "Password updated"}


# ---------------------------------------------------------------------------
# User-facing protected endpoints
# ---------------------------------------------------------------------------

@app.get("/profile", response_model=ProfileOut)
def profile(current_user: User = Depends(get_current_user)):
    """Return the authenticated user's own profile.

    Requires a valid access token. The response contains only non-sensitive
    fields: id, username, and role. Password hash and MFA secrets are never
    returned to the client.
    """
    return current_user


@app.get("/data")
def data(_auth=Depends(get_current_user_or_api_key_for_data)):
    """Return a protected data payload, accessible via JWT or API key.

    Accepts either a bearer JWT (any authenticated user) or an X-API-Key header
    where the key carries the 'data:read' scope. This endpoint demonstrates the
    dual-authentication path with scope-based API key authorisation.
    """
    return {"data": "Sensitive data payload"}


# ---------------------------------------------------------------------------
# Admin endpoints — all protected by require_admin
# ---------------------------------------------------------------------------

@app.get("/admin/users", response_model=list[UserOut])
def admin_users(current_admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """List all registered users in ascending ID order.

    The action is recorded in the audit log so administrators can see when
    user lists are accessed and by whom.
    """
    users = db.execute(select(User).order_by(User.id.asc())).scalars().all()
    _write_audit_log(
        db=db,
        action="admin_list_users",
        status="success",
        actor_username=current_admin.username,
        actor_role=current_admin.role,
        commit=True,
    )
    return users


@app.post("/admin/mfa/setup", response_model=MfaSetupOut, status_code=201)
def admin_mfa_setup(current_admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Generate a new TOTP secret for MFA setup and return the provisioning URI.

    The secret is stored in mfa_temp_secret and must be confirmed by calling
    POST /admin/mfa/enable with a valid TOTP code before MFA is actually active.
    This two-step flow prevents admins from locking themselves out by enabling
    MFA with a secret they cannot verify.

    If setup is called multiple times before confirmation, the previous
    mfa_temp_secret is simply overwritten.
    """
    secret = generate_totp_secret()
    current_admin.mfa_temp_secret = secret
    db.commit()
    _write_audit_log(
        db=db,
        action="admin_mfa_setup",
        status="success",
        actor_username=current_admin.username,
        actor_role=current_admin.role,
        target_username=current_admin.username,
        commit=True,
    )
    # Build the Key URI for QR-code display in authenticator apps.
    # Format: otpauth://totp/<issuer>:<account>?secret=...&issuer=...
    provisioning_uri = (
        f"otpauth://totp/{JWT_ISSUER}:{current_admin.username}"
        f"?secret={secret}&issuer={JWT_ISSUER}&algorithm=SHA1&digits=6&period=30"
    )
    return MfaSetupOut(status="ok", secret=secret, provisioning_uri=provisioning_uri)


@app.post("/admin/mfa/enable")
def admin_mfa_enable(
    data: MfaCodeIn,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Confirm a TOTP code and activate MFA for the admin account.

    Validates the code against mfa_temp_secret (set by /admin/mfa/setup).
    On success, mfa_secret is set from mfa_temp_secret, the temp secret is
    cleared, mfa_enabled is set to True, and refresh_token_version is
    incremented to force a fresh login with MFA on the next session.
    """
    if not current_admin.mfa_temp_secret:
        raise HTTPException(status_code=400, detail="MFA setup has not been initialized")
    if not verify_totp_code(secret=current_admin.mfa_temp_secret, code=data.code):
        raise HTTPException(status_code=401, detail="Invalid MFA code")

    # Promote temp secret to permanent and clear the staging field.
    current_admin.mfa_secret = current_admin.mfa_temp_secret
    current_admin.mfa_temp_secret = None
    current_admin.mfa_enabled = True
    # Invalidate existing sessions so the admin must re-authenticate with MFA.
    current_admin.refresh_token_version += 1
    db.commit()
    _write_audit_log(
        db=db,
        action="admin_mfa_enable",
        status="success",
        actor_username=current_admin.username,
        actor_role=current_admin.role,
        target_username=current_admin.username,
        commit=True,
    )
    return {"status": "ok", "message": "MFA enabled"}


@app.post("/admin/mfa/disable")
def admin_mfa_disable(
    data: MfaCodeIn,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Disable MFA for the admin account after verifying the current TOTP code.

    Requires a valid code from the currently active mfa_secret to prevent an
    attacker with a stolen session from disabling MFA without physical access
    to the authenticator device.

    On success, all MFA state is cleared and refresh_token_version is incremented
    to invalidate existing sessions.
    """
    if not current_admin.mfa_enabled or not current_admin.mfa_secret:
        raise HTTPException(status_code=400, detail="MFA is not enabled")
    if not verify_totp_code(secret=current_admin.mfa_secret, code=data.code):
        raise HTTPException(status_code=401, detail="Invalid MFA code")

    current_admin.mfa_enabled = False
    current_admin.mfa_secret = None
    current_admin.mfa_temp_secret = None
    current_admin.refresh_token_version += 1
    db.commit()
    _write_audit_log(
        db=db,
        action="admin_mfa_disable",
        status="success",
        actor_username=current_admin.username,
        actor_role=current_admin.role,
        target_username=current_admin.username,
        commit=True,
    )
    return {"status": "ok", "message": "MFA disabled"}


@app.get("/admin/api-keys", response_model=list[APIKeyOut])
def admin_list_api_keys(_admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Return metadata for all API keys in the system.

    The raw key values are never stored and are not included in the response.
    key_prefix allows administrators to identify individual keys without
    exposing the full secret.
    """
    keys = db.execute(select(APIKey).order_by(APIKey.id.asc())).scalars().all()
    return [api_key_to_out(key) for key in keys]


@app.post("/admin/api-keys", response_model=APIKeyCreateOut, status_code=201)
def admin_create_api_key(
    data: APIKeyCreateIn,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Create a new API key and return its raw value exactly once.

    The raw key is generated and hashed inside create_api_key_record; only the
    hash is persisted. The raw value is returned in this response and cannot be
    retrieved later — if it is lost, the key must be rotated.

    scopes defaults to ['data:read'] if not specified. expires_minutes is
    optional; omitting it creates a non-expiring key.
    """
    record, raw_key = create_api_key_record(
        db=db,
        name=data.name,
        created_by=current_admin.username,
        scopes=data.scopes,
        expires_minutes=data.expires_minutes,
    )
    _write_audit_log(
        db=db,
        action="admin_api_key_create",
        status="success",
        actor_username=current_admin.username,
        actor_role=current_admin.role,
        details={"key_id": record.id, "name": record.name},
        commit=True,
    )
    return APIKeyCreateOut(status="ok", api_key=raw_key, metadata=api_key_to_out(record))


@app.post("/admin/api-keys/{key_id}/rotate", response_model=APIKeyCreateOut)
def admin_rotate_api_key(
    key_id: int,
    data: APIKeyRotateIn,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Deactivate an existing API key and issue a replacement.

    The old key is marked is_active=False before the new key is created.
    rotated_from_id on the new key links back to the old one, preserving the
    rotation audit trail. The new key's name and scopes are taken from the
    request body, falling back to the old key's values when omitted.
    """
    existing = db.execute(select(APIKey).where(APIKey.id == key_id)).scalars().first()
    if not existing:
        raise HTTPException(status_code=404, detail="API key not found")
    if not existing.is_active:
        raise HTTPException(status_code=400, detail="API key is already inactive")

    # Deactivate the old key before creating the replacement.
    existing.is_active = False
    db.commit()
    new_name = data.name if data.name else f"{existing.name}-rotated"
    new_scopes = (
        data.scopes if data.scopes is not None else _deserialize_api_key_scopes(existing.scopes)
    )
    record, raw_key = create_api_key_record(
        db=db,
        name=new_name,
        created_by=current_admin.username,
        scopes=new_scopes,
        expires_minutes=data.expires_minutes,
        rotated_from_id=existing.id,
    )
    _write_audit_log(
        db=db,
        action="admin_api_key_rotate",
        status="success",
        actor_username=current_admin.username,
        actor_role=current_admin.role,
        details={"old_key_id": existing.id, "new_key_id": record.id},
        commit=True,
    )
    return APIKeyCreateOut(status="ok", api_key=raw_key, metadata=api_key_to_out(record))


@app.post("/admin/api-keys/{key_id}/revoke")
def admin_revoke_api_key(
    key_id: int,
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Deactivate an API key immediately, preventing further use.

    Unlike rotation, revocation does not create a replacement key. The endpoint
    is idempotent: revoking an already-inactive key returns 200 with status
    'already_inactive' rather than raising an error, so callers can safely
    retry in case of network failures.
    """
    existing = db.execute(select(APIKey).where(APIKey.id == key_id)).scalars().first()
    if not existing:
        raise HTTPException(status_code=404, detail="API key not found")
    if not existing.is_active:
        _write_audit_log(
            db=db,
            action="admin_api_key_revoke",
            status="already_inactive",
            actor_username=_admin.username,
            actor_role=_admin.role,
            details={"key_id": existing.id},
            commit=True,
        )
        return {"status": "ok", "message": "API key already inactive"}

    existing.is_active = False
    db.commit()
    _write_audit_log(
        db=db,
        action="admin_api_key_revoke",
        status="success",
        actor_username=_admin.username,
        actor_role=_admin.role,
        details={"key_id": existing.id},
        commit=True,
    )
    return {"status": "ok", "message": "API key revoked"}


@app.post("/admin/users/{username}/unlock")
def admin_unlock_user(
    username: str,
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Clear the lockout state and failure counter for a user account.

    Allows administrators to manually unlock accounts without waiting for the
    lockout timer to expire — useful when a legitimate user is locked out and
    needs immediate access.
    """
    user = get_user_by_username(db, username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()
    _write_audit_log(
        db=db,
        action="admin_unlock_user",
        status="success",
        actor_username=_admin.username,
        actor_role=_admin.role,
        target_username=user.username,
        commit=True,
    )

    return {"status": "ok", "message": f"User '{username}' unlocked"}


@app.get("/admin/auth-failures", response_model=AuthFailureLogPageOut)
def admin_auth_failures(
    page: int = 1,
    page_size: int = 50,
    username: Optional[str] = None,
    ip_address: Optional[str] = None,
    reason: Optional[str] = None,
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Return a paginated, filterable list of authentication failure log entries.

    Supports filtering by username, ip_address, and reason. All filter parameters
    are optional; omitting them returns all records. page_size is clamped to a
    maximum of 200 to prevent excessively large responses.

    Returns items in descending chronological order so the most recent failures
    appear first.
    """
    safe_page = max(1, page)
    safe_page_size = max(1, min(page_size, 200))
    conditions = []
    if username:
        conditions.append(AuthFailureLog.username == username)
    if ip_address:
        conditions.append(AuthFailureLog.ip_address == ip_address)
    if reason:
        conditions.append(AuthFailureLog.reason == reason)

    item_query = select(AuthFailureLog)
    count_query = select(func.count()).select_from(AuthFailureLog)
    if conditions:
        item_query = item_query.where(*conditions)
        count_query = count_query.where(*conditions)

    total = db.scalar(count_query) or 0
    offset = (safe_page - 1) * safe_page_size
    logs = db.execute(
        item_query.order_by(AuthFailureLog.created_at.desc(), AuthFailureLog.id.desc())
        .offset(offset)
        .limit(safe_page_size)
    )
    return AuthFailureLogPageOut(
        items=logs.scalars().all(),
        page=safe_page,
        page_size=safe_page_size,
        total=int(total),
    )


def build_security_alerts(
    db: Session,
    *,
    window_minutes: int,
    min_failed_logins: int,
    min_admin_denials: int,
) -> list[SecurityAlertOut]:
    """Query the database and return security alerts for any anomalous patterns.

    Two alert types are detected:

    login_failure_spike:
        Accounts with at least min_failed_logins authentication failures within
        the window. Severity is 'high' if count >= 2× the threshold, 'medium'
        otherwise. Counts only actionable failure reasons (wrong credentials, MFA
        failures, account locked) rather than all AuthFailureLog rows.

    admin_access_denied_spike:
        Principals with at least min_admin_denials denied admin access attempts
        within the window. Could indicate privilege escalation attempts by a
        compromised non-admin account.

    Results are sorted by descending count so the most severe alerts appear first.
    This function is extracted from the route handler so it can be tested directly
    without going through HTTP.
    """
    alerts: list[SecurityAlertOut] = []
    cutoff = utcnow_naive() - timedelta(minutes=window_minutes)

    # Aggregate auth failures by username, filtered to actionable reasons only.
    login_failure_rows = db.execute(
        select(
            AuthFailureLog.username,
            func.count(AuthFailureLog.id),
            func.min(AuthFailureLog.created_at),
            func.max(AuthFailureLog.created_at),
        )
        .where(
            AuthFailureLog.created_at >= cutoff,
            AuthFailureLog.username.is_not(None),
            AuthFailureLog.reason.in_(
                [
                    "invalid_credentials",
                    "missing_mfa_code",
                    "invalid_mfa_code",
                    "account_locked",
                ]
            ),
        )
        .group_by(AuthFailureLog.username)
        .having(func.count(AuthFailureLog.id) >= min_failed_logins)
    ).all()

    for username, count, first_seen, last_seen in login_failure_rows:
        severity = "high" if count >= (min_failed_logins * 2) else "medium"
        alerts.append(
            SecurityAlertOut(
                alert_type="login_failure_spike",
                severity=severity,
                count=int(count),
                window_minutes=window_minutes,
                first_seen=first_seen,
                last_seen=last_seen,
                context={"username": username},
            )
        )

    # Aggregate admin access denials by actor username.
    admin_denial_rows = db.execute(
        select(
            AuditLog.actor_username,
            func.count(AuditLog.id),
            func.min(AuditLog.created_at),
            func.max(AuditLog.created_at),
        )
        .where(
            AuditLog.created_at >= cutoff,
            AuditLog.action == "admin_access",
            AuditLog.status == "denied",
            AuditLog.actor_username.is_not(None),
        )
        .group_by(AuditLog.actor_username)
        .having(func.count(AuditLog.id) >= min_admin_denials)
    ).all()

    for actor_username, count, first_seen, last_seen in admin_denial_rows:
        severity = "high" if count >= (min_admin_denials * 2) else "medium"
        alerts.append(
            SecurityAlertOut(
                alert_type="admin_access_denied_spike",
                severity=severity,
                count=int(count),
                window_minutes=window_minutes,
                first_seen=first_seen,
                last_seen=last_seen,
                context={"actor_username": actor_username},
            )
        )

    # Sort by count descending so the most active anomalies appear first.
    alerts.sort(key=lambda item: item.count, reverse=True)
    return alerts


@app.get("/admin/audit-logs", response_model=AuditLogPageOut)
def admin_audit_logs(
    page: int = 1,
    page_size: int = 50,
    actor_username: Optional[str] = None,
    actor_role: Optional[str] = None,
    action: Optional[str] = None,
    status: Optional[str] = None,
    target_username: Optional[str] = None,
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Return a paginated, filterable view of the hash-chained audit log.

    All filter parameters are optional and combined with AND semantics.
    page_size is clamped to a maximum of 200 entries per page.
    Results are sorted by descending timestamp and descending id to handle
    the unlikely case of two records sharing the same timestamp.
    """
    safe_page = max(1, page)
    safe_page_size = max(1, min(page_size, 200))
    conditions = []
    if actor_username:
        conditions.append(AuditLog.actor_username == actor_username)
    if actor_role:
        conditions.append(AuditLog.actor_role == actor_role)
    if action:
        conditions.append(AuditLog.action == action)
    if status:
        conditions.append(AuditLog.status == status)
    if target_username:
        conditions.append(AuditLog.target_username == target_username)

    item_query = select(AuditLog)
    count_query = select(func.count()).select_from(AuditLog)
    if conditions:
        item_query = item_query.where(*conditions)
        count_query = count_query.where(*conditions)

    total = db.scalar(count_query) or 0
    offset = (safe_page - 1) * safe_page_size
    logs = db.execute(
        item_query.order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .offset(offset)
        .limit(safe_page_size)
    )
    return AuditLogPageOut(
        items=logs.scalars().all(),
        page=safe_page,
        page_size=safe_page_size,
        total=int(total),
    )


@app.get("/admin/audit-logs/verify", dependencies=[Depends(require_admin)])
def verify_audit_chain(db: Session = Depends(get_db)):
    """Walk the entire audit log chain and verify every hash link.

    Starting from the genesis sentinel ("0" * 64), each record's prev_hash
    must equal the previous record's record_hash, and the record_hash itself
    must match a fresh recomputation over all significant fields. Any mismatch
    indicates that a record has been modified or the chain order has been altered.

    Returns {"ok": True, "records": N, "chain_valid": True} if the full chain
    is intact, or {"ok": False, "first_broken_id": id} at the first broken link.
    This endpoint provides tamper evidence: a clean verification result confirms
    that no rows have been modified since insertion.
    """
    prev_hash = "0" * 64
    count = 0
    rows = db.execute(select(AuditLog).order_by(AuditLog.id)).scalars()
    for row in rows:
        # Normalise prev_hash: the genesis record stores NULL, treated as the
        # "0" * 64 sentinel for comparison purposes.
        stored_prev = row.prev_hash or "0" * 64
        if stored_prev != prev_hash:
            return {
                "ok": False,
                "records": count,
                "chain_valid": False,
                "first_broken_id": row.id,
            }
        ts_str = (
            row.created_at.isoformat()
            if isinstance(row.created_at, datetime)
            else str(row.created_at)
        )
        expected = _compute_record_hash(
            prev_hash,
            ts_str,
            row.action,
            row.actor_username or "",
            row.target_username or "",
            row.status,
        )
        if expected != row.record_hash:
            return {
                "ok": False,
                "records": count,
                "chain_valid": False,
                "first_broken_id": row.id,
            }
        prev_hash = row.record_hash
        count += 1
    return {"ok": True, "records": count, "chain_valid": True}


@app.post("/admin/service-registry", dependencies=[Depends(require_admin)], status_code=201)
def create_service_entry(
    body: ServiceRegistryCreate,
    db: Session = Depends(get_db),
):
    """Register a new downstream service in the token-exchange service registry.

    Each service is identified by a unique audience URI. allowed_callers is
    stored as a JSON array so it can be queried efficiently without a join table.
    Raises 409 if the audience is already registered to prevent accidental
    overwrites of existing entries.
    """
    if db.query(ServiceRegistry).filter_by(audience=body.audience).first():
        raise HTTPException(409, detail="audience_already_registered")
    entry = ServiceRegistry(
        service_id=body.service_id,
        audience=body.audience,
        allowed_callers=json.dumps(body.allowed_callers),
    )
    db.add(entry)
    db.commit()
    return {"id": entry.id, "service_id": entry.service_id}


@app.get("/admin/service-registry", dependencies=[Depends(require_admin)])
def list_service_entries(db: Session = Depends(get_db)):
    """Return all entries in the service registry with their decoded allowed_callers lists."""
    rows = db.query(ServiceRegistry).all()
    return [
        {
            "id": r.id,
            "service_id": r.service_id,
            "audience": r.audience,
            "allowed_callers": json.loads(r.allowed_callers),
            "enabled": r.enabled,
        }
        for r in rows
    ]


@app.get("/admin/policy/rules", dependencies=[Depends(require_admin)])
def get_policy_rules():
    """Return the currently loaded YAML policy rules and their count.

    The rules are read directly from the module-level _rules list, which
    reflects the most recent SIGHUP reload. Useful for verifying that a policy
    change has taken effect without restarting the application.
    """
    from app.policy import _rules

    return {"count": len(_rules), "rules": _rules}


@app.get("/admin/security-alerts", response_model=SecurityAlertsOut)
def admin_security_alerts(
    window_minutes: int = ALERT_DEFAULT_WINDOW_MINUTES,
    min_failed_logins: int = ALERT_DEFAULT_MIN_FAILED_LOGINS,
    min_admin_denials: int = ALERT_DEFAULT_MIN_ADMIN_DENIALS,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Query and return real-time security alerts based on recent event patterns.

    All three query parameters override the environment-variable defaults,
    allowing the caller to adjust sensitivity per-request. Values are clamped
    to safe ranges (window 1–1440 minutes; counts at least 1) before use.

    The query and its parameters are written to the audit log so administrators
    can see when alerts were checked and with what thresholds.
    """
    safe_window = max(1, min(window_minutes, 1440))
    safe_failed_logins = max(1, min_failed_logins)
    safe_admin_denials = max(1, min_admin_denials)
    alerts = build_security_alerts(
        db=db,
        window_minutes=safe_window,
        min_failed_logins=safe_failed_logins,
        min_admin_denials=safe_admin_denials,
    )
    _write_audit_log(
        db=db,
        action="admin_security_alerts_view",
        status="success",
        actor_username=current_admin.username,
        actor_role=current_admin.role,
        details={
            "window_minutes": safe_window,
            "min_failed_logins": safe_failed_logins,
            "min_admin_denials": safe_admin_denials,
            "alerts_returned": len(alerts),
        },
        commit=True,
    )
    return SecurityAlertsOut(
        generated_at=utcnow_naive(),
        window_minutes=safe_window,
        alerts=alerts,
    )


@app.post("/admin/users/{username}/revoke-refresh-tokens", response_model=AdminActionOut)
def admin_revoke_refresh_tokens(
    username: str,
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Increment a user's refresh_token_version to invalidate all current refresh tokens.

    Any refresh token carrying a version less than the new value is immediately
    rejected by _validate_refresh_token_version. This provides an admin-level
    kill switch for a user's sessions without requiring individual token revocations.

    The new refresh_token_version is returned in the response so the admin can
    confirm the version was incremented.
    """
    user = get_user_by_username(db, username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.refresh_token_version += 1
    db.commit()
    db.refresh(user)
    _write_audit_log(
        db=db,
        action="admin_revoke_refresh_tokens",
        status="success",
        actor_username=_admin.username,
        actor_role=_admin.role,
        target_username=user.username,
        details={"refresh_token_version": user.refresh_token_version},
        commit=True,
    )

    return AdminActionOut(
        status="ok",
        username=user.username,
        refresh_token_version=user.refresh_token_version,
    )


@app.post("/admin/maintenance/cleanup", response_model=CleanupOut)
def admin_cleanup_maintenance(
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Run the expired-row cleanup job immediately, bypassing the interval throttle.

    Normally cleanup runs at most once per CLEANUP_INTERVAL_MINUTES triggered
    by login requests. This endpoint forces a run regardless of the last
    execution time (force=True), useful after bulk operations that generate many
    rows that are immediately eligible for deletion.

    Returns the count of rows deleted from each table so the admin can see the
    impact of the cleanup.
    """
    result = run_cleanup_jobs(db=db, force=True)
    _write_audit_log(
        db=db,
        action="admin_cleanup_maintenance",
        status=result.get("status", "ok"),
        actor_username=_admin.username,
        actor_role=_admin.role,
        details={
            "revoked_tokens_deleted": result.get("revoked_tokens_deleted", 0),
            "auth_failure_logs_deleted": result.get("auth_failure_logs_deleted", 0),
            "login_attempts_deleted": result.get("login_attempts_deleted", 0),
            "password_reset_tokens_deleted": result.get("password_reset_tokens_deleted", 0),
        },
        commit=True,
    )
    return CleanupOut(**result)
