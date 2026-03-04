import logging
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Annotated, Optional
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, ConfigDict, StringConstraints
from sqlalchemy import func, inspect, select
from sqlalchemy.orm import Session

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
from app.database import Base as _Base
from app.database import SessionLocal, engine, get_db, utcnow, utcnow_naive
from app.jwt_backend import get_jwt_backend_name
from app.models import (
    APIKey,
    AuditLog,
    AuthFailureLog,
    PasswordResetToken,
    User,
)
from app.security import (
    _check_login_rate_limit,
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

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
oauth2_scheme_optional = OAuth2PasswordBearer(tokenUrl="login", auto_error=False)

# Keep `app.main.Base` available for existing tests/tools that import metadata from main.
Base = _Base


def _decode_token(db: Session, token: str, expected_type: str) -> dict:
    return decode_token(
        token=token,
        expected_type=expected_type,
        is_token_revoked=lambda jti: _is_token_revoked(db, jti),
    )


def _validate_refresh_token_version(payload: dict, user: User) -> None:
    validate_refresh_token_version(payload=payload, user=user)


def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)) -> User:
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


def _authenticate_user_or_api_key(
    *,
    db: Session,
    token: Optional[str],
    x_api_key: Optional[str],
    required_scopes: Optional[set[str]] = None,
) -> Optional[User]:
    if x_api_key:
        api_key_record = get_valid_api_key_record(db=db, raw_key=x_api_key)
        if api_key_record:
            api_key_scopes = set(_deserialize_api_key_scopes(api_key_record.scopes))
            if required_scopes and not required_scopes.issubset(api_key_scopes):
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
    if current_user.role != "admin":
        increment_metric("admin_access_denied", 1)
        _write_audit_log(
            db=db,
            action="admin_access",
            status="denied",
            request=request,
            actor_username=current_user.username,
            actor_role=current_user.role,
            details={"path": request.url.path},
            commit=True,
        )
        raise HTTPException(status_code=403, detail="Forbidden")
    increment_metric("admin_access_granted", 1)
    return current_user


# -------------------------
# API models
# -------------------------
class RegisterIn(BaseModel):
    username: Annotated[str, StringConstraints(min_length=3, max_length=64)]
    password: Annotated[str, StringConstraints(min_length=6, max_length=256)]
    role: Optional[str] = None


class LoginIn(BaseModel):
    username: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    password: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    totp_code: Optional[Annotated[str, StringConstraints(min_length=6, max_length=6)]] = None


class TokenOut(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"


class RefreshIn(BaseModel):
    refresh_token: str


class ProfileOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    role: str


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    role: str


class AuthFailureLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: Optional[str]
    ip_address: str
    reason: str
    created_at: datetime


class AuthFailureLogPageOut(BaseModel):
    items: list[AuthFailureLogOut]
    page: int
    page_size: int
    total: int


class AuditLogOut(BaseModel):
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
    items: list[AuditLogOut]
    page: int
    page_size: int
    total: int


class SecurityAlertOut(BaseModel):
    alert_type: str
    severity: str
    count: int
    window_minutes: int
    first_seen: datetime
    last_seen: datetime
    context: dict[str, object]


class SecurityAlertsOut(BaseModel):
    generated_at: datetime
    window_minutes: int
    alerts: list[SecurityAlertOut]


class AdminActionOut(BaseModel):
    status: str
    username: str
    refresh_token_version: int


class CleanupOut(BaseModel):
    status: str
    ran_at: datetime
    revoked_tokens_deleted: int
    auth_failure_logs_deleted: int
    login_attempts_deleted: int
    password_reset_tokens_deleted: int


class PasswordResetRequestIn(BaseModel):
    username: Annotated[str, StringConstraints(min_length=1, max_length=64)]


class PasswordResetRequestOut(BaseModel):
    status: str
    message: str
    reset_token: Optional[str] = None


class PasswordResetConfirmIn(BaseModel):
    token: Annotated[str, StringConstraints(min_length=20, max_length=256)]
    new_password: Annotated[str, StringConstraints(min_length=6, max_length=256)]


class MfaCodeIn(BaseModel):
    code: Annotated[str, StringConstraints(min_length=6, max_length=6)]


class MfaSetupOut(BaseModel):
    status: str
    secret: str
    provisioning_uri: str


class APIKeyCreateIn(BaseModel):
    name: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    expires_minutes: Optional[int] = None
    scopes: Optional[list[str]] = None


class APIKeyRotateIn(BaseModel):
    name: Optional[Annotated[str, StringConstraints(min_length=1, max_length=128)]] = None
    expires_minutes: Optional[int] = None
    scopes: Optional[list[str]] = None


class APIKeyOut(BaseModel):
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
    status: str
    api_key: str
    metadata: APIKeyOut


def api_key_to_out(record: APIKey) -> APIKeyOut:
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


# -------------------------
# App
# -------------------------
def startup_checks() -> None:
    _validate_required_schema()
    db = SessionLocal()
    try:
        seed_api_keys_from_env(db=db)
    finally:
        db.close()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    startup_checks()
    yield


app = FastAPI(title="Secure API Capstone Starter", lifespan=lifespan)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=400, content={"detail": exc.errors()})


@app.middleware("http")
async def request_context_and_logging_middleware(request: Request, call_next):
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


def _validate_required_schema() -> None:
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
    try:
        _validate_required_schema()
        with SessionLocal() as db:
            db.execute(select(1))
        return True, "ready"
    except Exception as exc:
        return False, str(exc)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/readyz")
def readyz():
    is_ready, detail = check_readiness()
    if not is_ready:
        return JSONResponse(status_code=503, content={"status": "not_ready", "detail": detail})
    return {"status": "ready"}


@app.get("/metrics")
def get_metrics():
    with metrics_lock:
        counters = dict(metrics)
    return {
        "uptime_seconds": int((utcnow() - app_start_time).total_seconds()),
        "jwt_backend": get_jwt_backend_name(),
        "counters": counters,
    }


@app.post("/register", status_code=201)
def register(data: RegisterIn, request: Request, db: Session = Depends(get_db)):
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

    role = data.role if data.role in {"user", "admin"} else "user"

    user = User(
        username=data.username,
        password_hash=hash_password(data.password),
        role=role,
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
    run_cleanup_jobs(db=db, force=False)
    client_ip = _check_login_rate_limit(request=request, db=db, username=data.username)

    user = get_user_by_username(db, data.username)
    if user and _is_user_locked(user):
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
        raise HTTPException(status_code=403, detail="Account locked. Try again later.")

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
    user = get_user_by_username(db, data.username)
    if not user:
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

    # Demo-friendly: return token directly since no email integration exists.
    return PasswordResetRequestOut(
        status="ok",
        message="Password reset token generated.",
        reset_token=raw_token,
    )


@app.post("/password-reset/confirm")
def password_reset_confirm(
    data: PasswordResetConfirmIn, request: Request, db: Session = Depends(get_db)
):
    if len(data.new_password.encode("utf-8")) > 72:
        raise HTTPException(
            status_code=400,
            detail="Password too long for bcrypt (max 72 bytes)",
        )

    now = utcnow_naive()
    token_hash = _hash_reset_token(data.token)
    reset_row = (
        db.execute(
            select(PasswordResetToken).where(
                PasswordResetToken.token_hash == token_hash,
                PasswordResetToken.used_at.is_(None),
                PasswordResetToken.expires_at >= now,
            )
        )
        .scalars()
        .first()
    )
    if not reset_row:
        _write_audit_log(
            db=db,
            action="password_reset_confirm",
            status="failed_invalid_or_expired_token",
            request=request,
            commit=True,
        )
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

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
    user.failed_login_attempts = 0
    user.locked_until = None
    user.refresh_token_version += 1
    reset_row.used_at = now
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


@app.get("/profile", response_model=ProfileOut)
def profile(current_user: User = Depends(get_current_user)):
    return current_user


@app.get("/data")
def data(_auth=Depends(get_current_user_or_api_key_for_data)):
    return {"data": "Sensitive data payload"}


@app.get("/admin/users", response_model=list[UserOut])
def admin_users(current_admin: User = Depends(require_admin), db: Session = Depends(get_db)):
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


@app.post("/admin/mfa/setup", response_model=MfaSetupOut)
def admin_mfa_setup(current_admin: User = Depends(require_admin), db: Session = Depends(get_db)):
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
    if not current_admin.mfa_temp_secret:
        raise HTTPException(status_code=400, detail="MFA setup has not been initialized")
    if not verify_totp_code(secret=current_admin.mfa_temp_secret, code=data.code):
        raise HTTPException(status_code=401, detail="Invalid MFA code")

    current_admin.mfa_secret = current_admin.mfa_temp_secret
    current_admin.mfa_temp_secret = None
    current_admin.mfa_enabled = True
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
    keys = db.execute(select(APIKey).order_by(APIKey.id.asc())).scalars().all()
    return [api_key_to_out(key) for key in keys]


@app.post("/admin/api-keys", response_model=APIKeyCreateOut)
def admin_create_api_key(
    data: APIKeyCreateIn,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
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
    existing = db.execute(select(APIKey).where(APIKey.id == key_id)).scalars().first()
    if not existing:
        raise HTTPException(status_code=404, detail="API key not found")
    if not existing.is_active:
        raise HTTPException(status_code=400, detail="API key is already inactive")

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
    alerts: list[SecurityAlertOut] = []
    cutoff = utcnow_naive() - timedelta(minutes=window_minutes)

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


@app.get("/admin/security-alerts", response_model=SecurityAlertsOut)
def admin_security_alerts(
    window_minutes: int = 60,
    min_failed_logins: int = 5,
    min_admin_denials: int = 3,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
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
