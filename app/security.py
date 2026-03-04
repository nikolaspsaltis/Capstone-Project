import json
import logging
import os
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import Optional

from fastapi import HTTPException, Request, status
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.database import utcnow, utcnow_naive
from app.models import (
    AuditLog,
    AuthFailureLog,
    LoginAttempt,
    PasswordResetToken,
    RevokedToken,
    User,
)

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
auth_logger = logging.getLogger("capstone.auth")
ops_logger = logging.getLogger("capstone.ops")

# Login defense settings.
MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
LOCKOUT_MINUTES = int(os.getenv("LOCKOUT_MINUTES", "15"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
RATE_LIMIT_MAX_ATTEMPTS = int(os.getenv("RATE_LIMIT_MAX_ATTEMPTS", "10"))
AUTH_FAILURE_LOG_RETENTION_DAYS = int(os.getenv("AUTH_FAILURE_LOG_RETENTION_DAYS", "30"))
LOGIN_ATTEMPT_RETENTION_DAYS = int(os.getenv("LOGIN_ATTEMPT_RETENTION_DAYS", "7"))
CLEANUP_INTERVAL_MINUTES = int(os.getenv("CLEANUP_INTERVAL_MINUTES", "60"))

last_cleanup_run: Optional[datetime] = None
app_start_time = utcnow()
request_id_ctx: ContextVar[Optional[str]] = ContextVar("request_id", default=None)
metrics_lock = Lock()
metrics = {
    "http_requests_total": 0,
    "http_request_errors": 0,
    "http_4xx_responses": 0,
    "http_5xx_responses": 0,
    "login_failures": 0,
    "login_successes": 0,
    "lockouts": 0,
    "rate_limit_hits": 0,
    "jwt_auth_successes": 0,
    "api_key_auth_successes": 0,
    "admin_access_granted": 0,
    "admin_access_denied": 0,
    "audit_events_total": 0,
}


def get_request_id() -> Optional[str]:
    return request_id_ctx.get()


def log_event(logger: logging.Logger, level: int, event: str, **fields) -> None:
    payload = {
        "ts": utcnow().isoformat(),
        "level": logging.getLevelName(level),
        "event": event,
        **fields,
    }
    logger.log(level, json.dumps(payload, default=str))


def increment_metric(name: str, amount: int = 1) -> None:
    with metrics_lock:
        metrics[name] = metrics.get(name, 0) + amount


def _extract_client_ip(request: Optional[Request]) -> str:
    if request and request.client and request.client.host:
        return request.client.host
    return "unknown"


def _write_audit_log(
    db: Session,
    *,
    action: str,
    status: str,
    request: Optional[Request] = None,
    actor_username: Optional[str] = None,
    actor_role: Optional[str] = None,
    target_username: Optional[str] = None,
    details: Optional[dict[str, object]] = None,
    commit: bool = False,
) -> None:
    detail_payload = json.dumps(details, sort_keys=True) if details is not None else None
    db.add(
        AuditLog(
            actor_username=actor_username,
            actor_role=actor_role,
            action=action,
            status=status,
            target_username=target_username,
            ip_address=_extract_client_ip(request),
            details=detail_payload,
        )
    )
    increment_metric("audit_events_total", 1)
    if commit:
        db.commit()


def _record_auth_failure(
    db: Session, username: Optional[str], ip_address: str, reason: str
) -> None:
    increment_metric("login_failures", 1)
    log_event(
        logger=auth_logger,
        level=logging.WARNING,
        event="auth_failure",
        username=username,
        ip_address=ip_address,
        reason=reason,
        request_id=get_request_id(),
    )
    db.add(AuthFailureLog(username=username, ip_address=ip_address, reason=reason))


def _check_login_rate_limit(request: Request, db: Session, username: str) -> str:
    client_ip = _extract_client_ip(request)
    now = utcnow_naive()
    cutoff = now - timedelta(seconds=RATE_LIMIT_WINDOW_SECONDS)

    db.add(LoginAttempt(ip_address=client_ip, created_at=now))
    db.execute(delete(LoginAttempt).where(LoginAttempt.created_at < cutoff))
    db.commit()

    attempt_count = db.scalar(
        select(func.count())
        .select_from(LoginAttempt)
        .where(LoginAttempt.ip_address == client_ip, LoginAttempt.created_at >= cutoff)
    )

    if attempt_count and attempt_count > RATE_LIMIT_MAX_ATTEMPTS:
        increment_metric("rate_limit_hits", 1)
        _write_audit_log(
            db=db,
            action="login",
            status="rate_limited",
            request=request,
            actor_username=username,
            target_username=username,
            details={"reason": "rate_limit"},
            commit=True,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Too many login attempts from this IP. Try again later.",
        )

    return client_ip


def _normalize_rowcount(rowcount: Optional[int]) -> int:
    return rowcount if rowcount and rowcount > 0 else 0


def run_cleanup_jobs(db: Session, force: bool = False) -> dict:
    global last_cleanup_run

    now = utcnow_naive()
    if (
        not force
        and last_cleanup_run is not None
        and now - last_cleanup_run < timedelta(minutes=CLEANUP_INTERVAL_MINUTES)
    ):
        return {
            "status": "skipped",
            "ran_at": now,
            "revoked_tokens_deleted": 0,
            "auth_failure_logs_deleted": 0,
            "login_attempts_deleted": 0,
            "password_reset_tokens_deleted": 0,
        }

    revoked_deleted = _normalize_rowcount(
        db.execute(delete(RevokedToken).where(RevokedToken.expires_at < now)).rowcount
    )
    auth_cutoff = now - timedelta(days=AUTH_FAILURE_LOG_RETENTION_DAYS)
    auth_logs_deleted = _normalize_rowcount(
        db.execute(delete(AuthFailureLog).where(AuthFailureLog.created_at < auth_cutoff)).rowcount
    )
    login_cutoff = now - timedelta(days=LOGIN_ATTEMPT_RETENTION_DAYS)
    login_attempts_deleted = _normalize_rowcount(
        db.execute(delete(LoginAttempt).where(LoginAttempt.created_at < login_cutoff)).rowcount
    )
    password_reset_tokens_deleted = _normalize_rowcount(
        db.execute(delete(PasswordResetToken).where(PasswordResetToken.expires_at < now)).rowcount
    )

    db.commit()
    last_cleanup_run = now
    return {
        "status": "ok",
        "ran_at": now,
        "revoked_tokens_deleted": revoked_deleted,
        "auth_failure_logs_deleted": auth_logs_deleted,
        "login_attempts_deleted": login_attempts_deleted,
        "password_reset_tokens_deleted": password_reset_tokens_deleted,
    }


def _is_user_locked(user: User) -> bool:
    return user.locked_until is not None and utcnow_naive() < user.locked_until


def _register_auth_failure(
    user: Optional[User],
    db: Session,
    username: str,
    ip_address: str,
    reason: str,
) -> None:
    _record_auth_failure(db=db, username=username, ip_address=ip_address, reason=reason)

    if user is not None:
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= MAX_LOGIN_ATTEMPTS:
            increment_metric("lockouts", 1)
            user.locked_until = utcnow_naive() + timedelta(minutes=LOCKOUT_MINUTES)
            user.failed_login_attempts = 0

    db.commit()


def _reset_lock_state(user: User, db: Session) -> None:
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()


def _is_token_revoked(db: Session, jti: str) -> bool:
    token = db.execute(select(RevokedToken).where(RevokedToken.jti == jti)).scalars().first()
    return token is not None


def _revoke_token(db: Session, jti: str, token_type: str, exp_value: int) -> None:
    existing = db.execute(select(RevokedToken).where(RevokedToken.jti == jti)).scalars().first()
    if existing:
        return

    expires_at = datetime.fromtimestamp(exp_value, tz=timezone.utc).replace(tzinfo=None)
    db.add(RevokedToken(jti=jti, token_type=token_type, expires_at=expires_at))
    db.commit()
