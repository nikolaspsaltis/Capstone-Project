"""
Security and observability module.

Provides:
- Thread-safe in-memory metrics counters
- Structured JSON logging with per-request IDs
- Per-IP login rate limiting
- Per-account login lockout
- Hash-chained audit log writes
- Token revocation helpers
- Periodic cleanup of expired database rows
"""

import hashlib
import json
import logging
import os
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
from math import ceil
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

# ---------------------------------------------------------------------------
# Login defence configuration — all thresholds are overridable via env vars
# so CI, staging, and production can use different values without code changes.
# ---------------------------------------------------------------------------
MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
LOCKOUT_MINUTES = int(os.getenv("LOCKOUT_MINUTES", "15"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
RATE_LIMIT_MAX_ATTEMPTS = int(os.getenv("RATE_LIMIT_MAX_ATTEMPTS", "10"))
AUTH_FAILURE_LOG_RETENTION_DAYS = int(os.getenv("AUTH_FAILURE_LOG_RETENTION_DAYS", "30"))
LOGIN_ATTEMPT_RETENTION_DAYS = int(os.getenv("LOGIN_ATTEMPT_RETENTION_DAYS", "7"))
CLEANUP_INTERVAL_MINUTES = int(os.getenv("CLEANUP_INTERVAL_MINUTES", "60"))

# Timestamp of the last cleanup run. Used to throttle cleanup to once per
# CLEANUP_INTERVAL_MINUTES rather than running on every request.
last_cleanup_run: Optional[datetime] = None
app_start_time = utcnow()

# ContextVar stores the request ID for the current async task. Because FastAPI
# can handle multiple requests concurrently, a thread-local would not work here.
request_id_ctx: ContextVar[Optional[str]] = ContextVar("request_id", default=None)

# metrics is a plain dictionary protected by a threading Lock. All updates go
# through increment_metric() which acquires the lock, so reads of individual
# counters from the /metrics endpoint are always consistent.
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
    """Return the request ID for the current async context, or None outside a request."""
    return request_id_ctx.get()


def log_event(logger: logging.Logger, level: int, event: str, **fields) -> None:
    """Emit a structured JSON log line with a UTC timestamp and event name.

    All extra keyword arguments are included as fields in the JSON object.
    The default=str serialiser handles datetime and other non-JSON types.
    """
    payload = {
        "ts": utcnow().isoformat(),
        "level": logging.getLevelName(level),
        "event": event,
        **fields,
    }
    logger.log(level, json.dumps(payload, default=str))


def increment_metric(name: str, amount: int = 1) -> None:
    """Increment a named counter in the metrics dictionary.

    The lock ensures that concurrent request handlers do not race on the same
    counter. Unknown metric names are initialised to zero on first use.
    """
    with metrics_lock:
        metrics[name] = metrics.get(name, 0) + amount


def _extract_client_ip(request: Optional[Request]) -> str:
    """Extract the client IP address from the request, or return 'unknown'."""
    if request and request.client and request.client.host:
        return request.client.host
    return "unknown"


def _compute_record_hash(
    prev_hash: str,
    ts: str,
    action: str,
    actor: str,
    target: str,
    decision: str,
) -> str:
    """Compute the SHA-256 hash for one audit log record in the chain.

    The hash input is the concatenation of all significant fields plus the
    previous record's hash. Any modification to a field or to the ordering
    of records produces a different hash, breaking the chain and making
    tampering detectable via the /admin/audit-logs/verify endpoint.
    """
    data = f"{prev_hash}{ts}{action}{actor}{target}{decision}"
    return hashlib.sha256(data.encode()).hexdigest()


def append_audit_event(
    db: Session,
    event_type: str,
    actor: str,
    target: str,
    decision: str,
) -> None:
    """Simplified public interface for writing a chained audit event.

    Used by the broker and workload identity modules which only need to log
    a single event type with an actor, target, and allow/deny decision.
    Full per-request context (IP address, HTTP request object) is not
    available in those modules, so it is omitted.
    """
    _write_audit_log(
        db=db,
        action=event_type,
        status=decision,
        actor_username=actor,
        target_username=target,
        commit=True,
    )


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
    """Write one hash-chained audit log record to the database.

    The chain is maintained as follows:
    - db.flush() makes any prior unflushed inserts in this transaction visible
      so the tail-of-chain query sees the most recent record.
    - prev_hash is taken from the most recent record's record_hash, or the
      genesis sentinel if this is the first record.
    - record_hash is computed over all significant fields, binding the new
      record to the chain so any later modification breaks it.

    If commit=True, the session is committed immediately. This is safe for
    callers that own the session; callers that are mid-transaction pass False
    and commit themselves.
    """
    detail_payload = json.dumps(details, sort_keys=True) if details is not None else None
    ts = utcnow_naive()

    # Flush so any prior unflushed audit inserts in this transaction are
    # visible when we query for the tail of the chain.
    db.flush()
    last = db.execute(select(AuditLog).order_by(AuditLog.id.desc()).limit(1)).scalars().first()
    # Genesis sentinel: a well-known constant so the first record's prev_hash
    # is deterministic and verifiable. An adversary with DB write access who
    # wants to forge a clean chain must start from this same value — providing
    # tamper evidence rather than tamper prevention.
    prev_hash = last.record_hash if last else "0" * 64
    record_hash = _compute_record_hash(
        prev_hash,
        ts.isoformat(),
        action,
        actor_username or "",
        target_username or "",
        status,
    )

    db.add(
        AuditLog(
            actor_username=actor_username,
            actor_role=actor_role,
            action=action,
            status=status,
            target_username=target_username,
            ip_address=_extract_client_ip(request),
            details=detail_payload,
            created_at=ts,
            prev_hash=prev_hash,
            record_hash=record_hash,
        )
    )
    increment_metric("audit_events_total", 1)
    if commit:
        db.commit()


def _record_auth_failure(
    db: Session, username: Optional[str], ip_address: str, reason: str
) -> None:
    """Persist an authentication failure event and emit a structured log line.

    This writes to AuthFailureLog for admin review and increments the
    login_failures metric counter. It does not update the user's lockout
    state; that is handled by _register_auth_failure.
    """
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
    """Enforce per-IP rate limiting on the login endpoint.

    On each call this function:
    1. Records the current attempt in LoginAttempt.
    2. Deletes attempts outside the sliding window to keep the table small.
    3. Counts attempts from this IP within the window.
    4. If the count exceeds RATE_LIMIT_MAX_ATTEMPTS, raises HTTP 429 with a
       Retry-After header set to the remaining window time in seconds.

    Returns the client IP so the caller can attach it to subsequent log entries.
    """
    client_ip = _extract_client_ip(request)
    now = utcnow_naive()
    cutoff = now - timedelta(seconds=RATE_LIMIT_WINDOW_SECONDS)

    db.add(LoginAttempt(ip_address=client_ip, created_at=now))
    # Delete stale attempts outside the current window before counting.
    db.execute(delete(LoginAttempt).where(LoginAttempt.created_at < cutoff))
    db.commit()

    attempt_count = db.scalar(
        select(func.count())
        .select_from(LoginAttempt)
        .where(LoginAttempt.ip_address == client_ip, LoginAttempt.created_at >= cutoff)
    )

    if attempt_count and attempt_count > RATE_LIMIT_MAX_ATTEMPTS:
        # Compute Retry-After as the remaining time until the oldest in-window
        # attempt falls outside the window, so the client knows exactly when
        # to retry rather than having to back off blindly.
        oldest_attempt = db.scalar(
            select(func.min(LoginAttempt.created_at)).where(
                LoginAttempt.ip_address == client_ip,
                LoginAttempt.created_at >= cutoff,
            )
        )
        elapsed_seconds = (
            max(0.0, (now - oldest_attempt).total_seconds()) if oldest_attempt else 0.0
        )
        retry_after_seconds = max(1, ceil(RATE_LIMIT_WINDOW_SECONDS - elapsed_seconds))
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
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts from this IP. Try again later.",
            headers={"Retry-After": str(retry_after_seconds)},
        )

    return client_ip


def _normalize_rowcount(rowcount: Optional[int]) -> int:
    """Return the rowcount as a non-negative integer.

    SQLAlchemy returns None or -1 for some dialects when the rowcount is
    not available; this normalises those cases to zero.
    """
    return rowcount if rowcount and rowcount > 0 else 0


def run_cleanup_jobs(db: Session, force: bool = False) -> dict:
    """Delete expired rows from all transient security tables.

    Runs at most once per CLEANUP_INTERVAL_MINUTES unless force=True.
    Called on every login request so cleanup happens automatically without
    a separate background worker. The interval throttle keeps the overhead
    negligible under normal traffic.

    Cleans up: expired revoked tokens, old auth failure logs, old login
    attempts, and used/expired password reset tokens.
    """
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

    # Delete revoked tokens whose natural expiry has passed — they are already
    # invalid so keeping them only grows the revocation table unnecessarily.
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
    """Return True if the user's account is currently locked out.

    Compares locked_until against the current naive UTC time. A null
    locked_until means the account has never been locked.
    """
    return user.locked_until is not None and utcnow_naive() < user.locked_until


def _register_auth_failure(
    user: Optional[User],
    db: Session,
    username: str,
    ip_address: str,
    reason: str,
) -> None:
    """Record a failed authentication attempt and trigger lockout if the threshold is reached.

    If user is not None, the per-account failed_login_attempts counter is
    incremented. When the counter reaches MAX_LOGIN_ATTEMPTS, locked_until is
    set and the counter resets to zero. This means that after a lockout expires,
    the user gets MAX_LOGIN_ATTEMPTS fresh attempts before locking again.
    """
    _record_auth_failure(db=db, username=username, ip_address=ip_address, reason=reason)

    if user is not None:
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= MAX_LOGIN_ATTEMPTS:
            increment_metric("lockouts", 1)
            user.locked_until = utcnow_naive() + timedelta(minutes=LOCKOUT_MINUTES)
            user.failed_login_attempts = 0

    db.commit()


def _reset_lock_state(user: User, db: Session) -> None:
    """Clear the lockout state and failure counter for a user on successful login.

    Called after a password and MFA check both pass so that a user who was
    temporarily locked is not stuck after the cooldown expires.
    """
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()


def _is_token_revoked(db: Session, jti: str) -> bool:
    """Return True if the given JTI appears in the revoked_tokens table.

    Called on every authenticated request. The jti column is indexed so the
    lookup is a single indexed point query.
    """
    token = db.execute(select(RevokedToken).where(RevokedToken.jti == jti)).scalars().first()
    return token is not None


def _revoke_token(db: Session, jti: str, token_type: str, exp_value: int) -> None:
    """Add a JTI to the revocation list if it is not already present.

    The idempotency check prevents duplicate key constraint errors when
    the same token is revoked twice (e.g. double logout). expires_at is
    stored so the cleanup job can remove the row once the token would have
    expired naturally.
    """
    existing = db.execute(select(RevokedToken).where(RevokedToken.jti == jti)).scalars().first()
    if existing:
        return

    expires_at = datetime.fromtimestamp(exp_value, tz=timezone.utc).replace(tzinfo=None)
    db.add(RevokedToken(jti=jti, token_type=token_type, expires_at=expires_at))
    db.commit()
