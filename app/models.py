from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text, UniqueConstraint

from app.database import Base, utcnow_naive


class User(Base):
    """Stores registered user accounts.

    failed_login_attempts and locked_until together implement account lockout:
    the counter increments on each bad login and resets to zero on success or
    manual admin unlock. locked_until holds the earliest datetime at which the
    account becomes usable again.

    refresh_token_version is incremented on logout so that any stolen refresh
    tokens from the previous session are immediately rejected on next use.

    mfa_temp_secret holds the unconfirmed TOTP secret during the MFA setup
    flow. Once the user verifies a code, mfa_secret is set and
    mfa_temp_secret is cleared.
    """

    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("username", name="uq_username"),)

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False, default="user")
    failed_login_attempts = Column(Integer, nullable=False, default=0)
    locked_until = Column(DateTime, nullable=True)
    refresh_token_version = Column(Integer, nullable=False, default=0)
    mfa_enabled = Column(Boolean, nullable=False, default=False)
    mfa_secret = Column(String, nullable=True)
    mfa_temp_secret = Column(String, nullable=True)


class APIKey(Base):
    """Represents a scoped API key for service-style authentication.

    The raw key is never stored. Only a SHA-256 hash (key_hash) and a short
    prefix (key_prefix) are kept, so a database breach does not expose usable
    keys.

    scopes is a JSON array of permission strings (e.g. ["data:read"]).
    expires_at is null for non-expiring keys.
    rotated_from_id links a replacement key back to the key it replaced,
    preserving the rotation history.
    """

    __tablename__ = "api_keys"
    __table_args__ = (UniqueConstraint("key_hash", name="uq_api_key_hash"),)

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    key_hash = Column(String, nullable=False, index=True)
    key_prefix = Column(String, nullable=False)
    scopes = Column(String, nullable=False, default="data:read")
    is_active = Column(Boolean, nullable=False, default=True)
    created_by = Column(String, nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow_naive)
    last_used_at = Column(DateTime, nullable=True)
    rotated_from_id = Column(Integer, nullable=True)
    expires_at = Column(DateTime, nullable=True)


class PasswordResetToken(Base):
    """Single-use, time-limited tokens for the password reset flow.

    token_hash stores the SHA-256 hash of the raw token sent to the user.
    used_at is set atomically when the token is consumed, ensuring a token
    cannot be used more than once even under concurrent requests.
    """

    __tablename__ = "password_reset_tokens"
    __table_args__ = (UniqueConstraint("token_hash", name="uq_password_reset_token_hash"),)

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False, index=True)
    token_hash = Column(String, nullable=False, index=True)
    created_at = Column(DateTime, nullable=False, default=utcnow_naive)
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime, nullable=True)


class LoginAttempt(Base):
    """Records each login attempt from a given IP address.

    The rate limiter queries this table to count attempts within a sliding
    window. Rows older than the window are deleted on each login to keep
    the table small.
    """

    __tablename__ = "login_attempts"

    id = Column(Integer, primary_key=True)
    ip_address = Column(String, nullable=False, index=True)
    created_at = Column(DateTime, nullable=False, default=utcnow_naive)


class AuthFailureLog(Base):
    """Permanent log of authentication failures for admin review.

    Unlike LoginAttempt (which is cleaned up aggressively), these rows are
    retained for AUTH_FAILURE_LOG_RETENTION_DAYS days and are exposed through
    the admin security-alerts endpoint to surface attack patterns.
    """

    __tablename__ = "auth_failure_logs"

    id = Column(Integer, primary_key=True)
    username = Column(String, nullable=True, index=True)
    ip_address = Column(String, nullable=False, index=True)
    reason = Column(String, nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow_naive)


class AuditLog(Base):
    """Hash-chained log of all security-relevant events.

    Each record stores a SHA-256 hash of itself chained to the previous
    record's hash. The /admin/audit-logs/verify endpoint re-computes the
    chain from the database and reports any mismatch, detecting tampering.

    prev_hash is null only for the genesis record (the very first entry).
    record_hash covers: prev_hash + timestamp + action + actor + target + status.
    """

    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)
    actor_username = Column(String, nullable=True, index=True)
    actor_role = Column(String, nullable=True)
    action = Column(String, nullable=False, index=True)
    status = Column(String, nullable=False)
    target_username = Column(String, nullable=True, index=True)
    ip_address = Column(String, nullable=False, index=True)
    details = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=utcnow_naive, index=True)
    prev_hash = Column(String(64), nullable=True)
    record_hash = Column(String(64), nullable=False, default=lambda: "0" * 64)


class RevokedToken(Base):
    """Stores JWT IDs (JTIs) that have been explicitly revoked.

    On every authenticated request the JTI of the bearer token is looked up
    here. A match means the token was revoked (e.g. via logout) and the
    request is rejected with 401. Rows are cleaned up once expires_at passes
    because a naturally expired token is already invalid.
    """

    __tablename__ = "revoked_tokens"
    __table_args__ = (UniqueConstraint("jti", name="uq_revoked_token_jti"),)

    id = Column(Integer, primary_key=True)
    jti = Column(String, nullable=False, index=True)
    token_type = Column(String, nullable=False)
    revoked_at = Column(DateTime, nullable=False, default=utcnow_naive)
    expires_at = Column(DateTime, nullable=False)


class ServiceRegistry(Base):
    """Tracks known service audiences for the token-exchange broker.

    audience is the unique URI a downstream service uses as its JWT audience
    claim (e.g. https://data-service.internal).

    allowed_callers is a JSON array of subject strings (usernames or
    workload:<name> identities) that are permitted to exchange a token for
    this audience. Any caller not in the list is denied at the broker.
    """

    __tablename__ = "service_registry"

    id = Column(Integer, primary_key=True)
    service_id = Column(String(64), unique=True, nullable=False)
    audience = Column(String(256), unique=True, nullable=False)
    allowed_callers = Column(Text, nullable=False)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow_naive)
