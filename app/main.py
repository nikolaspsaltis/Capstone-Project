from datetime import datetime, timedelta, timezone
import hashlib
import logging
import os
import secrets
from typing import Optional
from uuid import uuid4

import bcrypt as bcrypt_lib
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, ConfigDict, constr
from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    String,
    UniqueConstraint,
    create_engine,
    delete,
    func,
    select,
    text,
)
from sqlalchemy.orm import Session, declarative_base, sessionmaker

# -------------------------
# Config
# -------------------------
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
auth_logger = logging.getLogger("capstone.auth")

SECRET_KEY = os.getenv("JWT_SECRET", "")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_ISSUER = os.getenv("JWT_ISSUER", "capstone-project")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "capstone-client")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "30"))
REFRESH_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_REFRESH_EXPIRE_MINUTES", "10080"))
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")

if not SECRET_KEY or SECRET_KEY == "change-this-secret-in-production":
    raise RuntimeError(
        "JWT_SECRET must be set to a strong value (and not the placeholder) before running the app."
    )

# API key rotation is supported by comma-separated keys in API_KEYS.
API_KEYS = [key.strip() for key in os.getenv("API_KEYS", "capstone-demo-key").split(",") if key.strip()]

# Login defense settings.
MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
LOCKOUT_MINUTES = int(os.getenv("LOCKOUT_MINUTES", "15"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
RATE_LIMIT_MAX_ATTEMPTS = int(os.getenv("RATE_LIMIT_MAX_ATTEMPTS", "10"))

# -------------------------
# Database setup
# -------------------------
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def utcnow_naive() -> datetime:
    return utcnow().replace(tzinfo=None)


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("username", name="uq_username"),)

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False, default="user")
    failed_login_attempts = Column(Integer, nullable=False, default=0)
    locked_until = Column(DateTime, nullable=True)


class LoginAttempt(Base):
    __tablename__ = "login_attempts"

    id = Column(Integer, primary_key=True)
    ip_address = Column(String, nullable=False, index=True)
    created_at = Column(DateTime, nullable=False, default=utcnow_naive)


class AuthFailureLog(Base):
    __tablename__ = "auth_failure_logs"

    id = Column(Integer, primary_key=True)
    username = Column(String, nullable=True, index=True)
    ip_address = Column(String, nullable=False, index=True)
    reason = Column(String, nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow_naive)


class RevokedToken(Base):
    __tablename__ = "revoked_tokens"
    __table_args__ = (UniqueConstraint("jti", name="uq_revoked_token_jti"),)

    id = Column(Integer, primary_key=True)
    jti = Column(String, nullable=False, index=True)
    token_type = Column(String, nullable=False)
    revoked_at = Column(DateTime, nullable=False, default=utcnow_naive)
    expires_at = Column(DateTime, nullable=False)


Base.metadata.create_all(bind=engine)


def _ensure_users_schema() -> None:
    with engine.begin() as conn:
        tables = conn.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        ).fetchall()
        if not tables:
            return

        existing_cols = {
            row[1] for row in conn.execute(text("PRAGMA table_info(users)")).fetchall()
        }
        if "role" not in existing_cols:
            conn.execute(text("ALTER TABLE users ADD COLUMN role VARCHAR DEFAULT 'user'"))
            conn.execute(text("UPDATE users SET role='user' WHERE role IS NULL"))
        if "failed_login_attempts" not in existing_cols:
            conn.execute(
                text(
                    "ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0"
                )
            )
            conn.execute(
                text(
                    "UPDATE users SET failed_login_attempts=0 "
                    "WHERE failed_login_attempts IS NULL"
                )
            )
        if "locked_until" not in existing_cols:
            conn.execute(text("ALTER TABLE users ADD COLUMN locked_until DATETIME"))


_ensure_users_schema()


# -------------------------
# Dependency
# -------------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# -------------------------
# Security utils
# -------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
oauth2_scheme_optional = OAuth2PasswordBearer(tokenUrl="login", auto_error=False)
PASSLIB_BCRYPT_USABLE = hasattr(bcrypt_lib, "__about__")



def _hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


VALID_API_KEY_HASHES = {_hash_api_key(key) for key in API_KEYS}



def has_valid_api_key(api_key: Optional[str]) -> bool:
    if not api_key:
        return False

    candidate_hash = _hash_api_key(api_key)
    for key_hash in VALID_API_KEY_HASHES:
        if secrets.compare_digest(candidate_hash, key_hash):
            return True
    return False



def hash_password(password: str) -> str:
    if PASSLIB_BCRYPT_USABLE:
        return pwd_context.hash(password)
    hashed = bcrypt_lib.hashpw(password.encode("utf-8"), bcrypt_lib.gensalt())
    return hashed.decode("utf-8")



def verify_password(password: str, password_hash: str) -> bool:
    if PASSLIB_BCRYPT_USABLE:
        return pwd_context.verify(password, password_hash)
    try:
        return bcrypt_lib.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False



def _create_token(subject: str, token_type: str, expires_minutes: int) -> str:
    issued_at = utcnow()
    expire = issued_at + timedelta(minutes=expires_minutes)
    payload = {
        "sub": subject,
        "exp": expire,
        "iat": issued_at,
        "jti": str(uuid4()),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "typ": token_type,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)



def create_access_token(subject: str) -> str:
    return _create_token(subject=subject, token_type="access", expires_minutes=ACCESS_TOKEN_EXPIRE_MINUTES)



def create_refresh_token(subject: str) -> str:
    return _create_token(subject=subject, token_type="refresh", expires_minutes=REFRESH_TOKEN_EXPIRE_MINUTES)



def get_user_by_username(db: Session, username: str) -> Optional[User]:
    stmt = select(User).where(User.username == username)
    return db.execute(stmt).scalars().first()



def _record_auth_failure(db: Session, username: Optional[str], ip_address: str, reason: str) -> None:
    auth_logger.warning(
        "AUTH_FAILURE username=%s ip=%s reason=%s ts=%s",
        username,
        ip_address,
        reason,
        utcnow().isoformat(),
    )
    db.add(AuthFailureLog(username=username, ip_address=ip_address, reason=reason))



def _check_login_rate_limit(request: Request, db: Session) -> str:
    client_ip = request.client.host if request.client and request.client.host else "unknown"
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
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Too many login attempts from this IP. Try again later.",
        )

    return client_ip



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



def _decode_token(db: Session, token: str, expected_type: str) -> dict:
    cred_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
        )
    except JWTError:
        raise cred_exc

    required = ("sub", "exp", "iat", "jti", "iss", "aud", "typ")
    if not all(field in payload for field in required):
        raise cred_exc

    if payload.get("typ") != expected_type:
        raise cred_exc

    if _is_token_revoked(db, payload["jti"]):
        raise cred_exc

    return payload



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
    return user



def get_current_user_or_api_key(
    db: Session = Depends(get_db),
    token: Optional[str] = Depends(oauth2_scheme_optional),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> Optional[User]:
    if has_valid_api_key(x_api_key):
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

    return user



def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    return current_user


# -------------------------
# API models
# -------------------------
class RegisterIn(BaseModel):
    username: constr(min_length=3, max_length=64)
    password: constr(min_length=6, max_length=256)
    role: Optional[str] = None


class LoginIn(BaseModel):
    username: constr(min_length=1, max_length=64)
    password: constr(min_length=1, max_length=256)


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


# -------------------------
# App
# -------------------------
app = FastAPI(title="Secure API Capstone Starter")


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=400, content={"detail": exc.errors()})


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/register", status_code=201)
def register(data: RegisterIn, db: Session = Depends(get_db)):
    if len(data.password.encode("utf-8")) > 72:
        raise HTTPException(
            status_code=400,
            detail="Password too long for bcrypt (max 72 bytes)",
        )

    existing = get_user_by_username(db, data.username)
    if existing:
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
    return {"id": user.id, "username": user.username, "role": user.role}


@app.post("/login", response_model=TokenOut)
def login(data: LoginIn, request: Request, db: Session = Depends(get_db)):
    client_ip = _check_login_rate_limit(request=request, db=db)

    user = get_user_by_username(db, data.username)
    if user and _is_user_locked(user):
        _register_auth_failure(
            user=user,
            db=db,
            username=data.username,
            ip_address=client_ip,
            reason="account_locked",
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
        raise HTTPException(status_code=401, detail="Invalid username or password")

    _reset_lock_state(user, db)
    access_token = create_access_token(subject=user.username)
    refresh_token = create_refresh_token(subject=user.username)
    return TokenOut(access_token=access_token, refresh_token=refresh_token)


@app.post("/refresh", response_model=TokenOut)
def refresh_token(data: RefreshIn, db: Session = Depends(get_db)):
    payload = _decode_token(db=db, token=data.refresh_token, expected_type="refresh")

    username = payload["sub"]
    user = get_user_by_username(db, username)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    _revoke_token(
        db=db,
        jti=payload["jti"],
        token_type="refresh",
        exp_value=payload["exp"],
    )

    new_access_token = create_access_token(subject=user.username)
    new_refresh_token = create_refresh_token(subject=user.username)
    return TokenOut(access_token=new_access_token, refresh_token=new_refresh_token)


@app.post("/logout")
def logout(data: RefreshIn, db: Session = Depends(get_db)):
    payload = _decode_token(db=db, token=data.refresh_token, expected_type="refresh")
    _revoke_token(
        db=db,
        jti=payload["jti"],
        token_type="refresh",
        exp_value=payload["exp"],
    )
    return {"status": "ok", "message": "Refresh token revoked"}


@app.get("/profile", response_model=ProfileOut)
def profile(current_user: User = Depends(get_current_user)):
    return current_user


@app.get("/data")
def data(_auth=Depends(get_current_user_or_api_key)):
    return {"data": "Sensitive data payload"}


@app.get("/admin/users", response_model=list[UserOut])
def admin_users(_admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    users = db.execute(select(User).order_by(User.id.asc())).scalars().all()
    return users
