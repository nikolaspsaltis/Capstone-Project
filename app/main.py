from datetime import datetime, timedelta, timezone
import os
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
import bcrypt as bcrypt_lib
from passlib.context import CryptContext
from pydantic import BaseModel, ConfigDict, constr
from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    String,
    UniqueConstraint,
    create_engine,
    select,
    text,
)
from sqlalchemy.orm import Session, declarative_base, sessionmaker

# -------------------------
# Config
# -------------------------
SECRET_KEY = os.getenv("JWT_SECRET", "")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "30"))
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")

if not SECRET_KEY or SECRET_KEY == "change-this-secret-in-production":
    raise RuntimeError(
        "JWT_SECRET must be set to a strong value (and not the placeholder) before running the app."
    )

# API keys can be moved to env vars later; this is intentionally simple.
VALID_API_KEYS = {"capstone-demo-key"}

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


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("username", name="uq_username"),)

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False, default="user")
    failed_login_attempts = Column(Integer, nullable=False, default=0)
    locked_until = Column(DateTime, nullable=True)


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


# Lightweight, in-memory request tracking for per-IP login rate limits.
rate_limit_store: dict[str, list[datetime]] = {}


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


def create_access_token(subject: str, expires_delta: Optional[timedelta] = None) -> str:
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    payload = {"sub": subject, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_user_by_username(db: Session, username: str) -> Optional[User]:
    stmt = select(User).where(User.username == username)
    return db.execute(stmt).scalars().first()


def _check_login_rate_limit(request: Request) -> None:
    client_ip = request.client.host if request.client else "unknown"
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=RATE_LIMIT_WINDOW_SECONDS)

    attempts = [ts for ts in rate_limit_store.get(client_ip, []) if ts >= cutoff]
    if len(attempts) >= RATE_LIMIT_MAX_ATTEMPTS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Too many login attempts from this IP. Try again later.",
        )

    attempts.append(now)
    rate_limit_store[client_ip] = attempts


def _is_user_locked(user: User) -> bool:
    if user.locked_until is None:
        return False
    return datetime.now(timezone.utc) < user.locked_until.replace(tzinfo=timezone.utc)


def _register_auth_failure(user: Optional[User], db: Session, username: str) -> None:
    # Basic auth failure logging for auditing and testing.
    print(f"AUTH_FAILURE username={username} ts={datetime.now(timezone.utc).isoformat()}")

    if user is None:
        return

    user.failed_login_attempts += 1
    if user.failed_login_attempts >= MAX_LOGIN_ATTEMPTS:
        user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)
        user.failed_login_attempts = 0
    db.commit()


def _reset_lock_state(user: User, db: Session) -> None:
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()


def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)) -> User:
    cred_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise cred_exc
    except JWTError:
        raise cred_exc

    user = get_user_by_username(db, username)
    if not user:
        raise cred_exc
    return user


def get_current_user_or_api_key(
    db: Session = Depends(get_db),
    token: Optional[str] = Depends(oauth2_scheme_optional),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> Optional[User]:
    if x_api_key and x_api_key in VALID_API_KEYS:
        return None

    if not token:
        raise HTTPException(status_code=401, detail="Missing JWT or API key")

    cred_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise cred_exc
    except JWTError:
        raise cred_exc

    user = get_user_by_username(db, username)
    if not user:
        raise cred_exc
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
    token_type: str = "bearer"


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
    _check_login_rate_limit(request)

    user = get_user_by_username(db, data.username)
    if user and _is_user_locked(user):
        raise HTTPException(status_code=403, detail="Account locked. Try again later.")

    if not user or not verify_password(data.password, user.password_hash):
        _register_auth_failure(user, db, data.username)
        raise HTTPException(status_code=401, detail="Invalid username or password")

    _reset_lock_state(user, db)
    token = create_access_token(subject=user.username)
    return TokenOut(access_token=token)


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
