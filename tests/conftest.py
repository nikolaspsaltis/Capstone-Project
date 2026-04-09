import hashlib
import hmac
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import close_all_sessions, sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

os.environ["JWT_SECRET"] = "test-secret-for-ci"
os.environ["JWT_ALGORITHM"] = "HS256"
os.environ["JWT_EXPIRE_MINUTES"] = "30"
os.environ["JWT_REFRESH_EXPIRE_MINUTES"] = "120"
os.environ["PASSWORD_RESET_TOKEN_EXPIRE_MINUTES"] = "15"
os.environ["JWT_ISSUER"] = "capstone-tests"
os.environ["JWT_AUDIENCE"] = "capstone-tests-client"
os.environ["DATABASE_URL"] = "sqlite:///./test_app.db"
os.environ["API_KEYS"] = "test-api-key,rotated-api-key"
os.environ["MAX_LOGIN_ATTEMPTS"] = "5"
os.environ["LOCKOUT_MINUTES"] = "15"
os.environ["RATE_LIMIT_WINDOW_SECONDS"] = "60"
os.environ["RATE_LIMIT_MAX_ATTEMPTS"] = "3"
os.environ["AUTH_FAILURE_LOG_RETENTION_DAYS"] = "30"
os.environ["LOGIN_ATTEMPT_RETENTION_DAYS"] = "7"
os.environ["CLEANUP_INTERVAL_MINUTES"] = "60"
os.environ["TESTING"] = "1"
os.environ["BCRYPT_TEST_ROUNDS"] = "4"


@pytest.fixture(scope="session", autouse=True)
def jwt_test_env(tmp_path_factory):
    key_dir = tmp_path_factory.mktemp("keys")
    key_path = key_dir / "test_signing.pem"
    key = Ed25519PrivateKey.generate()
    key_path.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    os.environ["JWT_PRIVATE_KEY_PATH"] = str(key_path)
    os.environ.setdefault("JWT_AUDIENCE", "capstone-tests-client")
    os.environ.setdefault("JWT_ISSUER", "capstone-tests")
    os.environ.setdefault("JWT_SECRET", "test-secret-unused")
    os.environ.setdefault("WORKLOAD_ATTESTATION_SECRET", "test-attestation-secret")
    os.environ.setdefault("APP_ENV", "dev")


from app import database as database_module
from app import main as main_app
from app import security as security_module


@pytest.fixture(autouse=True)
def isolated_db(tmp_path):
    db_path = tmp_path / "test_app.db"
    db_url = f"sqlite:///{db_path}"
    test_engine = create_engine(db_url, connect_args={"check_same_thread": False})
    test_session_local = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)

    old_main_engine = main_app.engine
    old_main_session_local = main_app.SessionLocal
    old_db_engine = database_module.engine
    old_db_session_local = database_module.SessionLocal

    main_app.engine = test_engine
    main_app.SessionLocal = test_session_local
    database_module.engine = test_engine
    database_module.SessionLocal = test_session_local

    main_app.Base.metadata.create_all(bind=test_engine)
    security_module.last_cleanup_run = None
    with main_app.metrics_lock:
        for key in main_app.metrics:
            main_app.metrics[key] = 0

    try:
        yield
    finally:
        close_all_sessions()
        test_engine.dispose()
        main_app.engine = old_main_engine
        main_app.SessionLocal = old_main_session_local
        database_module.engine = old_db_engine
        database_module.SessionLocal = old_db_session_local


@pytest.fixture
def client():
    with TestClient(main_app.app) as test_client:
        yield test_client


@pytest.fixture
def db_session():
    db = main_app.SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def admin_client(client):
    """TestClient pre-authenticated as an admin user."""
    client.post("/register", json={"username": "admin_fixture", "password": "adminpass123"})
    db = main_app.SessionLocal()
    try:
        user = main_app.get_user_by_username(db, "admin_fixture")
        user.role = "admin"
        db.commit()
    finally:
        db.close()
    resp = client.post("/login", json={"username": "admin_fixture", "password": "adminpass123"})
    token = resp.json()["access_token"]
    client.headers = {**client.headers, "Authorization": f"Bearer {token}"}
    return client


@pytest.fixture
def auth_client():
    """TestClient pre-authenticated as 'testuser'."""
    with TestClient(main_app.app) as c:
        c.post("/register", json={"username": "testuser", "password": "testpass123"})
        resp = c.post("/login", json={"username": "testuser", "password": "testpass123"})
        token = resp.json()["access_token"]
        c.headers = {**c.headers, "Authorization": f"Bearer {token}"}
        yield c


@pytest.fixture
def other_user_client():
    """TestClient pre-authenticated as 'otheruser' (not in allowed_callers)."""
    with TestClient(main_app.app) as c:
        c.post("/register", json={"username": "otheruser", "password": "testpass123"})
        resp = c.post("/login", json={"username": "otheruser", "password": "testpass123"})
        token = resp.json()["access_token"]
        c.headers = {**c.headers, "Authorization": f"Bearer {token}"}
        yield c


def make_workload_attestation(service_name: str) -> str:
    """Compute the HMAC attestation value for the current minute."""
    secret = os.environ.get("WORKLOAD_ATTESTATION_SECRET", "test-attestation-secret")
    minute = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M")
    msg = f"{service_name}:{minute}".encode()
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()
