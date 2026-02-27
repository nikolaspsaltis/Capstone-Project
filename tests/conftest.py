import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

TEST_DB_PATH = Path("./test_app.db")
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

os.environ["JWT_SECRET"] = "test-secret-for-ci"
os.environ["JWT_ALGORITHM"] = "HS256"
os.environ["JWT_EXPIRE_MINUTES"] = "30"
os.environ["JWT_REFRESH_EXPIRE_MINUTES"] = "120"
os.environ["JWT_ISSUER"] = "capstone-tests"
os.environ["JWT_AUDIENCE"] = "capstone-tests-client"
os.environ["DATABASE_URL"] = "sqlite:///./test_app.db"
os.environ["API_KEYS"] = "test-api-key,rotated-api-key"
os.environ["MAX_LOGIN_ATTEMPTS"] = "5"
os.environ["LOCKOUT_MINUTES"] = "15"
os.environ["RATE_LIMIT_WINDOW_SECONDS"] = "60"
os.environ["RATE_LIMIT_MAX_ATTEMPTS"] = "3"

from app import main as main_app


@pytest.fixture(autouse=True)
def clean_db():
    main_app.Base.metadata.drop_all(bind=main_app.engine)
    main_app.Base.metadata.create_all(bind=main_app.engine)
    yield


@pytest.fixture
def client():
    with TestClient(main_app.app) as test_client:
        yield test_client


@pytest.fixture(scope="session", autouse=True)
def cleanup_db_file():
    yield
    if TEST_DB_PATH.exists():
        TEST_DB_PATH.unlink()
