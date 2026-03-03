import os
import sqlite3
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_INI = PROJECT_ROOT / "alembic.ini"


def run_alembic(db_url: str, *args: str) -> None:
    env = os.environ.copy()
    env["DATABASE_URL"] = db_url
    env["JWT_SECRET"] = "migration-test-secret"
    env["JWT_ISSUER"] = "capstone-tests"
    env["JWT_AUDIENCE"] = "capstone-tests-client"
    env["API_KEYS"] = "migration-test-key"

    result = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(ALEMBIC_INI), *args],
        cwd=PROJECT_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"Alembic command failed: {' '.join(args)}\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )


def table_exists(db_path: Path, table_name: str) -> bool:
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,),
        ).fetchone()
    return row is not None


def column_exists(db_path: Path, table_name: str, column_name: str) -> bool:
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return any(row[1] == column_name for row in rows)


def current_revision(db_path: Path) -> str | None:
    if not table_exists(db_path, "alembic_version"):
        return None
    with sqlite3.connect(db_path) as conn:
        row = conn.execute("SELECT version_num FROM alembic_version").fetchone()
    return row[0] if row else None


def test_migration_upgrade_head_creates_auth_depth_schema(tmp_path):
    db_path = tmp_path / "upgrade_head.db"
    db_url = f"sqlite:///{db_path}"

    run_alembic(db_url, "upgrade", "head")

    assert current_revision(db_path) == "0005_add_api_key_scopes"
    assert table_exists(db_path, "users")
    assert table_exists(db_path, "api_keys")
    assert table_exists(db_path, "password_reset_tokens")
    assert table_exists(db_path, "audit_logs")
    assert column_exists(db_path, "api_keys", "scopes")
    assert column_exists(db_path, "users", "mfa_enabled")
    assert column_exists(db_path, "users", "mfa_secret")
    assert column_exists(db_path, "users", "mfa_temp_secret")


def test_migration_downgrade_base_then_reupgrade(tmp_path):
    db_path = tmp_path / "downgrade_reupgrade.db"
    db_url = f"sqlite:///{db_path}"

    run_alembic(db_url, "upgrade", "head")
    run_alembic(db_url, "downgrade", "base")

    assert current_revision(db_path) is None
    assert not table_exists(db_path, "users")
    assert not table_exists(db_path, "api_keys")
    assert not table_exists(db_path, "password_reset_tokens")
    assert not table_exists(db_path, "audit_logs")

    run_alembic(db_url, "upgrade", "head")
    assert current_revision(db_path) == "0005_add_api_key_scopes"
    assert table_exists(db_path, "users")
    assert table_exists(db_path, "api_keys")
    assert table_exists(db_path, "password_reset_tokens")
    assert table_exists(db_path, "audit_logs")
    assert column_exists(db_path, "api_keys", "scopes")
