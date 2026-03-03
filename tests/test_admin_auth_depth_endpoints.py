import time

import pytest

from app import main as main_app


def register(client, username: str, password: str, role: str | None = None):
    payload = {"username": username, "password": password}
    if role:
        payload["role"] = role
    return client.post("/register", json=payload)


def login(client, username: str, password: str, totp_code: str | None = None):
    payload = {"username": username, "password": password}
    if totp_code:
        payload["totp_code"] = totp_code
    return client.post("/login", json=payload)


@pytest.mark.parametrize(
    ("method", "path", "payload"),
    [
        ("POST", "/admin/mfa/setup", None),
        ("POST", "/admin/mfa/enable", {"code": "000000"}),
        ("POST", "/admin/mfa/disable", {"code": "000000"}),
        ("GET", "/admin/api-keys", None),
        ("POST", "/admin/api-keys", {"name": "user-attempt"}),
        ("POST", "/admin/api-keys/9999/rotate", {"name": "user-attempt-rotated"}),
        ("POST", "/admin/api-keys/9999/revoke", None),
        ("GET", "/admin/audit-logs", None),
    ],
)
def test_non_admin_forbidden_on_new_admin_endpoints(client, method: str, path: str, payload: dict):
    register(client, "user", "userpass")
    user_token = login(client, "user", "userpass").json()["access_token"]
    response = client.request(
        method,
        path,
        json=payload,
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert response.status_code == 403


def test_admin_mfa_enable_requires_setup(client):
    register(client, "admin", "adminpass", role="admin")
    admin_token = login(client, "admin", "adminpass").json()["access_token"]

    response = client.post(
        "/admin/mfa/enable",
        json={"code": "123456"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 400
    assert "initialized" in response.json()["detail"]


def test_admin_mfa_disable_requires_enabled_state(client):
    register(client, "admin", "adminpass", role="admin")
    admin_token = login(client, "admin", "adminpass").json()["access_token"]

    response = client.post(
        "/admin/mfa/disable",
        json={"code": "123456"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 400
    assert "not enabled" in response.json()["detail"]


def test_admin_api_key_rotate_and_revoke_missing_key(client):
    register(client, "admin", "adminpass", role="admin")
    admin_token = login(client, "admin", "adminpass").json()["access_token"]

    rotate = client.post(
        "/admin/api-keys/9999/rotate",
        json={"name": "missing"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert rotate.status_code == 404

    revoke = client.post(
        "/admin/api-keys/9999/revoke",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert revoke.status_code == 404


def test_admin_api_key_revoke_is_idempotent(client):
    register(client, "admin", "adminpass", role="admin")
    admin_token = login(client, "admin", "adminpass").json()["access_token"]

    created = client.post(
        "/admin/api-keys",
        json={"name": "to-revoke"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert created.status_code == 200
    key_id = created.json()["metadata"]["id"]

    first = client.post(
        f"/admin/api-keys/{key_id}/revoke",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert first.status_code == 200
    assert first.json()["message"] == "API key revoked"

    second = client.post(
        f"/admin/api-keys/{key_id}/revoke",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert second.status_code == 200
    assert second.json()["message"] == "API key already inactive"


def test_admin_api_key_with_expiry_becomes_invalid(client):
    register(client, "admin", "adminpass", role="admin")
    admin_token = login(client, "admin", "adminpass").json()["access_token"]

    created = client.post(
        "/admin/api-keys",
        json={"name": "short-lived", "expires_minutes": 1},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert created.status_code == 200
    raw_key = created.json()["api_key"]
    key_id = created.json()["metadata"]["id"]

    valid_now = client.get("/data", headers={"X-API-Key": raw_key})
    assert valid_now.status_code == 200

    db = main_app.SessionLocal()
    try:
        key = (
            db.execute(main_app.select(main_app.APIKey).where(main_app.APIKey.id == key_id))
            .scalars()
            .first()
        )
        assert key is not None
        key.expires_at = main_app.utcnow_naive() - main_app.timedelta(seconds=1)
        db.commit()
    finally:
        db.close()

    time.sleep(0.01)
    expired = client.get("/data", headers={"X-API-Key": raw_key})
    assert expired.status_code == 401
