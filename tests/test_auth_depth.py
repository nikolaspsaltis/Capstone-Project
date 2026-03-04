import time

from app import auth as auth_app
from app import main as main_app
from app import security as security_app


def register(client, username: str, password: str, role: str | None = None):
    response = client.post("/register", json={"username": username, "password": password})
    if role == "admin" and response.status_code == 201:
        db = main_app.SessionLocal()
        try:
            user = main_app.get_user_by_username(db, username)
            assert user is not None
            user.role = "admin"
            db.commit()
        finally:
            db.close()
    return response


def login(client, username: str, password: str, totp_code: str | None = None):
    payload = {"username": username, "password": password}
    if totp_code:
        payload["totp_code"] = totp_code
    return client.post("/login", json=payload)


def test_password_reset_one_time_token_flow(client):
    register(client, "alice", "secret123")

    request = client.post("/password-reset/request", json={"username": "alice"})
    assert request.status_code == 200
    token = request.json()["reset_token"]
    assert token

    confirm = client.post(
        "/password-reset/confirm",
        json={"token": token, "new_password": "newsecret123"},
    )
    assert confirm.status_code == 200

    old_login = login(client, "alice", "secret123")
    assert old_login.status_code == 401

    new_login = login(client, "alice", "newsecret123")
    assert new_login.status_code == 200

    replay = client.post(
        "/password-reset/confirm",
        json={"token": token, "new_password": "anotherpass"},
    )
    assert replay.status_code == 400


def test_admin_optional_mfa_totp_flow(client):
    original_limit = security_app.RATE_LIMIT_MAX_ATTEMPTS
    security_app.RATE_LIMIT_MAX_ATTEMPTS = 100
    try:
        register(client, "admin", "adminpass", role="admin")

        setup = client.post(
            "/admin/mfa/setup",
            headers={
                "Authorization": (
                    f"Bearer {login(client, 'admin', 'adminpass').json()['access_token']}"
                )
            },
        )
        assert setup.status_code == 200
        secret = setup.json()["secret"]

        code = auth_app.generate_totp_code(secret=secret, for_timestamp=int(time.time()))
        enable = client.post(
            "/admin/mfa/enable",
            json={"code": code},
            headers={
                "Authorization": (
                    f"Bearer {login(client, 'admin', 'adminpass').json()['access_token']}"
                )
            },
        )
        assert enable.status_code == 200

        no_code_login = login(client, "admin", "adminpass")
        assert no_code_login.status_code == 401

        bad_code_login = login(client, "admin", "adminpass", totp_code="000000")
        assert bad_code_login.status_code == 401

        good_code = auth_app.generate_totp_code(secret=secret, for_timestamp=int(time.time()))
        good_login = login(client, "admin", "adminpass", totp_code=good_code)
        assert good_login.status_code == 200

        disable_code = auth_app.generate_totp_code(secret=secret, for_timestamp=int(time.time()))
        disable = client.post(
            "/admin/mfa/disable",
            json={"code": disable_code},
            headers={"Authorization": f"Bearer {good_login.json()['access_token']}"},
        )
        assert disable.status_code == 200

        no_code_after_disable = login(client, "admin", "adminpass")
        assert no_code_after_disable.status_code == 200
    finally:
        security_app.RATE_LIMIT_MAX_ATTEMPTS = original_limit


def test_api_key_metadata_rotation_and_revoke(client):
    register(client, "admin", "adminpass", role="admin")
    admin_access = login(client, "admin", "adminpass").json()["access_token"]

    create = client.post(
        "/admin/api-keys",
        json={"name": "integration-key"},
        headers={"Authorization": f"Bearer {admin_access}"},
    )
    assert create.status_code == 200
    raw_key = create.json()["api_key"]
    key_id = create.json()["metadata"]["id"]

    data_ok = client.get("/data", headers={"X-API-Key": raw_key})
    assert data_ok.status_code == 200

    listed = client.get("/admin/api-keys", headers={"Authorization": f"Bearer {admin_access}"})
    assert listed.status_code == 200
    assert any(item["id"] == key_id and item["is_active"] for item in listed.json())

    rotate = client.post(
        f"/admin/api-keys/{key_id}/rotate",
        json={"name": "integration-key-rotated"},
        headers={"Authorization": f"Bearer {admin_access}"},
    )
    assert rotate.status_code == 200
    rotated_key = rotate.json()["api_key"]
    rotated_id = rotate.json()["metadata"]["id"]

    old_key_denied = client.get("/data", headers={"X-API-Key": raw_key})
    assert old_key_denied.status_code == 401

    new_key_ok = client.get("/data", headers={"X-API-Key": rotated_key})
    assert new_key_ok.status_code == 200

    revoke = client.post(
        f"/admin/api-keys/{rotated_id}/revoke",
        headers={"Authorization": f"Bearer {admin_access}"},
    )
    assert revoke.status_code == 200

    revoked_denied = client.get("/data", headers={"X-API-Key": rotated_key})
    assert revoked_denied.status_code == 401
