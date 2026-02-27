import base64
import json

from app import main as main_app


def register(client, username: str, password: str, role: str | None = None):
    payload = {"username": username, "password": password}
    if role:
        payload["role"] = role
    return client.post("/register", json=payload)


def login(client, username: str, password: str):
    return client.post("/login", json={"username": username, "password": password})


def test_register_validation_duplicate_and_password_length(client):
    ok = register(client, "alice", "secret123")
    assert ok.status_code == 201

    dup = register(client, "alice", "secret123")
    assert dup.status_code == 400

    long_pw = register(client, "bob", "a" * 73)
    assert long_pw.status_code == 400


def test_login_profile_and_invalid_creds(client):
    register(client, "alice", "secret123")

    bad = login(client, "alice", "wrong")
    assert bad.status_code == 401

    good = login(client, "alice", "secret123")
    assert good.status_code == 200
    body = good.json()
    assert "access_token" in body
    assert "refresh_token" in body

    profile = client.get(
        "/profile",
        headers={"Authorization": f"Bearer {body['access_token']}"},
    )
    assert profile.status_code == 200
    assert profile.json()["username"] == "alice"


def test_data_access_via_jwt_or_api_key(client):
    register(client, "alice", "secret123")
    token = login(client, "alice", "secret123").json()["access_token"]

    jwt_resp = client.get("/data", headers={"Authorization": f"Bearer {token}"})
    assert jwt_resp.status_code == 200

    key_resp = client.get("/data", headers={"X-API-Key": "test-api-key"})
    assert key_resp.status_code == 200

    none_resp = client.get("/data")
    assert none_resp.status_code == 401


def test_admin_rbac(client):
    register(client, "admin", "adminpass", role="admin")
    register(client, "user", "userpass")

    admin_token = login(client, "admin", "adminpass").json()["access_token"]
    user_token = login(client, "user", "userpass").json()["access_token"]

    forbidden = client.get("/admin/users", headers={"Authorization": f"Bearer {user_token}"})
    assert forbidden.status_code == 403

    allowed = client.get("/admin/users", headers={"Authorization": f"Bearer {admin_token}"})
    assert allowed.status_code == 200
    assert len(allowed.json()) >= 2


def test_refresh_rotation_and_logout_revocation(client):
    register(client, "alice", "secret123")
    first_login = login(client, "alice", "secret123")
    refresh_token = first_login.json()["refresh_token"]

    rotated = client.post("/refresh", json={"refresh_token": refresh_token})
    assert rotated.status_code == 200
    new_refresh = rotated.json()["refresh_token"]

    replay = client.post("/refresh", json={"refresh_token": refresh_token})
    assert replay.status_code == 401

    logout = client.post("/logout", json={"refresh_token": new_refresh})
    assert logout.status_code == 200

    after_logout = client.post("/refresh", json={"refresh_token": new_refresh})
    assert after_logout.status_code == 401


def test_account_lockout(client):
    register(client, "alice", "secret123")

    original_limit = main_app.RATE_LIMIT_MAX_ATTEMPTS
    main_app.RATE_LIMIT_MAX_ATTEMPTS = 100
    try:
        for _ in range(main_app.MAX_LOGIN_ATTEMPTS):
            failed = login(client, "alice", "wrongpass")
            assert failed.status_code == 401

        locked = login(client, "alice", "secret123")
        assert locked.status_code == 403
    finally:
        main_app.RATE_LIMIT_MAX_ATTEMPTS = original_limit


def test_rate_limit(client):
    for _ in range(main_app.RATE_LIMIT_MAX_ATTEMPTS):
        failed = login(client, "ghost", "whatever")
        assert failed.status_code == 401

    blocked = login(client, "ghost", "whatever")
    assert blocked.status_code == 403


def test_tampered_jwt_is_rejected(client):
    register(client, "alice", "secret123")
    access = login(client, "alice", "secret123").json()["access_token"]

    header_b64, payload_b64, signature = access.split(".")
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "==").decode("utf-8"))
    payload["sub"] = "admin"

    tampered_payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ).decode("utf-8").rstrip("=")

    tampered = f"{header_b64}.{tampered_payload_b64}.{signature}"
    response = client.get("/profile", headers={"Authorization": f"Bearer {tampered}"})
    assert response.status_code == 401
