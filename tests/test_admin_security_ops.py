from datetime import timedelta

from app import main as main_app


def register(client, username: str, password: str, role: str | None = None):
    payload = {"username": username, "password": password}
    if role:
        payload["role"] = role
    return client.post("/register", json=payload)


def login(client, username: str, password: str):
    return client.post("/login", json={"username": username, "password": password})


def test_admin_can_unlock_user(client):
    register(client, "admin", "adminpass", role="admin")
    register(client, "lockeduser", "secret123")

    admin_access = login(client, "admin", "adminpass").json()["access_token"]

    original_limit = main_app.RATE_LIMIT_MAX_ATTEMPTS
    main_app.RATE_LIMIT_MAX_ATTEMPTS = 100
    try:
        for _ in range(main_app.MAX_LOGIN_ATTEMPTS):
            bad = login(client, "lockeduser", "wrongpass")
            assert bad.status_code == 401

        locked = login(client, "lockeduser", "secret123")
        assert locked.status_code == 403

        unlock = client.post(
            "/admin/users/lockeduser/unlock",
            headers={"Authorization": f"Bearer {admin_access}"},
        )
        assert unlock.status_code == 200

        after = login(client, "lockeduser", "secret123")
        assert after.status_code == 200
    finally:
        main_app.RATE_LIMIT_MAX_ATTEMPTS = original_limit


def test_non_admin_cannot_unlock_user(client):
    register(client, "user", "userpass")
    access = login(client, "user", "userpass").json()["access_token"]

    resp = client.post(
        "/admin/users/user/unlock",
        headers={"Authorization": f"Bearer {access}"},
    )
    assert resp.status_code == 403


def test_admin_can_view_auth_failure_logs(client):
    register(client, "admin", "adminpass", role="admin")
    admin_access = login(client, "admin", "adminpass").json()["access_token"]

    original_limit = main_app.RATE_LIMIT_MAX_ATTEMPTS
    main_app.RATE_LIMIT_MAX_ATTEMPTS = 100
    try:
        login(client, "ghost", "wrong1")
        login(client, "ghost", "wrong2")
        login(client, "other", "wrong3")
    finally:
        main_app.RATE_LIMIT_MAX_ATTEMPTS = original_limit

    page_1 = client.get(
        "/admin/auth-failures?page=1&page_size=1&username=ghost",
        headers={"Authorization": f"Bearer {admin_access}"},
    )
    assert page_1.status_code == 200
    body_1 = page_1.json()
    assert body_1["page"] == 1
    assert body_1["page_size"] == 1
    assert body_1["total"] >= 2
    assert len(body_1["items"]) == 1
    assert body_1["items"][0]["username"] == "ghost"

    page_2 = client.get(
        "/admin/auth-failures?page=2&page_size=1&username=ghost",
        headers={"Authorization": f"Bearer {admin_access}"},
    )
    assert page_2.status_code == 200
    body_2 = page_2.json()
    assert body_2["page"] == 2
    assert len(body_2["items"]) == 1
    assert body_2["items"][0]["username"] == "ghost"


def test_admin_can_revoke_refresh_tokens_by_user(client):
    register(client, "admin", "adminpass", role="admin")
    register(client, "alice", "secret123")

    admin_access = login(client, "admin", "adminpass").json()["access_token"]

    login_1 = login(client, "alice", "secret123")
    refresh_1 = login_1.json()["refresh_token"]

    revoke = client.post(
        "/admin/users/alice/revoke-refresh-tokens",
        headers={"Authorization": f"Bearer {admin_access}"},
    )
    assert revoke.status_code == 200
    assert revoke.json()["refresh_token_version"] == 1

    stale = client.post("/refresh", json={"refresh_token": refresh_1})
    assert stale.status_code == 401

    login_2 = login(client, "alice", "secret123")
    refresh_2 = login_2.json()["refresh_token"]

    fresh = client.post("/refresh", json={"refresh_token": refresh_2})
    assert fresh.status_code == 200


def test_non_admin_cannot_revoke_refresh_tokens(client):
    register(client, "alice", "secret123")
    access = login(client, "alice", "secret123").json()["access_token"]

    resp = client.post(
        "/admin/users/alice/revoke-refresh-tokens",
        headers={"Authorization": f"Bearer {access}"},
    )
    assert resp.status_code == 403


def test_admin_cleanup_removes_expired_and_old_records(client):
    register(client, "admin", "adminpass", role="admin")
    admin_access = login(client, "admin", "adminpass").json()["access_token"]

    db = main_app.SessionLocal()
    try:
        now = main_app.utcnow_naive()
        db.add(
            main_app.RevokedToken(
                jti="expired-jti",
                token_type="refresh",
                expires_at=now - timedelta(days=1),
            )
        )
        db.add(
            main_app.RevokedToken(
                jti="active-jti",
                token_type="refresh",
                expires_at=now + timedelta(days=1),
            )
        )
        db.add(
            main_app.AuthFailureLog(
                username="old-user",
                ip_address="127.0.0.1",
                reason="invalid_credentials",
                created_at=now - timedelta(days=main_app.AUTH_FAILURE_LOG_RETENTION_DAYS + 1),
            )
        )
        db.add(
            main_app.AuthFailureLog(
                username="fresh-user",
                ip_address="127.0.0.1",
                reason="invalid_credentials",
                created_at=now,
            )
        )
        db.add(
            main_app.LoginAttempt(
                ip_address="127.0.0.1",
                created_at=now - timedelta(days=main_app.LOGIN_ATTEMPT_RETENTION_DAYS + 1),
            )
        )
        db.add(main_app.LoginAttempt(ip_address="127.0.0.1", created_at=now))
        db.commit()
    finally:
        db.close()

    cleanup = client.post(
        "/admin/maintenance/cleanup",
        headers={"Authorization": f"Bearer {admin_access}"},
    )
    assert cleanup.status_code == 200
    body = cleanup.json()
    assert body["status"] == "ok"
    assert body["revoked_tokens_deleted"] >= 1
    assert body["auth_failure_logs_deleted"] >= 1
    assert body["login_attempts_deleted"] >= 1
