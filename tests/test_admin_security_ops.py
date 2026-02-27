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

    login(client, "ghost", "wrong1")
    login(client, "ghost", "wrong2")

    resp = client.get(
        "/admin/auth-failures?limit=2",
        headers={"Authorization": f"Bearer {admin_access}"},
    )
    assert resp.status_code == 200

    logs = resp.json()
    assert len(logs) == 2
    assert all("reason" in row for row in logs)
    assert all(row["reason"] in {"invalid_credentials", "account_locked"} for row in logs)


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
