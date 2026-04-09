import pytest

SERVICE_AUDIENCE = "https://test-service.internal"


@pytest.fixture(autouse=True)
def seed_service_registry(admin_client):
    admin_client.post(
        "/admin/service-registry",
        json={
            "service_id": "test-service",
            "audience": SERVICE_AUDIENCE,
            "allowed_callers": ["testuser"],
        },
    )


def test_exchange_returns_audience_scoped_token(auth_client):
    r = auth_client.post("/token/exchange", json={"target_audience": SERVICE_AUDIENCE})
    assert r.status_code == 200
    from jose import jwt as jose_jwt

    payload = jose_jwt.get_unverified_claims(r.json()["access_token"])
    assert SERVICE_AUDIENCE in payload["aud"]
    assert payload["scope"] == "service:call"


def test_exchange_unknown_audience_404(auth_client):
    r = auth_client.post("/token/exchange", json={"target_audience": "https://unknown.internal"})
    assert r.status_code == 404


def test_exchange_unauthorised_caller_403(other_user_client):
    r = other_user_client.post("/token/exchange", json={"target_audience": SERVICE_AUDIENCE})
    assert r.status_code == 403
    assert r.json()["detail"]["error"] == "not_authorised_for_audience"


def test_exchanged_token_rejected_by_main_api(auth_client):
    exchanged = auth_client.post(
        "/token/exchange", json={"target_audience": SERVICE_AUDIENCE}
    ).json()["access_token"]
    r = auth_client.get("/data", headers={"Authorization": f"Bearer {exchanged}"})
    assert r.status_code == 401


def test_duplicate_service_registration_409(admin_client):
    r = admin_client.post(
        "/admin/service-registry",
        json={
            "service_id": "test-service",
            "audience": SERVICE_AUDIENCE,
            "allowed_callers": ["testuser"],
        },
    )
    assert r.status_code == 409
