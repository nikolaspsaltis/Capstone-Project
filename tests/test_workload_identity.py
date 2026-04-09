import pytest

from tests.conftest import make_workload_attestation

WORKER = "test-worker"


@pytest.fixture(autouse=True)
def seed_worker_service(admin_client):
    admin_client.post(
        "/admin/service-registry",
        json={
            "service_id": WORKER,
            "audience": "https://capstone-api-test",
            "allowed_callers": [f"workload:{WORKER}"],
        },
    )


def test_valid_attestation_issues_svid(client):
    r = client.post(
        "/workload/identity/issue",
        json={
            "service_name": WORKER,
            "attestation": make_workload_attestation(WORKER),
        },
    )
    assert r.status_code == 200
    assert "access_token" in r.json()
    assert r.json()["expires_in"] == 300


def test_wrong_hmac_returns_401(client):
    r = client.post(
        "/workload/identity/issue",
        json={
            "service_name": WORKER,
            "attestation": "not-a-valid-hmac",
        },
    )
    assert r.status_code == 401
    assert r.json()["detail"]["error"] == "attestation_failed"


def test_unregistered_service_returns_404(client):
    r = client.post(
        "/workload/identity/issue",
        json={
            "service_name": "ghost-service",
            "attestation": make_workload_attestation("ghost-service"),
        },
    )
    assert r.status_code == 404


def test_svid_audience_is_trust_broker(client):
    r = client.post(
        "/workload/identity/issue",
        json={
            "service_name": WORKER,
            "attestation": make_workload_attestation(WORKER),
        },
    )
    from jose import jwt as jose_jwt

    claims = jose_jwt.get_unverified_claims(r.json()["access_token"])
    assert "trust-broker" in claims["aud"]


def test_svid_can_be_exchanged_for_scoped_token(client):
    svid = client.post(
        "/workload/identity/issue",
        json={
            "service_name": WORKER,
            "attestation": make_workload_attestation(WORKER),
        },
    ).json()["access_token"]

    r = client.post(
        "/token/exchange",
        json={"target_audience": "https://capstone-api-test"},
        headers={"Authorization": f"Bearer {svid}"},
    )
    assert r.status_code == 200
    assert "access_token" in r.json()
