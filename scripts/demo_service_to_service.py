#!/usr/bin/env python3
"""
Demonstrates the full machine-to-machine zero-trust flow.

Usage:
    python scripts/demo_service_to_service.py [--base-url http://localhost:8000]

Requires:
    WORKLOAD_ATTESTATION_SECRET env var set.
    API_KEYS env var set (first key is used to seed the service registry).

The script registers the demo-worker service entry automatically via the
admin API before running the flow, so no manual setup is needed.

Flow demonstrated:
  1. Register demo-worker in service registry (idempotent)
  2. Obtain workload SVID via HMAC attestation
  3. Exchange SVID for audience-scoped token at the broker
  4. Use scoped token to access /data
  5. Replay the same scoped token — must be rejected (401)
  6. Present scoped token to wrong-audience endpoint — must be rejected (401/403)
"""
import argparse
import hashlib
import hmac
import os
import sys
from datetime import datetime, timezone

import httpx

# The audience this demo registers and exchanges tokens for. Must match the
# SERVICE_AUDIENCE configured on the downstream service in docker-compose.yml.
DEMO_AUDIENCE = "https://data-service.internal"


def _make_attestation(service_name: str) -> str:
    """Compute the HMAC-SHA256 attestation for the current UTC minute."""
    secret = os.environ.get("WORKLOAD_ATTESTATION_SECRET", "")
    if not secret:
        sys.exit("ERROR: WORKLOAD_ATTESTATION_SECRET is not set")
    minute = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M")
    return hmac.new(
        secret.encode(),
        f"{service_name}:{minute}".encode(),
        hashlib.sha256,
    ).hexdigest()


def _seed_service_registry(base: str, worker: str) -> None:
    """Register demo-worker in the service registry if not already present.

    Uses the first API key from the API_KEYS environment variable to
    authenticate as a service-level caller against the admin endpoint.
    A 409 response means the entry already exists — that is treated as success.
    """
    api_key = os.environ.get("API_KEYS", "").split(",")[0].strip()
    if not api_key:
        print("  [WARN] API_KEYS not set — skipping service registry seed")
        print("         Ensure demo-worker is already registered manually.")
        return

    r = httpx.post(
        f"{base}/admin/service-registry",
        json={
            "service_id": worker,
            "audience": DEMO_AUDIENCE,
            "allowed_callers": [f"workload:{worker}"],
        },
        headers={"X-API-Key": api_key},
    )
    if r.status_code in (201, 409):
        status = "registered" if r.status_code == 201 else "already registered"
        print(f"  [OK]   Service registry: {worker} → {DEMO_AUDIENCE} ({status})")
    else:
        print(f"  [WARN] Service registry seed returned HTTP {r.status_code}: {r.text}")


def main():
    p = argparse.ArgumentParser(description="Demonstrate machine-to-machine zero-trust flow")
    p.add_argument("--base-url", default="http://localhost:8000")
    args = p.parse_args()
    base = args.base_url.rstrip("/")
    worker = "demo-worker"
    results = []

    def step(label: str, ok: bool, status: int):
        tag = "PASS" if ok else "FAIL"
        results.append(tag)
        print(f"  [{tag}] {label}  (HTTP {status})")

    print(f"\n{'='*60}")
    print("  Machine-to-machine zero-trust flow demo")
    print(f"{'='*60}\n")

    # 0. Seed service registry so the exchange step has a registered audience
    _seed_service_registry(base, worker)
    print()

    # 1. Issue workload SVID via HMAC attestation
    r = httpx.post(
        f"{base}/workload/identity/issue",
        json={"service_name": worker, "attestation": _make_attestation(worker)},
    )
    step("Issue workload SVID", r.status_code == 200, r.status_code)
    if r.status_code != 200:
        print(f"  Cannot continue — workload identity failed: {r.text}")
        sys.exit(1)
    svid = r.json()["access_token"]

    # 2. Exchange SVID for an audience-scoped token targeting DEMO_AUDIENCE
    r = httpx.post(
        f"{base}/token/exchange",
        json={"target_audience": DEMO_AUDIENCE},
        headers={"Authorization": f"Bearer {svid}"},
    )
    step("Exchange SVID for scoped token", r.status_code == 200, r.status_code)
    if r.status_code != 200:
        print(f"  Exchange failed: {r.text}")
        sys.exit(1)
    scoped = r.json()["access_token"]

    # 3. Use scoped token to access a protected endpoint
    r = httpx.get(f"{base}/data", headers={"Authorization": f"Bearer {scoped}"})
    step("Access /data with scoped token", r.status_code == 200, r.status_code)

    # 4. Replay the same token — the JTI replay cache must reject it
    r = httpx.get(f"{base}/data", headers={"Authorization": f"Bearer {scoped}"})
    step("Replay rejected (JTI replay cache)", r.status_code == 401, r.status_code)

    # 5. Present scoped token (aud=DEMO_AUDIENCE) to a wrong-audience endpoint
    r = httpx.get(f"{base}/admin/users", headers={"Authorization": f"Bearer {scoped}"})
    step("Wrong-audience endpoint rejected", r.status_code in (401, 403), r.status_code)

    passed = results.count("PASS")
    print(f"\n  {passed}/{len(results)} steps passed")
    print(f"{'='*60}\n")
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
