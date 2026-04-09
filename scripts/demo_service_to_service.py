#!/usr/bin/env python3
"""
Demonstrates the full machine-to-machine zero-trust flow.

Usage:
    python scripts/demo_service_to_service.py [--base-url http://localhost:8000]

Requires:
    WORKLOAD_ATTESTATION_SECRET env var set.
    A service named "demo-worker" registered in the service registry
    with allowed_callers=["workload:demo-worker"].
"""
import argparse
import hashlib
import hmac
import os
import sys
from datetime import datetime, timezone

import httpx


def _make_attestation(service_name: str) -> str:
    secret = os.environ.get("WORKLOAD_ATTESTATION_SECRET", "")
    if not secret:
        sys.exit("ERROR: WORKLOAD_ATTESTATION_SECRET is not set")
    minute = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M")
    return hmac.new(
        secret.encode(),
        f"{service_name}:{minute}".encode(),
        hashlib.sha256,
    ).hexdigest()


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

    print(f"\n{'='*52}")
    print("  Machine-to-machine zero-trust flow demo")
    print(f"{'='*52}\n")

    # 1. Issue workload SVID
    r = httpx.post(
        f"{base}/workload/identity/issue",
        json={"service_name": worker, "attestation": _make_attestation(worker)},
    )
    step("Issue workload SVID", r.status_code == 200, r.status_code)
    if r.status_code != 200:
        print("  Cannot continue — workload identity failed.")
        sys.exit(1)
    svid = r.json()["access_token"]

    # 2. Exchange SVID for audience-scoped token
    r = httpx.post(
        f"{base}/token/exchange",
        json={"target_audience": f"{base}"},
        headers={"Authorization": f"Bearer {svid}"},
    )
    step("Exchange SVID for scoped token", r.status_code == 200, r.status_code)
    scoped = r.json().get("access_token", "")

    # 3. Use scoped token against /data
    r = httpx.get(f"{base}/data", headers={"Authorization": f"Bearer {scoped}"})
    step("Access /data with scoped token", r.status_code == 200, r.status_code)

    # 4. Replay same token — must be rejected
    r = httpx.get(f"{base}/data", headers={"Authorization": f"Bearer {scoped}"})
    step("Replay rejected (jti cache)", r.status_code == 401, r.status_code)

    # 5. Use scoped token on wrong-audience endpoint
    r = httpx.get(f"{base}/admin/users", headers={"Authorization": f"Bearer {scoped}"})
    step("Wrong-audience rejected", r.status_code in (401, 403), r.status_code)

    passed = results.count("PASS")
    print(f"\n  {passed}/{len(results)} steps passed")
    print(f"{'='*52}\n")
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
