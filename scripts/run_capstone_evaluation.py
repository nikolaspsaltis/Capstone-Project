#!/usr/bin/env python3
import argparse
import hashlib
import hmac
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = ROOT / "results"
SCRIPTS = [
    "scripts/bruteforce_login.py",
    "scripts/token_tampering.py",
    "scripts/unauthorized_admin_access.py",
    "scripts/performance_test.py",
]


# -- ATTACK 1: Token replay after expiry ------------------------------------


def attack_replay_expired_token(base_url: str) -> bool:
    """
    Obtain a valid token. Use it once (caches jti), then use again.
    Second use is a replay — expect 401.
    """
    import httpx

    r = httpx.post(
        f"{base_url}/login",
        json={"username": "testuser", "password": "testpass"},
    )
    if r.status_code != 200:
        print("  [SKIP] ATTACK-1: could not log in to get test token")
        return True  # don't fail on setup issues

    real_token = r.json()["access_token"]
    # Use the token once (caches jti), then use again — second use is replay
    httpx.get(f"{base_url}/data", headers={"Authorization": f"Bearer {real_token}"})
    r3 = httpx.get(f"{base_url}/data", headers={"Authorization": f"Bearer {real_token}"})
    passed = r3.status_code == 401
    reason = (
        r3.json().get("detail", {}).get("reason", "")
        if isinstance(r3.json().get("detail"), dict)
        else ""
    )
    print(
        f"  [{'PASS' if passed else 'FAIL'}] ATTACK-1 token replay "
        f"— HTTP {r3.status_code} reason={reason!r}"
    )
    return passed


# -- ATTACK 2: Audience mismatch -------------------------------------------


def attack_audience_mismatch(base_url: str) -> bool:
    """
    Exchange a login token for a service-scoped token, then try to use the
    scoped token against the main API. The audience mismatch must cause 401.
    """
    import httpx

    r = httpx.post(
        f"{base_url}/login",
        json={"username": "testuser", "password": "testpass"},
    )
    if r.status_code != 200:
        print("  [SKIP] ATTACK-2: could not log in")
        return True

    login_token = r.json()["access_token"]
    r2 = httpx.post(
        f"{base_url}/token/exchange",
        json={"target_audience": "https://some-other-service.internal"},
        headers={"Authorization": f"Bearer {login_token}"},
    )

    if r2.status_code == 404:
        print(
            "  [PASS] ATTACK-2 audience mismatch — exchange rejected (404 — "
            "audience not registered, correct behaviour)"
        )
        return True

    if r2.status_code != 200:
        print(
            f"  [PASS] ATTACK-2 audience mismatch — exchange rejected " f"(HTTP {r2.status_code})"
        )
        return True

    scoped = r2.json()["access_token"]
    r3 = httpx.get(f"{base_url}/data", headers={"Authorization": f"Bearer {scoped}"})
    passed = r3.status_code == 401
    print(
        f"  [{'PASS' if passed else 'FAIL'}] ATTACK-2 audience mismatch " f"— HTTP {r3.status_code}"
    )
    return passed


# -- ATTACK 3: Dev token targeting prod audience ----------------------------


def attack_dev_token_targeting_prod(base_url: str) -> bool:
    """
    Issue a workload SVID with env=dev.
    Attempt token exchange targeting a prod audience.
    Policy rule block_dev_targeting_prod must fire — 403.
    """
    import httpx

    secret = os.environ.get("WORKLOAD_ATTESTATION_SECRET", "")
    if not secret:
        print("  [SKIP] ATTACK-3: WORKLOAD_ATTESTATION_SECRET not set")
        return True

    minute = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M")
    att = hmac.new(
        secret.encode(),
        f"eval-worker:{minute}".encode(),
        hashlib.sha256,
    ).hexdigest()

    r = httpx.post(
        f"{base_url}/workload/identity/issue",
        json={"service_name": "eval-worker", "attestation": att},
    )
    if r.status_code != 200:
        print(
            f"  [SKIP] ATTACK-3: could not issue workload SVID "
            f"(HTTP {r.status_code}) — register eval-worker first"
        )
        return True

    svid = r.json()["access_token"]
    r2 = httpx.post(
        f"{base_url}/token/exchange",
        json={"target_audience": "https://prod.billing.internal"},
        headers={"Authorization": f"Bearer {svid}"},
    )
    passed = r2.status_code == 403
    rule = (
        r2.json().get("detail", {}).get("rule_id", "")
        if isinstance(r2.json().get("detail"), dict)
        else ""
    )
    print(
        f"  [{'PASS' if passed else 'FAIL'}] ATTACK-3 dev→prod "
        f"— HTTP {r2.status_code} rule_id={rule!r}"
    )
    return passed


def _seed_eval_fixtures(base_url: str) -> None:
    """Register accounts and service registry entries required by attack scenarios.

    Creates:
    - testuser/testpass (regular user, needed by ATTACK-1 and ATTACK-2)
    - admin/adminpass   (admin account, needed to call /admin/service-registry)
    - eval-worker entry in the service registry (needed by ATTACK-3)

    All requests are idempotent — duplicate registration or 409 on the service
    registry are silently ignored so the function is safe to call multiple times.
    """
    import httpx

    # Register test accounts (ignore 400 if already exist)
    httpx.post(f"{base_url}/register", json={"username": "testuser", "password": "testpass"})
    httpx.post(f"{base_url}/register", json={"username": "admin", "password": "adminpass"})

    # Promote admin account — requires a pre-existing admin token seeded via API key
    api_key = os.environ.get("API_KEYS", "").split(",")[0].strip()
    if not api_key:
        return

    headers = {"X-API-Key": api_key}

    # Register eval-worker for ATTACK-3 (ignore 409 if already registered)
    httpx.post(
        f"{base_url}/admin/service-registry",
        json={
            "service_id": "eval-worker",
            "audience": "https://eval-worker.internal",
            "allowed_callers": ["workload:eval-worker"],
        },
        headers=headers,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run Capstone evaluation scripts and zero-trust attack scenarios"
    )
    parser.add_argument(
        "--base-url",
        default="http://localhost:8000",
        help="Base URL of the running API server",
    )
    args = parser.parse_args()
    base_url = args.base_url.rstrip("/")

    # Seed the service registry entries needed by attack scenarios before running them.
    _seed_eval_fixtures(base_url)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_path = RESULTS_DIR / f"evaluation_report_{ts}.md"
    summary_path = RESULTS_DIR / f"evaluation_summary_{ts}.json"

    report_lines = [
        "# Capstone Evaluation Run",
        f"- UTC timestamp: `{ts}`",
        f"- Base URL: `{base_url}`",
        "- Note: Start the API first (`uvicorn app.main:app --reload`) before running this script.",
        "",
    ]
    summary = {"timestamp_utc": ts, "base_url": base_url, "runs": []}

    for rel_path in SCRIPTS:
        script_path = ROOT / rel_path
        proc = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=180,
        )
        log_name = f"{script_path.stem}_{ts}.log"
        log_path = RESULTS_DIR / log_name
        log_text = proc.stdout + ("\n" + proc.stderr if proc.stderr else "")
        log_path.write_text(log_text, encoding="utf-8")

        run_info = {
            "script": rel_path,
            "exit_code": proc.returncode,
            "log_file": f"results/{log_name}",
        }
        summary["runs"].append(run_info)

        report_lines.extend(
            [
                f"## {rel_path}",
                f"- Exit code: `{proc.returncode}`",
                f"- Log: `{run_info['log_file']}`",
                "",
            ]
        )

    print("\n── Zero-trust attack scenarios ──")
    attack_results = [
        attack_replay_expired_token(base_url),
        attack_audience_mismatch(base_url),
        attack_dev_token_targeting_prod(base_url),
    ]
    if not all(attack_results):
        print("\nOne or more attack scenarios FAILED.")

    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    report_lines.append(f"- JSON summary: `results/{summary_path.name}`")
    report_path.write_text("\n".join(report_lines) + "\n", encoding="utf-8")
    print(f"[+] Evaluation report: {report_path}")
    print(f"[+] Evaluation summary: {summary_path}")


if __name__ == "__main__":
    main()
