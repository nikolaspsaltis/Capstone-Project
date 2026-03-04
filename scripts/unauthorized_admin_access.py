#!/usr/bin/env python3
import argparse
import json
import sys
import time
from urllib import error, request


def post_json(base_url: str, path: str, payload: dict, timeout: float) -> tuple[int, str]:
    data = json.dumps(payload).encode("utf-8")
    req = request.Request(
        f"{base_url}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8")
    except error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


def get(base_url: str, path: str, headers: dict | None, timeout: float) -> tuple[int, str]:
    req = request.Request(f"{base_url}{path}", headers=headers or {}, method="GET")
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8")
    except error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify non-admin users cannot access admin routes."
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--username", default=f"rbac_user_{int(time.time())}")
    parser.add_argument("--password", default="secret123")
    parser.add_argument(
        "--expected-status",
        type=int,
        default=403,
        help="Expected status when non-admin calls /admin/users.",
    )
    parser.add_argument("--timeout", type=float, default=5.0)
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        register_status, register_body = post_json(
            args.base_url,
            "/register",
            {"username": args.username, "password": args.password},
            args.timeout,
        )
    except error.URLError as exc:
        print(f"[-] Connection failed during register: {exc}")
        return 2

    if register_status not in (201, 400):
        print(f"[-] Unexpected register status={register_status}, body={register_body}")
        return 1

    try:
        login_status, login_body = post_json(
            args.base_url,
            "/login",
            {"username": args.username, "password": args.password},
            args.timeout,
        )
    except error.URLError as exc:
        print(f"[-] Connection failed during login: {exc}")
        return 2

    if login_status != 200:
        print(f"[-] Unable to login as non-admin user. status={login_status}, body={login_body}")
        return 1

    try:
        token = json.loads(login_body)["access_token"]
    except (KeyError, json.JSONDecodeError) as exc:
        print(f"[-] Failed to parse login response: {exc}")
        return 1

    try:
        admin_status, admin_body = get(
            args.base_url,
            "/admin/users",
            headers={"Authorization": f"Bearer {token}"},
            timeout=args.timeout,
        )
    except error.URLError as exc:
        print(f"[-] Connection failed during admin access call: {exc}")
        return 2

    print(
        "[+] Summary: "
        f"base_url={args.base_url} user={args.username} "
        f"expected={args.expected_status} observed={admin_status}"
    )

    if admin_status == args.expected_status:
        print("[+] PASS: Non-admin access was denied as expected")
        return 0

    print(
        "[-] FAIL: Non-admin access did not match expected status. "
        f"status={admin_status}, body={admin_body}"
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
