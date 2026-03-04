#!/usr/bin/env python3
import argparse
import base64
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


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def tamper_token(token: str) -> str:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Unexpected JWT format")

    payload_raw = base64.urlsafe_b64decode(parts[1] + "==")
    payload = json.loads(payload_raw.decode())
    payload["sub"] = "admin"

    tampered_payload = b64url(json.dumps(payload, separators=(",", ":")).encode())
    return f"{parts[0]}.{tampered_payload}.{parts[2]}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Attempt JWT payload tampering.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--username", default=f"tamper_user_{int(time.time())}")
    parser.add_argument("--password", default="secret123")
    parser.add_argument(
        "--expected-status",
        type=int,
        default=401,
        help="Expected status when calling /profile with a tampered token.",
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
        print(f"[-] Failed to get baseline token. status={login_status}, body={login_body}")
        return 1

    try:
        token = json.loads(login_body)["access_token"]
        forged = tamper_token(token)
    except (KeyError, ValueError, json.JSONDecodeError) as exc:
        print(f"[-] Failed to parse/tamper token: {exc}")
        return 1

    try:
        status, body = get(
            args.base_url,
            "/profile",
            headers={"Authorization": f"Bearer {forged}"},
            timeout=args.timeout,
        )
    except error.URLError as exc:
        print(f"[-] Connection failed during tampered token request: {exc}")
        return 2

    print(
        "[+] Summary: "
        f"base_url={args.base_url} user={args.username} "
        f"expected={args.expected_status} observed={status}"
    )

    if status == args.expected_status:
        print("[+] PASS: Tampered token rejected as expected")
        return 0

    print(f"[-] FAIL: Unexpected status for tampered token. status={status}, body={body}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
