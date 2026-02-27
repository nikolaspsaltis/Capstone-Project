#!/usr/bin/env python3
import base64
import json
import time
from urllib import error, request

BASE_URL = "http://127.0.0.1:8000"
USERNAME = f"tamper_user_{int(time.time())}"
PASSWORD = "secret123"


def post_json(path: str, payload: dict) -> tuple[int, str]:
    data = json.dumps(payload).encode("utf-8")
    req = request.Request(
        f"{BASE_URL}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read().decode("utf-8")
    except error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


def get(path: str, headers: dict | None = None) -> tuple[int, str]:
    req = request.Request(f"{BASE_URL}{path}", headers=headers or {}, method="GET")
    try:
        with request.urlopen(req, timeout=5) as resp:
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


def main() -> None:
    post_json("/register", {"username": USERNAME, "password": PASSWORD})
    login_status, login_body = post_json("/login", {"username": USERNAME, "password": PASSWORD})
    if login_status != 200:
        print(f"[-] Failed to get baseline token. status={login_status}, body={login_body}")
        return

    token = json.loads(login_body)["access_token"]
    forged = tamper_token(token)

    status, body = get("/profile", headers={"Authorization": f"Bearer {forged}"})

    if status == 401:
        print("[+] PASS: Tampered token was rejected (401)")
    else:
        print(f"[!] FAIL: Tampered token status={status}, body={body}")


if __name__ == "__main__":
    main()
