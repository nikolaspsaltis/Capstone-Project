#!/usr/bin/env python3
import json
import time
from urllib import request, error

BASE_URL = "http://127.0.0.1:8000"
USERNAME = f"bf_user_{int(time.time())}"
REAL_PASSWORD = "secret123"
PASSWORD_CANDIDATES = ["password", "123456", "letmein", REAL_PASSWORD]


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


def main() -> None:
    print("[+] Starting brute-force simulation")
    post_json("/register", {"username": USERNAME, "password": REAL_PASSWORD})

    for idx, password in enumerate(PASSWORD_CANDIDATES, start=1):
        status, body = post_json("/login", {"username": USERNAME, "password": password})
        ok = status == 200
        print(f"Attempt {idx}: password='{password}' -> status={status}, success={ok}")

        if ok:
            token = json.loads(body).get("access_token", "")
            print(f"[!] Valid credential found. Token prefix: {token[:20]}...")
            return

    print("[-] No valid credentials found in provided list")


if __name__ == "__main__":
    main()
