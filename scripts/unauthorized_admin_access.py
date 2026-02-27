#!/usr/bin/env python3
import json
from urllib import error, request

BASE_URL = "http://127.0.0.1:8000"


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


def main() -> None:
    register_status, register_body = post_json(
        "/register", {"username": "bob", "password": "bobsecret"}
    )
    if register_status not in (201, 400):
        print(f"[-] Unexpected register status={register_status}, body={register_body}")
        return

    login_status, login_body = post_json("/login", {"username": "bob", "password": "bobsecret"})
    if login_status != 200:
        print(f"[-] Unable to login as bob. status={login_status}, body={login_body}")
        return

    token = json.loads(login_body)["access_token"]
    admin_status, admin_body = get("/admin/users", headers={"Authorization": f"Bearer {token}"})

    if admin_status == 403:
        print("[+] PASS: Non-admin user denied admin endpoint")
    else:
        print(f"[!] FAIL: Non-admin received status={admin_status}, body={admin_body}")


if __name__ == "__main__":
    main()
