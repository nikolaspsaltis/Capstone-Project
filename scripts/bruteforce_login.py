#!/usr/bin/env python3
import argparse
import csv
import json
import sys
import time
from pathlib import Path
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simulate a brute-force login attack.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--username", default=f"bf_user_{int(time.time())}")
    parser.add_argument("--password", default="secret123", help="Real account password.")
    parser.add_argument(
        "--wrong-password",
        default="not_the_real_password",
        help="Password used for brute-force attempts.",
    )
    parser.add_argument(
        "--attempts",
        type=int,
        default=12,
        help="Number of wrong-password attempts before testing valid credentials.",
    )
    parser.add_argument(
        "--rate",
        type=float,
        default=20.0,
        help="Attempt rate in requests/second. 0 disables delays between attempts.",
    )
    parser.add_argument(
        "--output",
        default="",
        help="Optional CSV output path (for example results/bruteforce_attempts.csv).",
    )
    parser.add_argument(
        "--expect-defense",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Expect lockout/rate-limit defenses to trigger.",
    )
    parser.add_argument("--timeout", type=float, default=5.0)
    return parser.parse_args()


def write_attempts_csv(output_path: str, rows: list[tuple[int, str, int]]) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["attempt_index", "password_type", "status_code"])
        writer.writerows(rows)


def main() -> int:
    args = parse_args()
    print("[+] Starting brute-force simulation")
    print(
        "[+] base_url="
        f"{args.base_url} username={args.username} attempts={args.attempts} rate={args.rate}"
    )

    if args.attempts < 1:
        print("[-] --attempts must be >= 1")
        return 2
    if args.rate < 0:
        print("[-] --rate must be >= 0")
        return 2

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

    if register_status == 201:
        print("[+] Test user registered")
    elif register_status == 400:
        print(f"[!] Register returned 400; continuing with existing user. body={register_body}")
    else:
        print(f"[-] Unexpected register status={register_status}, body={register_body}")
        return 1

    attempt_rows: list[tuple[int, str, int]] = []
    defense_statuses = {403, 429}
    defense_triggered = False
    defense_status = 0

    for idx in range(1, args.attempts + 1):
        try:
            status, _body = post_json(
                args.base_url,
                "/login",
                {"username": args.username, "password": args.wrong_password},
                args.timeout,
            )
        except error.URLError as exc:
            print(f"[-] Connection failed during login attempt {idx}: {exc}")
            return 2

        attempt_rows.append((idx, "wrong", status))
        print(f"Attempt {idx}: status={status}")

        if status in defense_statuses:
            defense_triggered = True
            defense_status = status
            print(f"[+] Defense triggered on attempt {idx} with status {status}")
            break
        if status != 401:
            print(f"[-] Unexpected status during brute-force attempts: {status}")
            return 1

        if idx < args.attempts and args.rate > 0:
            time.sleep(1.0 / args.rate)

    try:
        valid_status, valid_body = post_json(
            args.base_url,
            "/login",
            {"username": args.username, "password": args.password},
            args.timeout,
        )
    except error.URLError as exc:
        print(f"[-] Connection failed during valid-login check: {exc}")
        return 2

    attempt_rows.append((len(attempt_rows) + 1, "correct", valid_status))
    print(f"[+] Valid-password check status={valid_status}")

    if args.output:
        write_attempts_csv(args.output, attempt_rows)
        print(f"[+] Wrote attempt CSV: {args.output}")

    if args.expect_defense:
        if not defense_triggered:
            print(
                "[-] FAIL: Defense did not trigger. Increase --attempts or verify "
                "rate-limit/lockout settings."
            )
            return 1
        if valid_status not in defense_statuses:
            print(
                "[-] FAIL: Defense triggered, but valid password was still accepted immediately "
                f"(status={valid_status})."
            )
            return 1
        print(
            "[+] PASS: Defense triggered and blocked valid-password login "
            f"(trigger_status={defense_status}, final_status={valid_status})."
        )
        return 0

    if valid_status == 200:
        print("[+] PASS: Valid-password login succeeded without requiring defense behavior.")
        return 0

    print(
        "[-] FAIL: Expected successful valid-password login when --no-expect-defense is used, "
        f"but got status={valid_status}, body={valid_body}"
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
