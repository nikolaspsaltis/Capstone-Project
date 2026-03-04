#!/usr/bin/env python3
import argparse
import csv
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib import error, request


def make_request(
    base_url: str,
    endpoint: str,
    timeout: float,
    api_key: str | None,
    bearer_token: str | None,
) -> int:
    headers: dict[str, str] = {}
    if api_key:
        headers["X-API-Key"] = api_key
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"

    req = request.Request(f"{base_url}{endpoint}", headers=headers, method="GET")
    with request.urlopen(req, timeout=timeout) as resp:
        return resp.status


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a simple endpoint latency benchmark.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--endpoint", default="/health")
    parser.add_argument("--attempts", type=int, default=100)
    parser.add_argument("--expected-status", type=int, default=200)
    parser.add_argument("--api-key", default="", help="Optional X-API-Key header value.")
    parser.add_argument(
        "--bearer-token",
        default="",
        help="Optional Bearer token value (without the 'Bearer ' prefix).",
    )
    parser.add_argument(
        "--output",
        default="",
        help="CSV output path. Defaults to results/performance_<timestamp>.csv.",
    )
    parser.add_argument("--timeout", type=float, default=5.0)
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.attempts < 1:
        print("[-] --attempts must be >= 1")
        return 2

    out_file = args.output
    if not out_file:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        out_file = f"results/performance_{timestamp}.csv"

    output_path = Path(out_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    latencies_ms: list[float] = []
    rows: list[tuple[int, int, str]] = []
    unexpected_count = 0

    print(
        "[+] Starting performance test: "
        f"base_url={args.base_url} endpoint={args.endpoint} attempts={args.attempts}"
    )

    total_start = time.perf_counter()
    for index in range(1, args.attempts + 1):
        request_start = time.perf_counter()
        try:
            status = make_request(
                base_url=args.base_url,
                endpoint=args.endpoint,
                timeout=args.timeout,
                api_key=args.api_key or None,
                bearer_token=args.bearer_token or None,
            )
            body_excerpt = ""
        except error.HTTPError as exc:
            status = exc.code
            body_excerpt = exc.read().decode("utf-8").replace("\n", " ")[:120]
        except error.URLError as exc:
            print(f"[-] Connection failed on request {index}: {exc}")
            return 2

        latency_ms = (time.perf_counter() - request_start) * 1000.0
        latencies_ms.append(latency_ms)
        rows.append((index, status, f"{latency_ms:.3f}"))

        if status != args.expected_status:
            unexpected_count += 1
            print(
                f"[!] Unexpected status at request {index}: status={status}, "
                f"expected={args.expected_status}, body={body_excerpt}"
            )

    total_seconds = time.perf_counter() - total_start
    avg_latency = statistics.mean(latencies_ms)
    p95_latency = sorted(latencies_ms)[max(0, int(len(latencies_ms) * 0.95) - 1)]
    rps = args.attempts / total_seconds if total_seconds > 0 else 0.0

    with output_path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["request_index", "status_code", "latency_ms"])
        writer.writerows(rows)

    print(f"[+] CSV written to: {output_path}")
    print(f"[+] Average latency (ms): {avg_latency:.3f}")
    print(f"[+] P95 latency (ms): {p95_latency:.3f}")
    print(f"[+] Requests per second: {rps:.3f}")
    print(f"[+] Unexpected responses: {unexpected_count}/{args.attempts}")

    if unexpected_count > 0:
        print("[-] FAIL: Performance run observed unexpected status codes.")
        return 1

    print("[+] PASS: All responses matched expected status.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
