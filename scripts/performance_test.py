#!/usr/bin/env python3
import csv
import os
import time
from datetime import datetime, timezone
from urllib import error, request

BASE_URL = "http://127.0.0.1:8000"
ENDPOINT = "/health"
REQUESTS_TOTAL = 100


def get(path: str) -> int:
    req = request.Request(f"{BASE_URL}{path}", method="GET")
    with request.urlopen(req, timeout=5) as resp:
        return resp.status


def main() -> None:
    os.makedirs("results", exist_ok=True)

    latencies = []
    start = time.perf_counter()

    for _ in range(REQUESTS_TOTAL):
        req_start = time.perf_counter()
        try:
            status = get(ENDPOINT)
        except error.HTTPError as exc:
            print(f"[-] Unexpected status during test: {exc.code}")
            return

        req_end = time.perf_counter()
        if status != 200:
            print(f"[-] Unexpected status during test: {status}")
            return

        latencies.append((req_end - req_start) * 1000.0)

    total_seconds = time.perf_counter() - start
    avg_latency = sum(latencies) / len(latencies)
    rps = REQUESTS_TOTAL / total_seconds if total_seconds > 0 else 0.0

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_file = f"results/performance_{timestamp}.csv"

    with open(out_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["request_index", "latency_ms"])
        for i, latency in enumerate(latencies, start=1):
            writer.writerow([i, f"{latency:.3f}"])

    print(f"[+] Performance test complete: {REQUESTS_TOTAL} requests")
    print(f"[+] Average latency (ms): {avg_latency:.3f}")
    print(f"[+] Requests per second: {rps:.3f}")
    print(f"[+] CSV written to: {out_file}")


if __name__ == "__main__":
    main()
