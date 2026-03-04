#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

import matplotlib.pyplot as plt


def classify_reason(log_text: str) -> str:
    lower = log_text.lower()
    if "connectionrefusederror" in lower or "connection refused" in lower:
        return "Server unavailable"
    if "timed out" in lower or "timeout" in lower:
        return "Timeout"
    if "401" in lower or "unauthorized" in lower:
        return "Unauthorized/invalid auth"
    if "403" in lower or "forbidden" in lower:
        return "Authorization denied"
    if "traceback" in lower:
        return "Unhandled exception"
    return "Unknown"


def load_runs(summary_path: Path) -> tuple[str, list[dict]]:
    data = json.loads(summary_path.read_text(encoding="utf-8"))
    ts = data.get("timestamp_utc", "unknown")
    return ts, data.get("runs", [])


def build_records(summary_path: Path) -> tuple[str, list[dict]]:
    ts, runs = load_runs(summary_path)
    records: list[dict] = []
    root = summary_path.resolve().parents[1]
    for run in runs:
        script = Path(run["script"]).name
        exit_code = int(run.get("exit_code", 1))
        log_rel = run.get("log_file", "")
        log_path = root / log_rel
        log_text = ""
        if log_path.exists():
            log_text = log_path.read_text(encoding="utf-8", errors="replace")
        reason = classify_reason(log_text)
        records.append(
            {
                "script": script,
                "exit_code": exit_code,
                "status": "PASS" if exit_code == 0 else "FAIL",
                "reason": reason,
            }
        )
    return ts, records


def make_plot(ts: str, records: list[dict], output_path: Path) -> None:
    scripts = [r["script"] for r in records]
    exit_codes = [r["exit_code"] for r in records]
    reasons = [r["reason"] for r in records]
    colors = ["#2ca02c" if c == 0 else "#d62728" for c in exit_codes]

    reason_counts = Counter(reasons)
    reason_labels = list(reason_counts.keys())
    reason_values = [reason_counts[k] for k in reason_labels]

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(13, 8), gridspec_kw={"height_ratios": [2.0, 1.2]})

    bars = ax1.barh(scripts, exit_codes, color=colors)
    ax1.set_title("Evaluation Script Outcomes (with Failure Root Cause)", fontsize=16, pad=10)
    ax1.set_xlabel("Exit Code (0 = pass, non-zero = fail)")
    ax1.set_xlim(0, max(1, max(exit_codes) + 0.4))
    ax1.grid(axis="x", alpha=0.25)

    for bar, rec in zip(bars, records):
        y = bar.get_y() + bar.get_height() / 2
        label = f"{rec['status']} | {rec['reason']}"
        ax1.text(bar.get_width() + 0.03, y, label, va="center", fontsize=10)

    ax2.bar(reason_labels, reason_values, color="#4c78a8")
    ax2.set_title("Failure Cause Distribution", fontsize=13, pad=8)
    ax2.set_ylabel("Script count")
    ax2.grid(axis="y", alpha=0.25)
    ax2.set_ylim(0, max(1, max(reason_values) + 1))
    for i, v in enumerate(reason_values):
        ax2.text(i, v + 0.05, str(v), ha="center", va="bottom", fontsize=10)

    plt.xticks(rotation=12, ha="right")
    fig.suptitle(f"Source summary timestamp: {ts}", fontsize=10, y=0.995)
    fig.tight_layout()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, dpi=170, bbox_inches="tight")
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate evaluation diagnostic graph from summary JSON"
    )
    parser.add_argument(
        "--summary",
        default="results/evaluation_summary_20260302_182627.json",
        help="Path to evaluation_summary_*.json",
    )
    parser.add_argument(
        "--output",
        default="",
        help="Optional output PNG path (default derived from summary timestamp)",
    )
    args = parser.parse_args()

    summary_path = Path(args.summary).resolve()
    if not summary_path.exists():
        raise SystemExit(f"Summary file not found: {summary_path}")

    ts, records = build_records(summary_path)
    if not records:
        raise SystemExit("No runs found in summary file.")

    if args.output:
        output_path = Path(args.output).resolve()
    else:
        output_path = summary_path.parents[1] / "results" / f"graph_evaluation_diagnostics_{ts}.png"

    make_plot(ts, records, output_path)
    print(f"[+] Wrote: {output_path}")


if __name__ == "__main__":
    main()
