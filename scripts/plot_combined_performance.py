#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import matplotlib.pyplot as plt

TS_RE = re.compile(r"performance_(\d{8}_\d{6})\.csv$")


@dataclass
class RunData:
    path: Path
    timestamp_label: str
    timestamp_dt: datetime
    request_index: list[int]
    latencies_ms: list[float]
    status_codes: list[int]


def parse_timestamp(path: Path) -> tuple[str, datetime]:
    match = TS_RE.search(path.name)
    if match:
        ts = match.group(1)
        dt = datetime.strptime(ts, "%Y%m%d_%H%M%S").replace(tzinfo=timezone.utc)
        return ts, dt
    ts = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
    dt = datetime.strptime(ts, "%Y%m%d_%H%M%S").replace(tzinfo=timezone.utc)
    return ts, dt


def percentile(values: list[float], p: float) -> float:
    if not values:
        return math.nan
    ordered = sorted(values)
    idx = max(0, min(len(ordered) - 1, math.ceil((p / 100.0) * len(ordered)) - 1))
    return ordered[idx]


def rolling_mean(values: list[float], window: int) -> list[float]:
    if not values:
        return []
    out: list[float] = []
    running = 0.0
    for i, v in enumerate(values):
        running += v
        if i >= window:
            running -= values[i - window]
        denom = min(i + 1, window)
        out.append(running / float(denom))
    return out


def load_run(path: Path) -> RunData | None:
    request_index: list[int] = []
    latencies_ms: list[float] = []
    status_codes: list[int] = []
    with path.open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames or "latency_ms" not in reader.fieldnames:
            return None
        for i, row in enumerate(reader, start=1):
            latency_raw = (row.get("latency_ms") or "").strip()
            if not latency_raw:
                continue
            try:
                latency = float(latency_raw)
            except ValueError:
                continue
            idx_raw = (row.get("request_index") or "").strip()
            try:
                idx = int(idx_raw) if idx_raw else i
            except ValueError:
                idx = i
            request_index.append(idx)
            latencies_ms.append(latency)
            status_raw = (row.get("status_code") or "").strip()
            if status_raw:
                try:
                    status_codes.append(int(status_raw))
                except ValueError:
                    pass
    if not latencies_ms:
        return None
    ts_label, ts_dt = parse_timestamp(path)
    return RunData(
        path=path,
        timestamp_label=ts_label,
        timestamp_dt=ts_dt,
        request_index=request_index,
        latencies_ms=latencies_ms,
        status_codes=status_codes,
    )


def gather_runs(files: Iterable[Path]) -> list[RunData]:
    runs: list[RunData] = []
    for path in files:
        run = load_run(path)
        if run:
            runs.append(run)
    runs.sort(key=lambda r: r.timestamp_dt)
    return runs


def make_output_path(runs: list[RunData], explicit_output: str) -> Path:
    if explicit_output:
        return Path(explicit_output).resolve()
    latest_ts = (
        runs[-1].timestamp_label if runs else datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    )
    return (Path.cwd() / "results" / f"graph_performance_combined_2x2_{latest_ts}.png").resolve()


def build_stats(runs: list[RunData]) -> dict[str, object]:
    labels = [r.timestamp_dt.strftime("%m-%d %H:%M") for r in runs]
    mean_vals = [sum(r.latencies_ms) / len(r.latencies_ms) for r in runs]
    p95_vals = [percentile(r.latencies_ms, 95) for r in runs]
    p99_vals = [percentile(r.latencies_ms, 99) for r in runs]
    return {
        "labels": labels,
        "x": list(range(len(runs))),
        "mean_vals": mean_vals,
        "p95_vals": p95_vals,
        "p99_vals": p99_vals,
        "latest": runs[-1],
        "first": runs[0],
        "median_run": runs[len(runs) // 2],
    }


def plot_trend_panel(
    ax,
    labels: list[str],
    x: list[int],
    mean_vals: list[float],
    p95_vals: list[float],
    p99_vals: list[float],
) -> None:
    ax.plot(x, mean_vals, marker="o", linewidth=2.0, color="#1f77b4", label="Mean")
    ax.plot(x, p95_vals, marker="s", linewidth=2.0, color="#ff7f0e", label="P95")
    ax.plot(x, p99_vals, marker="^", linewidth=1.6, color="#2ca02c", label="P99")
    ax.set_title("Run-to-Run Latency Trend")
    ax.set_ylabel("Latency (ms)")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=25, ha="right")
    ax.grid(alpha=0.25)
    ax.legend(frameon=False)
    ax.scatter(x[-1], p95_vals[-1], color="#d62728", zorder=5)
    ax.annotate(
        f"Latest P95: {p95_vals[-1]:.2f} ms",
        xy=(x[-1], p95_vals[-1]),
        xytext=(-90, 18),
        textcoords="offset points",
        fontsize=9,
        arrowprops={"arrowstyle": "->", "lw": 0.8},
    )


def plot_distribution_panel(ax, runs: list[RunData], labels: list[str]) -> None:
    ax.boxplot(
        [r.latencies_ms for r in runs],
        tick_labels=labels,
        patch_artist=True,
        medianprops={"color": "#111111", "linewidth": 1.6},
        boxprops={"facecolor": "#9ecae1", "alpha": 0.75},
        whiskerprops={"linewidth": 1.1},
        capprops={"linewidth": 1.1},
        flierprops={"marker": ".", "markersize": 3, "alpha": 0.5},
    )
    ax.set_title("Latency Distribution by Run")
    ax.set_ylabel("Latency (ms)")
    ax.tick_params(axis="x", rotation=25)
    ax.grid(axis="y", alpha=0.25)


def plot_latest_profile_panel(ax, latest: RunData) -> None:
    rolling = rolling_mean(latest.latencies_ms, window=7)
    ax.plot(
        latest.request_index,
        latest.latencies_ms,
        color="#7f7f7f",
        linewidth=1.0,
        alpha=0.8,
        label="Per request",
    )
    ax.plot(
        latest.request_index,
        rolling,
        color="#d62728",
        linewidth=2.0,
        label="7-request rolling mean",
    )
    ax.set_title(f"Latest Run Profile ({latest.timestamp_dt.strftime('%Y-%m-%d %H:%M UTC')})")
    ax.set_xlabel("Request index")
    ax.set_ylabel("Latency (ms)")
    ax.grid(alpha=0.25)
    ax.legend(frameon=False)


def plot_cdf_panel(ax, first: RunData, median_run: RunData, latest: RunData) -> None:
    cdf_runs = [first, median_run, latest]
    seen_paths: set[Path] = set()
    cdf_palette = ["#1f77b4", "#2ca02c", "#d62728"]
    for color, run in zip(cdf_palette, cdf_runs):
        if run.path in seen_paths:
            continue
        seen_paths.add(run.path)
        ordered = sorted(run.latencies_ms)
        y = [(i + 1) / len(ordered) for i in range(len(ordered))]
        ax.plot(
            ordered,
            y,
            linewidth=2.0,
            color=color,
            label=run.timestamp_dt.strftime("%Y-%m-%d %H:%M"),
        )
    ax.set_title("Empirical CDF (First vs Middle vs Latest)")
    ax.set_xlabel("Latency (ms)")
    ax.set_ylabel("Cumulative probability")
    ax.set_ylim(0.0, 1.01)
    ax.grid(alpha=0.25)
    ax.legend(frameon=False, fontsize=9)


def render_plot(runs: list[RunData], output_path: Path, title: str) -> None:
    stats = build_stats(runs)
    labels = stats["labels"]
    x = stats["x"]
    mean_vals = stats["mean_vals"]
    p95_vals = stats["p95_vals"]
    p99_vals = stats["p99_vals"]
    latest = stats["latest"]
    first = stats["first"]
    median_run = stats["median_run"]

    assert isinstance(labels, list)
    assert isinstance(x, list)
    assert isinstance(mean_vals, list)
    assert isinstance(p95_vals, list)
    assert isinstance(p99_vals, list)
    assert isinstance(latest, RunData)
    assert isinstance(first, RunData)
    assert isinstance(median_run, RunData)

    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 10))
    plot_trend_panel(ax1, labels, x, mean_vals, p95_vals, p99_vals)
    plot_distribution_panel(ax2, runs, labels)
    plot_latest_profile_panel(ax3, latest)
    plot_cdf_panel(ax4, first, median_run, latest)

    success_text = "N/A"
    if latest.status_codes:
        ok = sum(1 for s in latest.status_codes if s == 200)
        success_text = f"{(ok / len(latest.status_codes)) * 100.0:.1f}%"

    fig.suptitle(
        f"{title}\nRuns={len(runs)}  Latest mean={mean_vals[-1]:.2f} ms  "
        f"Latest P95={p95_vals[-1]:.2f} ms  Latest success={success_text}",
        fontsize=14,
        y=0.98,
    )
    fig.tight_layout(rect=(0, 0, 1, 0.94))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close(fig)


def render_split_plots(runs: list[RunData], output_dir: Path, title: str) -> list[Path]:
    stats = build_stats(runs)
    labels = stats["labels"]
    x = stats["x"]
    mean_vals = stats["mean_vals"]
    p95_vals = stats["p95_vals"]
    p99_vals = stats["p99_vals"]
    latest = stats["latest"]
    first = stats["first"]
    median_run = stats["median_run"]

    assert isinstance(labels, list)
    assert isinstance(x, list)
    assert isinstance(mean_vals, list)
    assert isinstance(p95_vals, list)
    assert isinstance(p99_vals, list)
    assert isinstance(latest, RunData)
    assert isinstance(first, RunData)
    assert isinstance(median_run, RunData)

    ts = runs[-1].timestamp_label
    output_dir.mkdir(parents=True, exist_ok=True)
    outputs = [
        output_dir / f"graph_performance_trend_{ts}.png",
        output_dir / f"graph_performance_distribution_{ts}.png",
        output_dir / f"graph_performance_latest_profile_{ts}.png",
        output_dir / f"graph_performance_cdf_{ts}.png",
    ]

    fig1, ax1 = plt.subplots(figsize=(10, 6))
    plot_trend_panel(ax1, labels, x, mean_vals, p95_vals, p99_vals)
    fig1.suptitle(title, fontsize=13)
    fig1.tight_layout(rect=(0, 0, 1, 0.95))
    fig1.savefig(outputs[0], dpi=300, bbox_inches="tight")
    plt.close(fig1)

    fig2, ax2 = plt.subplots(figsize=(10, 6))
    plot_distribution_panel(ax2, runs, labels)
    fig2.suptitle(title, fontsize=13)
    fig2.tight_layout(rect=(0, 0, 1, 0.95))
    fig2.savefig(outputs[1], dpi=300, bbox_inches="tight")
    plt.close(fig2)

    fig3, ax3 = plt.subplots(figsize=(10, 6))
    plot_latest_profile_panel(ax3, latest)
    fig3.suptitle(title, fontsize=13)
    fig3.tight_layout(rect=(0, 0, 1, 0.95))
    fig3.savefig(outputs[2], dpi=300, bbox_inches="tight")
    plt.close(fig3)

    fig4, ax4 = plt.subplots(figsize=(10, 6))
    plot_cdf_panel(ax4, first, median_run, latest)
    fig4.suptitle(title, fontsize=13)
    fig4.tight_layout(rect=(0, 0, 1, 0.95))
    fig4.savefig(outputs[3], dpi=300, bbox_inches="tight")
    plt.close(fig4)

    return outputs


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate a poster-ready combined 2x2 performance graph" " from performance CSV runs."
        ),
    )
    parser.add_argument(
        "--include",
        nargs="*",
        default=["results/performance_*.csv", "results/archive/performance_*.csv"],
        help="One or more glob patterns for input CSV files.",
    )
    parser.add_argument(
        "--output",
        default="",
        help=(
            "Optional output PNG path. "
            "Defaults to results/graph_performance_combined_2x2_<latest_ts>.png"
        ),
    )
    parser.add_argument(
        "--title",
        default="Combined Performance Overview",
        help="Figure title prefix.",
    )
    parser.add_argument(
        "--split",
        action="store_true",
        help="Write four separate panel images instead of one combined 2x2 image.",
    )
    parser.add_argument(
        "--split-output-dir",
        default="results",
        help="Output directory for --split images.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    files: set[Path] = set()
    for pattern in args.include:
        files.update(Path.cwd().glob(pattern))
    runs = gather_runs(files)
    if not runs:
        raise SystemExit("No readable performance CSV runs found.")

    if args.split:
        output_dir = Path(args.split_output_dir).resolve()
        outputs = render_split_plots(runs, output_dir, title=args.title)
        for path in outputs:
            print(f"[+] Wrote: {path}")
    else:
        output_path = make_output_path(runs, args.output)
        render_plot(runs, output_path, title=args.title)
        print(f"[+] Wrote: {output_path}")


if __name__ == "__main__":
    main()
