# Results Artifacts Guide

This project now keeps a minimal, submission-focused evidence set in `results/`.
Older runs are archived in `results/archive/` to reduce navigation noise.

## Minimal Evidence Set (Retained in `results/`)

- `results/evaluation_report_20260304_154048.md`
- `results/evaluation_summary_20260304_154048.json`
- `results/bruteforce_login_20260304_154048.log`
- `results/token_tampering_20260304_154048.log`
- `results/unauthorized_admin_access_20260304_154048.log`
- `results/performance_test_20260304_154048.log`
- `results/performance_20260304_154048.csv`
- `results/graph_evaluation_diagnostics_20260304_154048.png`
- `results/graph_report_combined_2x2_20260302_182627.png` (report-ready appendix figure)

## Archived Legacy Artifacts

- Location: `results/archive/`
- Contents: older timestamped runs, duplicate diagnostics, superseded CSVs, and extra logs.
- Purpose: retained for traceability while keeping top-level `results/` clean for markers.

## What Each Retained File Represents

| File | Purpose | Produced by |
|---|---|---|
| `evaluation_report_20260304_154048.md` | Human-readable evaluation summary | `python scripts/run_capstone_evaluation.py` |
| `evaluation_summary_20260304_154048.json` | Machine-readable run metadata (`script`, `exit_code`, `log_file`) | `python scripts/run_capstone_evaluation.py` |
| `*_20260304_154048.log` (four files) | Raw stdout/stderr evidence for attack/perf scripts | `python scripts/run_capstone_evaluation.py` |
| `performance_20260304_154048.csv` | Per-request latency samples (`request_index`, `latency_ms`) | `python scripts/performance_test.py` (invoked by runner) |
| `graph_evaluation_diagnostics_20260304_154048.png` | Script outcome diagnostics plot | `python scripts/plot_evaluation_diagnostics.py` |
| `graph_report_combined_2x2_20260302_182627.png` | Curated report appendix figure | retained reference figure |

## Regenerate Core Artifacts

From repo root:

```bash
cd "/home/nikolas/Documents/UoE Documents/Captone-Project"
source .venv/bin/activate
set -a
. ./.env
set +a
```

Terminal A:

```bash
alembic upgrade head
uvicorn app.main:app --reload
```

Terminal B:

```bash
python scripts/run_capstone_evaluation.py
LATEST_SUMMARY=$(ls -t results/evaluation_summary_*.json | head -n 1)
python scripts/plot_evaluation_diagnostics.py --summary "$LATEST_SUMMARY"
```

## Notes

- `results/*.csv` and `results/*.log` are git-ignored; regenerate as needed.
- To inspect historical runs, open `results/archive/`.
