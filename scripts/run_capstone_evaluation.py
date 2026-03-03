#!/usr/bin/env python3
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = ROOT / "results"
SCRIPTS = [
    "scripts/bruteforce_login.py",
    "scripts/token_tampering.py",
    "scripts/unauthorized_admin_access.py",
    "scripts/performance_test.py",
]


def main() -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_path = RESULTS_DIR / f"evaluation_report_{ts}.md"
    summary_path = RESULTS_DIR / f"evaluation_summary_{ts}.json"

    report_lines = [
        "# Capstone Evaluation Run",
        f"- UTC timestamp: `{ts}`",
        "- Note: Start the API first (`uvicorn app.main:app --reload`) before running this script.",
        "",
    ]
    summary = {"timestamp_utc": ts, "runs": []}

    for rel_path in SCRIPTS:
        script_path = ROOT / rel_path
        proc = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=180,
        )
        log_name = f"{script_path.stem}_{ts}.log"
        log_path = RESULTS_DIR / log_name
        log_text = proc.stdout + ("\n" + proc.stderr if proc.stderr else "")
        log_path.write_text(log_text, encoding="utf-8")

        run_info = {
            "script": rel_path,
            "exit_code": proc.returncode,
            "log_file": f"results/{log_name}",
        }
        summary["runs"].append(run_info)

        report_lines.extend(
            [
                f"## {rel_path}",
                f"- Exit code: `{proc.returncode}`",
                f"- Log: `{run_info['log_file']}`",
                "",
            ]
        )

    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    report_lines.append(f"- JSON summary: `results/{summary_path.name}`")
    report_path.write_text("\n".join(report_lines) + "\n", encoding="utf-8")
    print(f"[+] Evaluation report: {report_path}")
    print(f"[+] Evaluation summary: {summary_path}")


if __name__ == "__main__":
    main()
