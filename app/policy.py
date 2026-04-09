"""
File-driven policy evaluator.

Production swap: replace _load_rules() and evaluate() with calls to
the OPA HTTP API (https://www.openpolicyagent.org/docs/latest/rest-api/)
via the `opa-python-client` package. The PolicyContext / PolicyDecision
dataclasses stay the same — only the evaluation backend changes.
"""

import glob
import logging
import signal
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

POLICY_DIR = Path(__file__).parent.parent / "policies"


@dataclass
class PolicyContext:
    role: str
    method: str
    path: str
    token_env: str = "prod"
    target_audience: Optional[str] = None


@dataclass
class PolicyDecision:
    allowed: bool
    reason: Optional[str] = None
    rule_id: Optional[str] = None


_rules: list[dict] = []


def _load_rules() -> None:
    global _rules
    loaded = []
    for f in sorted(glob.glob(str(POLICY_DIR / "*.yaml"))):
        with open(f) as fh:
            loaded.extend(yaml.safe_load(fh).get("rules", []))
    _rules = loaded
    logging.info("policy: loaded %d rules from %s", len(_rules), POLICY_DIR)


def _rule_matches(rule: dict, ctx: PolicyContext) -> bool:
    d = rule.get("deny_if", {})
    if "role" in d and ctx.role != d["role"]:
        return False
    if "method" in d and ctx.method.upper() != d["method"].upper():
        return False
    if "path_prefix" in d and not ctx.path.startswith(d["path_prefix"]):
        return False
    if "utc_hour_range" in d:
        hour = datetime.now(timezone.utc).hour
        lo, hi = d["utc_hour_range"]
        if not (lo <= hour < hi):
            return False
    if "token_env" in d and ctx.token_env != d["token_env"]:
        return False
    if "target_audience_prefix" in d:
        if not ctx.target_audience:
            return False
        if not ctx.target_audience.startswith(d["target_audience_prefix"]):
            return False
    return True


def evaluate(ctx: PolicyContext) -> PolicyDecision:
    for rule in _rules:
        if _rule_matches(rule, ctx):
            return PolicyDecision(
                allowed=False,
                reason=rule.get("reason"),
                rule_id=rule["id"],
            )
    return PolicyDecision(allowed=True)


# Hot-reload on SIGHUP
signal.signal(signal.SIGHUP, lambda *_: _load_rules())

# Initial load at import time
_load_rules()
