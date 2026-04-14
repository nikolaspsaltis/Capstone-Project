"""
File-driven policy evaluator.

This module implements a lightweight attribute-based access control (ABAC) engine
backed by YAML policy files. Each YAML file under the policies/ directory contains
a list of rules; every rule specifies conditions under which a request is denied.
The evaluation model is deny-by-first-match: as soon as one rule matches the
supplied context, evaluation stops and a deny decision is returned. If no rule
matches, the request is allowed.

Production migration path: replace _load_rules() and evaluate() with calls to an
Open Policy Agent (OPA) REST API endpoint. The PolicyContext and PolicyDecision
dataclasses remain unchanged — only the evaluation backend is swapped out. This
design keeps the rest of the application independent of the policy engine
implementation.

Hot-reload support: the module installs a SIGHUP signal handler so the policy
files can be reloaded at runtime (e.g. `kill -HUP <pid>`) without restarting the
application. This allows policy updates in production with zero downtime.
"""

import glob
import logging
import signal
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

# POLICY_DIR resolves the policies/ directory relative to this source file's
# location so the path remains correct regardless of the working directory.
POLICY_DIR = Path(__file__).parent.parent / "policies"


@dataclass
class PolicyContext:
    """Carries all request attributes used to evaluate policy rules.

    role: the caller's RBAC role (e.g. "user", "admin", "service").
    method: the HTTP method of the incoming request (e.g. "GET", "POST").
    path: the URL path of the incoming request (e.g. "/token/exchange").
    token_env: the environment claim embedded in the caller's JWT ("prod" by default).
    target_audience: for token-exchange requests, the audience the caller wants
        a scoped token for. None for non-exchange requests.
    """

    role: str
    method: str
    path: str
    token_env: str = "prod"
    target_audience: Optional[str] = None


@dataclass
class PolicyDecision:
    """Represents the outcome of a policy evaluation.

    allowed: True if the request passes all policy rules, False if any rule
        matched and denied the request.
    reason: a human-readable explanation supplied by the matching rule, or None
        if the request was allowed (no rule matched).
    rule_id: the unique identifier of the rule that triggered the denial, or
        None when the request is allowed. Returned to the caller so they can
        identify which policy was violated.
    """

    allowed: bool
    reason: Optional[str] = None
    rule_id: Optional[str] = None


# _rules holds the currently active set of parsed policy rules. It is replaced
# atomically on each reload so in-flight evaluations see a consistent snapshot.
_rules: list[dict] = []


def _validate_rule(rule: dict, source: str) -> bool:
    """Check that a rule dictionary contains the required fields.

    A valid rule must be a dict with an 'id' string key and a 'deny_if' dict
    that holds the match conditions. Rules that fail validation are skipped and
    a warning is logged; they do not prevent the rest of the file from loading.

    Returns True if the rule is structurally valid, False otherwise.
    """
    if not isinstance(rule, dict):
        logging.warning("policy: skipping non-dict rule in %s: %r", source, rule)
        return False
    if "id" not in rule:
        logging.warning("policy: skipping rule missing 'id' in %s: %r", source, rule)
        return False
    if "deny_if" not in rule or not isinstance(rule["deny_if"], dict):
        logging.warning(
            "policy: skipping rule %r missing 'deny_if' dict in %s", rule.get("id"), source
        )
        return False
    return True


def _load_rules() -> None:
    """Read all YAML policy files from POLICY_DIR and rebuild the active rule set.

    Files are processed in sorted order so that rule precedence is deterministic
    and can be controlled by prefixing filenames with numbers (e.g. 01_base.yaml).
    Each file is expected to contain a top-level 'rules' list; missing keys are
    ignored rather than raising an error so a malformed file does not block the
    others from loading.

    This function is called once at import time and again on every SIGHUP signal.
    """
    global _rules
    loaded = []
    for f in sorted(glob.glob(str(POLICY_DIR / "*.yaml"))):
        with open(f) as fh:
            for rule in yaml.safe_load(fh).get("rules", []):
                if _validate_rule(rule, f):
                    loaded.append(rule)
    _rules = loaded
    logging.info("policy: loaded %d rules from %s", len(_rules), POLICY_DIR)


def _rule_matches(rule: dict, ctx: PolicyContext) -> bool:
    """Return True if all conditions in a rule's deny_if block match the context.

    Each condition in deny_if is optional; a rule with fewer conditions is more
    broadly applicable. All present conditions must match for the rule to fire.
    Supported conditions:

    - role: exact string match against ctx.role.
    - method: case-insensitive match against ctx.method.
    - path_prefix: ctx.path must start with this prefix.
    - utc_hour_range: a [lo, hi] pair — the current UTC hour must satisfy lo <= hour < hi.
    - token_env: exact match against the 'env' claim in the caller's token.
    - target_audience_prefix: ctx.target_audience must start with this prefix.
    """
    d = rule.get("deny_if", {})

    # Each condition returns False early if its criterion is not met, meaning
    # the rule does NOT match on this condition alone.
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

    # All conditions that are present in the rule have matched.
    return True


def evaluate(ctx: PolicyContext) -> PolicyDecision:
    """Evaluate all loaded rules against the supplied request context.

    Iterates through _rules in order. The first matching rule triggers an
    immediate deny and its id and reason are included in the decision so callers
    can report exactly which policy was violated. If no rule matches, the request
    is allowed.

    This function is called by the token-exchange broker on every exchange request
    to enforce environment-level and audience-level access controls on top of the
    service registry's allowed_callers list.
    """
    for rule in _rules:
        if _rule_matches(rule, ctx):
            return PolicyDecision(
                allowed=False,
                reason=rule.get("reason"),
                rule_id=rule["id"],
            )
    return PolicyDecision(allowed=True)


# Install a SIGHUP handler so operators can reload policy files without restarting
# the application. The lambda discards the signal number and frame arguments that
# the signal module passes — only the reload side effect is needed.
signal.signal(signal.SIGHUP, lambda *_: _load_rules())

# Load policy rules once at import time so the evaluator is ready before the
# first request arrives. If the policies/ directory is empty, _rules stays [].
_load_rules()
