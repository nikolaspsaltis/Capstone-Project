from datetime import datetime, timezone
from unittest.mock import patch

from app.policy import PolicyContext, evaluate

# --- block_user_admin_endpoints -------------------------------------------


def test_user_blocked_from_admin_path():
    d = evaluate(PolicyContext(role="user", method="GET", path="/admin/users"))
    assert d.allowed is False
    assert d.rule_id == "block_user_admin_endpoints"


def test_admin_allowed_on_admin_path():
    d = evaluate(PolicyContext(role="admin", method="GET", path="/admin/users"))
    assert d.allowed is True


def test_user_allowed_on_non_admin_path():
    d = evaluate(PolicyContext(role="user", method="GET", path="/data"))
    assert d.allowed is True


# --- block_maintenance_window -----------------------------------------------


def _at_hour(hour: int):
    return datetime(2024, 1, 1, hour, 0, 0, tzinfo=timezone.utc)


def test_maintenance_post_blocked_in_window():
    with patch("app.policy.datetime") as m:
        m.now.return_value = _at_hour(3)
        d = evaluate(PolicyContext(role="admin", method="POST", path="/admin/maintenance/cleanup"))
    assert d.allowed is False
    assert d.rule_id == "block_maintenance_window"


def test_maintenance_post_allowed_outside_window():
    with patch("app.policy.datetime") as m:
        m.now.return_value = _at_hour(10)
        d = evaluate(PolicyContext(role="admin", method="POST", path="/admin/maintenance/cleanup"))
    assert d.allowed is True


def test_maintenance_get_always_allowed_in_window():
    with patch("app.policy.datetime") as m:
        m.now.return_value = _at_hour(3)
        d = evaluate(PolicyContext(role="admin", method="GET", path="/admin/maintenance/cleanup"))
    assert d.allowed is True  # rule only fires on POST


# --- block_dev_targeting_prod -----------------------------------------------


def test_dev_token_blocked_from_prod_audience():
    d = evaluate(
        PolicyContext(
            role="user",
            method="POST",
            path="/token/exchange",
            token_env="dev",
            target_audience="https://prod.billing.internal",
        )
    )
    assert d.allowed is False
    assert d.rule_id == "block_dev_targeting_prod"


def test_prod_token_allowed_on_prod_audience():
    d = evaluate(
        PolicyContext(
            role="user",
            method="POST",
            path="/token/exchange",
            token_env="prod",
            target_audience="https://prod.billing.internal",
        )
    )
    assert d.allowed is True


def test_dev_token_allowed_on_staging_audience():
    d = evaluate(
        PolicyContext(
            role="user",
            method="POST",
            path="/token/exchange",
            token_env="dev",
            target_audience="https://staging.billing.internal",
        )
    )
    assert d.allowed is True  # prefix is "https://prod." — no match
