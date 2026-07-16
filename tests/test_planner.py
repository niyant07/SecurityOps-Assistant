"""Tests for the natural-language workflow planner."""

from __future__ import annotations

import pytest

from securityops.workflow.planner import RuleBasedPlanner, extract_target
from securityops.workflow.plan import StepStatus


@pytest.fixture()
def planner(all_installed_tools) -> RuleBasedPlanner:
    return RuleBasedPlanner(all_installed_tools)


def test_ports_goal_selects_nmap(planner: RuleBasedPlanner) -> None:
    plan = planner.plan("Find the open ports of 10.0.0.5")
    tool_keys = [s.tool_key for s in plan.steps]
    assert "nmap" in tool_keys
    assert not plan.refused
    # Every step's command starts from a vetted binary path, not raw text.
    assert all(s.command.startswith("/usr/bin/") for s in plan.steps)


def test_generic_web_goal_uses_default_chain(planner: RuleBasedPlanner) -> None:
    plan = planner.plan("assess the security of http://example.com")
    tool_keys = [s.tool_key for s in plan.steps]
    assert tool_keys[0] == "nmap"
    assert "whatweb" in tool_keys and "nikto" in tool_keys


def test_harmful_goal_is_refused(planner: RuleBasedPlanner) -> None:
    plan = planner.plan("deploy ransomware on example.com and steal credentials")
    assert plan.refused
    assert not plan.steps
    assert "prohibited" in plan.refusal_reason.lower()


def test_missing_target_reports_clearly(planner: RuleBasedPlanner) -> None:
    plan = planner.plan("scan for open ports")
    assert plan.steps == []
    assert "target" in plan.summary.lower()


def test_disruptive_step_carries_warning(planner: RuleBasedPlanner) -> None:
    plan = planner.plan("test http://example.com for sql injection")
    sqlmap_steps = [s for s in plan.steps if s.tool_key == "sqlmap"]
    assert sqlmap_steps
    assert sqlmap_steps[0].warning


def test_manual_only_tools_excluded(planner: RuleBasedPlanner) -> None:
    plan = planner.plan("assess http://example.com")
    assert all(s.tool_key not in {"metasploit", "burpsuite", "hydra"} for s in plan.steps)


def test_steps_start_pending(planner: RuleBasedPlanner) -> None:
    plan = planner.plan("scan example.com ports")
    assert all(s.status == StepStatus.PENDING for s in plan.steps)


def test_missing_tools_are_skipped_not_crash() -> None:
    from securityops.core.tools import ToolRegistry

    empty = ToolRegistry(extra_paths=["/nonexistent"])
    # Force everything uninstalled.
    for d in empty.all():
        d.path = None
    plan = RuleBasedPlanner(empty).plan("scan example.com for open ports")
    assert plan.steps == []
    assert "installed" in plan.summary.lower()


@pytest.mark.parametrize(
    "goal,expected_kind",
    [
        ("scan http://example.com/app", "url"),
        ("scan 192.168.1.10", "ip"),
        ("scan example.com", "host"),
    ],
)
def test_extract_target_kinds(goal: str, expected_kind: str) -> None:
    target = extract_target(goal)
    assert target is not None
    if expected_kind == "url":
        assert target.is_url
    elif expected_kind == "ip":
        assert target.raw == "192.168.1.10"
    else:
        assert target.raw == "example.com"
