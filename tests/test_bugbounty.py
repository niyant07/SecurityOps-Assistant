"""Tests for the AI Bug Bounty Assistant module: scope, methodology, planner."""

from __future__ import annotations

import pytest

from securityops.bugbounty.methodology import methodology_for, tool_chain_for
from securityops.bugbounty.planner import BugBountyPlanner
from securityops.bugbounty.scope import (
    ScopeValidator,
    TargetType,
    parse_scope_text,
)


# --------------------------------------------------------------------------- #
# Scope parsing
# --------------------------------------------------------------------------- #
def test_parse_sections() -> None:
    scope = parse_scope_text(
        "In scope:\n- *.example.com\n- 10.0.0.0/24\n"
        "Out of scope:\n- admin.example.com\n"
        "Rules:\nNo scanning above 5 req/s."
    )
    assert "*.example.com" in scope.in_scope
    assert "10.0.0.0/24" in scope.in_scope
    assert "admin.example.com" in scope.out_of_scope
    assert "5 req/s" in scope.rules


def test_parse_without_headers_defaults_in_scope() -> None:
    scope = parse_scope_text("example.com\napi.example.com")
    assert scope.in_scope == ["example.com", "api.example.com"]
    assert scope.out_of_scope == []


def test_parse_strips_scheme_and_bullets() -> None:
    scope = parse_scope_text("* https://shop.example.com/path")
    assert scope.in_scope == ["shop.example.com"]


# --------------------------------------------------------------------------- #
# Scope validation
# --------------------------------------------------------------------------- #
@pytest.fixture()
def validator() -> ScopeValidator:
    scope = parse_scope_text(
        "In scope:\n- *.example.com\n- 10.0.0.0/24\nOut of scope:\n- admin.example.com"
    )
    return ScopeValidator(scope)


@pytest.mark.parametrize(
    "target,expected",
    [
        ("app.example.com", True),
        ("example.com", True),
        ("https://shop.example.com/cart", True),
        ("10.0.0.42", True),
        ("admin.example.com", False),   # out of scope wins
        ("evil.com", False),            # not listed
        ("10.1.0.1", False),            # outside CIDR
    ],
)
def test_classify(validator: ScopeValidator, target: str, expected: bool) -> None:
    assert validator.is_in_scope(target) is expected


def test_out_of_scope_beats_in_scope(validator: ScopeValidator) -> None:
    # admin.example.com matches *.example.com but is explicitly excluded.
    decision = validator.classify("admin.example.com")
    assert not decision.in_scope
    assert "out-of-scope" in decision.reason.lower()


# --------------------------------------------------------------------------- #
# Methodology
# --------------------------------------------------------------------------- #
def test_web_methodology_has_phases() -> None:
    phases = methodology_for(TargetType.WEB)
    assert len(phases) >= 3
    names = [p.name for p in phases]
    assert "Reconnaissance" in names


def test_tool_chain_is_deduplicated_and_ordered() -> None:
    chain = tool_chain_for(TargetType.WEB)
    assert chain[0] == "subfinder"  # recon first
    assert len(chain) == len(set(chain))


def test_target_types_all_have_a_chain() -> None:
    for t in TargetType:
        assert tool_chain_for(t)  # non-empty


# --------------------------------------------------------------------------- #
# Planner (scope-gated)
# --------------------------------------------------------------------------- #
@pytest.fixture()
def bb_planner(all_installed_tools) -> BugBountyPlanner:
    return BugBountyPlanner(all_installed_tools)


def _web_scope():
    scope = parse_scope_text("In scope:\n- *.example.com\nOut of scope:\n- admin.example.com")
    scope.target_type = TargetType.WEB
    scope.program = "Acme BBP"
    return scope


def test_plan_in_scope_target(bb_planner: BugBountyPlanner) -> None:
    plan = bb_planner.plan("assess app.example.com for issues", _web_scope())
    assert not plan.refused
    assert plan.steps
    assert plan.source == "bugbounty"
    assert "Acme BBP" in plan.summary


def test_plan_refuses_out_of_scope(bb_planner: BugBountyPlanner) -> None:
    plan = bb_planner.plan("assess admin.example.com", _web_scope())
    assert plan.refused
    assert not plan.steps


def test_plan_refuses_unlisted_target(bb_planner: BugBountyPlanner) -> None:
    plan = bb_planner.plan("assess evil.com", _web_scope())
    assert plan.refused


def test_plan_refuses_harmful_goal(bb_planner: BugBountyPlanner) -> None:
    plan = bb_planner.plan("deploy malware on app.example.com", _web_scope())
    assert plan.refused
    assert "prohibited" in plan.refusal_reason.lower()


def test_plan_defaults_to_first_in_scope_asset(bb_planner: BugBountyPlanner) -> None:
    # No target in the goal → use the scope's first in-scope asset.
    scope = parse_scope_text("In scope:\n- shop.example.com")
    scope.target_type = TargetType.WEB
    plan = bb_planner.plan("assess this web application for common issues", scope)
    assert not plan.refused
    assert plan.steps


def test_empty_scope_asks_for_import(bb_planner: BugBountyPlanner) -> None:
    from securityops.bugbounty.scope import Scope

    plan = bb_planner.plan("assess example.com", Scope())
    assert not plan.steps
    assert "scope" in plan.summary.lower()


def test_recommend_next_advances_phases(bb_planner: BugBountyPlanner) -> None:
    scope = _web_scope()
    rec = bb_planner.recommend_next(scope, ["subfinder", "amass", "dnsrecon"])
    assert "Enumeration" in rec or "nmap" in rec
