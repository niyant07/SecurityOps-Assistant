"""Tests for workflow execution audit persistence."""

from __future__ import annotations

from datetime import datetime, timezone

from securityops.core.config import load_config
from securityops.core.context import AppContext
from securityops.core.database import Database
from securityops.core.tasks import TaskManager
from securityops.core.tools import ToolRegistry
from securityops.models import Project, ScanStatus
from securityops.workflow.engine import WorkflowEngine
from securityops.workflow.plan import StepStatus, WorkflowPlan, WorkflowStep


def test_running_scan_record_is_updated_when_step_finishes(db: Database) -> None:
    project = db.projects.create(Project(name="Running workflow audit"))
    assert project.id is not None
    context = AppContext(load_config(), db, TaskManager(), ToolRegistry())
    engine = WorkflowEngine(context)
    engine._project_id = project.id
    started_at = datetime.now(timezone.utc)  # noqa: UP017
    step = WorkflowStep(
        tool_key="nmap",
        title="Nmap scan",
        rationale="Test scan persistence.",
        command="nmap example.test",
        target="example.test",
        status=StepStatus.RUNNING,
        started_at=started_at,
    )

    engine._persist(0, step)
    running_records = db.scans.list_for_project(project.id)
    assert len(running_records) == 1
    assert running_records[0].status is ScanStatus.RUNNING

    step.status = StepStatus.COMPLETED
    step.output = "22/tcp open ssh"
    step.exit_code = 0
    step.finished_at = datetime.now(timezone.utc)  # noqa: UP017
    engine._persist(0, step)

    completed_records = db.scans.list_for_project(project.id)
    assert len(completed_records) == 1
    assert completed_records[0].status is ScanStatus.COMPLETED
    assert completed_records[0].output == "22/tcp open ssh"
    assert completed_records[0].exit_code == 0


def test_malformed_command_fails_step_and_finishes_plan(db: Database) -> None:
    project = db.projects.create(Project(name="Malformed command"))
    assert project.id is not None
    context = AppContext(load_config(), db, TaskManager(), ToolRegistry())
    engine = WorkflowEngine(context)
    finished: list[bool] = []
    engine.plan_finished.connect(lambda: finished.append(True))
    step = WorkflowStep(
        tool_key="whatweb",
        title="WhatWeb",
        rationale="Unbalanced quote cannot be split into argv.",
        command="whatweb http://example.test/a'b",
        target="http://example.test/a'b",
        status=StepStatus.APPROVED,
    )

    engine.run(WorkflowPlan(goal="test", summary="", steps=[step]), project.id)

    assert step.status is StepStatus.FAILED
    assert "Malformed command" in step.output
    assert finished == [True]
    assert db.scans.list_for_project(project.id)[0].status is ScanStatus.FAILED
