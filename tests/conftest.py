"""Shared pytest fixtures.

These tests exercise the headless core (config, database, tools, assistant,
reporting) and deliberately avoid importing Qt-dependent modules.
"""

from __future__ import annotations

import pytest

from securityops.core.database import Database


@pytest.fixture()
def db() -> Database:
    """An in-memory database with a fresh schema per test."""
    database = Database(":memory:")
    yield database
    database.close()


@pytest.fixture()
def project_id(db: Database) -> int:
    from securityops.models import Project

    project = db.projects.create(Project(name="Test Engagement", authorized=True))
    assert project.id is not None
    return project.id


@pytest.fixture()
def all_installed_tools():
    """A ToolRegistry with every catalog tool marked as installed.

    Detection normally depends on the host's $PATH; for planner tests we want a
    deterministic environment where all tools are present.
    """
    from securityops.core.tools import ToolRegistry

    registry = ToolRegistry()
    for detected in registry.all():
        detected.path = f"/usr/bin/{detected.spec.binary}"
    return registry
