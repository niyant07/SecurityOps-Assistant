"""Persist an engagement :class:`Scope` with its project.

In-scope and out-of-scope entries are saved as project assets (so every module
shares one authorization boundary); program, platform, target type and rules are
saved in the project's ``scope_notes`` under a recognizable header.
"""

from __future__ import annotations

from ..core.database import Database
from ..models import Asset, AssetType, Project, ScopeState
from .scope import Scope, TargetType, _normalize

NOTES_HEADER = "# Bug Bounty Engagement"


def scope_from_assets(assets: list[Asset]) -> Scope:
    """The authorization boundary defined by a project's assets."""
    scope = Scope()
    for asset in assets:
        entry = _normalize(asset.identifier)
        if not entry:
            continue
        if asset.scope is ScopeState.IN_SCOPE and entry not in scope.in_scope:
            scope.in_scope.append(entry)
        elif asset.scope is ScopeState.OUT_OF_SCOPE and entry not in scope.out_of_scope:
            scope.out_of_scope.append(entry)
    return scope


def scope_to_notes(scope: Scope) -> str:
    return (f"{NOTES_HEADER}\nProgram: {scope.program}\nPlatform: {scope.platform}\n"
            f"Target-Type: {scope.target_type.value}\n\n{scope.rules}").strip()


def load_scope(project: Project | None, assets: list[Asset]) -> Scope:
    """Rebuild a project's scope from its assets and notes header."""
    scope = scope_from_assets(assets)
    if project and project.scope_notes.startswith(NOTES_HEADER):
        for line in project.scope_notes.splitlines():
            if line.startswith("Program:"):
                scope.program = line.split(":", 1)[1].strip()
            elif line.startswith("Platform:"):
                scope.platform = line.split(":", 1)[1].strip()
            elif line.startswith("Target-Type:"):
                value = line.split(":", 1)[1].strip()
                for target_type in TargetType:
                    if target_type.value == value:
                        scope.target_type = target_type
        body = project.scope_notes.split("\n\n", 1)
        scope.rules = body[1].strip() if len(body) > 1 else ""
    return scope


def asset_type_for(target_type: TargetType) -> AssetType:
    return {
        TargetType.WEB: AssetType.WEB_APP,
        TargetType.API: AssetType.URL,
        TargetType.MOBILE_BACKEND: AssetType.URL,
        TargetType.DESKTOP: AssetType.HOST,
        TargetType.NETWORK: AssetType.NETWORK,
    }.get(target_type, AssetType.OTHER)


def persist_scope(database: Database, project_id: int, scope: Scope) -> None:
    """Save scope entries as assets and the engagement details as scope notes."""
    existing = {a.identifier for a in database.assets.list_for_project(project_id)}
    asset_type = asset_type_for(scope.target_type)
    for entries, state in ((scope.in_scope, ScopeState.IN_SCOPE),
                           (scope.out_of_scope, ScopeState.OUT_OF_SCOPE)):
        for identifier in entries:
            if identifier not in existing:
                database.assets.create(Asset(project_id=project_id, identifier=identifier,
                                             asset_type=asset_type, scope=state,
                                             label="bug-bounty"))
    project = database.projects.get(project_id)
    if project is not None:
        project.scope_notes = scope_to_notes(scope)
        database.projects.update(project)
