"""MCP server that lets AI agents (e.g. an SDLC agent) query the catalog.

Run: ``repo-catalog mcp --out data`` (stdio). Requires the ``[mcp]`` extra.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from . import __version__, query

READ_ONLY = ToolAnnotations(read_only_hint=True, open_world_hint=False)

INSTRUCTIONS = """\
Catalog of every repository in the organization plus an AI asset library (skills, agents,
prompts, rules files, MCP servers, hooks, LLM integrations).
Typical flow: search_repos / search_ai_assets to find candidates, then get_repo / get_ai_asset
for full detail. Before writing new infrastructure, call find_building_blocks: the org may
already have a GitHub Action, reusable workflow, Terraform module, Helm chart, template or API
for it. Use repos_using to find prior art for a technology ("stripe", "fastapi"),
technology_usage to learn the org's standard stack, repo_relationships for what a repo depends
on and what depends on it (blast radius), list_flags for security/maintenance/AI-governance
findings, dependency_usage for exactly which repos ship a package version (direct or
transitive, from lockfiles), and sql for anything else (tables: repos, repo_tech, repo_capabilities,
dependencies, packages, practice_checks, flags, reusables, repo_links, runtime_versions,
ai_assets, asset_tools, asset_models, asset_tags; views: tech_usage, dependency_usage,
dependency_versions, vulnerable_dependencies, flag_summary). Dependencies carry resolved
(locked) versions and purls; full per-repo SBOMs are in data/sbom/.
"""


def build_server(db_path: Path) -> MCPServer:
    """The server starts even before a catalog exists (so MCP clients connect cleanly);
    tools then explain how to create it instead of failing opaquely."""

    def con() -> sqlite3.Connection:
        if not db_path.exists():
            raise ToolError(
                f"No catalog at {db_path}. Run `repo-catalog scan --org <org>` (or "
                "`--local <folder>`) to create it, then retry."
            )
        c = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, check_same_thread=False)
        c.row_factory = sqlite3.Row
        return c

    server = MCPServer("repo-catalog", instructions=INSTRUCTIONS, version=__version__)

    @server.tool(annotations=READ_ONLY)
    def search_repos(
        query_text: str = "",
        language: str | None = None,
        technology: str | None = None,
        capability: str | None = None,
        repo_type: str | None = None,
        has_ai: bool | None = None,
        include_archived: bool = False,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Full-text search repositories by purpose, README, stack and capabilities.

        Filters: language (primary language, e.g. "Python"), technology (framework, library or
        dependency name, partial match), capability (e.g. "payments", "pdf", "auth"),
        repo_type (service, web-app, library, cli, mcp-server, monorepo, ...), has_ai.
        """
        return query.search_repos(
            con(),
            query_text,
            language=language,
            technology=technology,
            capability=capability,
            repo_type=repo_type,
            has_ai=has_ai,
            include_archived=include_archived,
            limit=min(limit, 100),
        )

    @server.tool(annotations=READ_ONLY)
    def get_repo(repo_id: str) -> dict[str, Any] | str:
        """Full catalog record for one repo ("owner/name" or just "name"): summary, stack,
        dependencies, structure, best-practice checks, ownership and AI usage. Direct
        dependencies only, and long lists are capped (see `truncated` for totals): use
        dependency_usage, repo_relationships or sql for the rest."""
        return query.get_repo(con(), repo_id) or f"No repo named {repo_id!r}."

    @server.tool(annotations=READ_ONLY)
    def search_ai_assets(
        query_text: str = "",
        kind: str | None = None,
        ecosystem: str | None = None,
        repo: str | None = None,
        min_quality: int = 0,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Search the AI asset library. kind: skill, agent, command, prompt, instructions,
        mcp-server, mcp-config, settings, hook, plugin, eval, workflow, sdk-usage.
        ecosystem: claude-code, agent-skills, copilot, cursor, agents-md, windsurf, gemini,
        crewai, langgraph, ..."""
        return query.search_assets(
            con(),
            query_text,
            kind=kind,
            ecosystem=ecosystem,
            repo=repo,
            min_quality=min_quality,
            limit=min(limit, 100),
        )

    @server.tool(annotations=READ_ONLY)
    def get_ai_asset(asset_id: str) -> dict[str, Any] | str:
        """Full AI asset including its content (skill body, prompt text, agent definition...)."""
        return query.get_asset(con(), asset_id) or f"No asset with id {asset_id!r}."

    @server.tool(annotations=READ_ONLY)
    def dependency_usage(
        package: str,
        ecosystem: str | None = None,
        version_prefix: str | None = None,
        include_transitive: bool = True,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        """Which repos ship a package, at which versions, direct or transitive, and with
        which known advisories. package is the exact name (e.g. "lodash", "requests",
        "org.springframework.boot:spring-boot-starter-web", "postgres" for images).
        ecosystem: npm, pypi, go, cargo, maven, nuget, gem, composer, docker,
        github-actions, terraform, helm... version_prefix: e.g. "4.17" or "2.".
        Use it for upgrade planning and "are we exposed to CVE-X in package Y?"."""
        return query.dependency_usage(
            con(),
            package,
            ecosystem=ecosystem,
            version_prefix=version_prefix,
            include_transitive=include_transitive,
            limit=min(limit, 1000),
        )

    @server.tool(annotations=READ_ONLY)
    def repos_using(technology: str) -> list[dict[str, Any]]:
        """Repos that use a technology or dependency (partial, case-insensitive match)."""
        return query.repos_using(con(), technology)

    @server.tool(annotations=READ_ONLY)
    def technology_usage(category: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        """How many repos use each technology. category: frameworks, libraries, testing,
        linting, databases, messaging, cloud, infrastructure, ci_cd, observability, auth, ai,
        build_tools, package_managers, languages."""
        return query.technology_usage(con(), category, limit)

    @server.tool(annotations=READ_ONLY)
    def find_building_blocks(
        query_text: str = "", kind: str | None = None, limit: int = 20
    ) -> list[dict[str, Any]]:
        """Reusable building blocks across the org, e.g. "deploy ecs", "postgres rds",
        "release npm". kind: action, reusable-workflow, terraform-module, helm-chart, template,
        api, config-package. Details include inputs, variables or API operations."""
        return query.find_building_blocks(con(), query_text, kind=kind, limit=min(limit, 100))

    @server.tool(annotations=READ_ONLY)
    def repo_relationships(repo_id: str) -> dict[str, Any] | str:
        """Org repos this repo depends on (packages, actions, workflows, Terraform modules,
        images, submodules) and the repos that depend on it. Each list shows up to 100
        links (runtime ones first); depends_on_total / used_by_total count them all."""
        return query.repo_relationships(con(), repo_id) or f"No repo named {repo_id!r}."

    @server.tool(annotations=READ_ONLY)
    def list_flags(
        severity: str | None = None,
        category: str | None = None,
        flag_id: str | None = None,
        repo: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Findings worth attention, most severe first. severity: high, medium, low.
        category: security, maintenance, ownership, ai-governance. flag_id e.g.
        committed-secret, eol-runtime, deprecated-model, workflow-script-injection,
        mcp-unpinned-package, ai-permissions-bypassed, single-maintainer."""
        return query.list_flags(
            con(),
            severity=severity,
            category=category,
            flag_id=flag_id,
            repo=repo,
            limit=min(limit, 500),
        )

    @server.tool(annotations=READ_ONLY)
    def sql(statement: str, limit: int = 200) -> list[dict[str, Any]]:
        """Run one read-only SELECT against the catalog database (see server instructions
        for tables). Full records are in the `json` columns."""
        try:
            return query.read_only_sql(con(), statement, limit=max(1, min(limit, 1000)))
        except (ValueError, sqlite3.Error) as exc:
            raise ToolError(f"SQL error: {exc}") from None

    return server


def serve(db_path: Path) -> None:
    build_server(db_path).run("stdio")
