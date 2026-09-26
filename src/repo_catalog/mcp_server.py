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
for full detail. Use repos_using to find prior art for a technology ("stripe", "fastapi"),
technology_usage to learn the org's standard stack, and sql for anything else
(tables: repos, repo_tech, repo_capabilities, dependencies, packages, practice_checks,
ai_assets, asset_tools, asset_models, asset_tags; views: tech_usage, dependency_usage).
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
        dependencies, structure, best-practice checks, ownership and AI usage."""
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
        mcp-server, mcp-config, hook, plugin, eval, workflow, sdk-usage. ecosystem: claude-code,
        agent-skills, copilot, cursor, agents-md, windsurf, gemini, crewai, langgraph, ..."""
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
