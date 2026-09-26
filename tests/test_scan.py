"""End-to-end: build a realistic fixture repo, scan it, and check both catalogs."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from pathlib import Path

import pytest
import yaml

from repo_catalog.github import RepoRef
from repo_catalog.models import AIAsset
from repo_catalog.outputs import exports, store
from repo_catalog.outputs.sqlite import build_sqlite
from repo_catalog.query import get_asset, repos_using, search_assets, search_repos
from repo_catalog.scanner import ScanOptions, ScanResult, analyze_checkout, mark_duplicates

SKILL = """---
name: pdf-report
description: Generate branded PDF reports from JSON. Use when the user asks for a report.
license: MIT
allowed-tools: Read Bash(python:*)
metadata:
  owner: platform
---
# PDF report

## Steps
1. Load data
2. Render with ReportLab

## Example
```bash
python scripts/render.py data.json
```
"""

SUBAGENT = """---
name: code-reviewer
description: Reviews diffs for bugs. Use proactively after edits.
tools: Read, Grep, Glob
model: sonnet
---
You are a senior reviewer. Check correctness first.
"""

FILES = {
    "README.md": "# Billing Service\n\nHandles invoices and Stripe payments for all products. "
    "It exposes a REST API used by the web app.\n\n## Features\n- Invoice PDFs\n- Refunds\n",
    "LICENSE": "MIT License\n...",
    ".gitignore": "node_modules\n",
    ".github/CODEOWNERS": "* @acme/billing-team\n",
    ".github/dependabot.yml": "version: 2\n",
    ".github/workflows/ci.yml": "on: push\npermissions:\n  contents: read\njobs:\n  t:\n"
    "    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@"
    "0123456789abcdef0123456789abcdef01234567\n      - run: pytest\n",
    ".github/workflows/claude.yml": "name: Claude review\non:\n  pull_request:\njobs:\n  r:\n"
    "    runs-on: ubuntu-latest\n    steps:\n      - uses: anthropics/claude-code-action@v1\n"
    "        with:\n          prompt: |\n            Review this PR for security issues.\n",
    "pyproject.toml": '[project]\nname = "billing"\ndescription = "Billing API"\n'
    'dependencies = ["fastapi", "stripe", "sqlalchemy", "psycopg", "anthropic", "mcp"]\n'
    "[tool.ruff]\nline-length = 100\n",
    "uv.lock": "version = 1\n",
    "src/billing/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
    "src/billing/llm.py": (
        "import anthropic\n\nclient = anthropic.Anthropic()\n\n"
        'SYSTEM_PROMPT = """You are a billing assistant. Explain invoices to customers in plain '
        "language, never reveal internal account notes, and always cite the invoice number. "
        "If the customer asks for a refund, collect the reason and hand off to a human agent "
        'with a short summary of the conversation so far."""\n\n'
        'def ask(q):\n    return client.messages.create(model="claude-opus-5", max_tokens=100,\n'
        '        system=SYSTEM_PROMPT, messages=[{"role": "user", "content": q}])\n'
    ),
    "src/billing/mcp_server.py": (
        'from mcp.server.mcpserver import MCPServer\n\nserver = MCPServer("billing-tools")\n\n'
        "@server.tool()\ndef get_invoice(invoice_id: str) -> dict:\n"
        '    """Fetch an invoice by id."""\n    return {}\n\n'
        '@server.tool(name="refund")\nasync def do_refund(x: str) -> str:\n    return x\n'
    ),
    "tests/test_main.py": "def test_ok():\n    assert True\n",
    "CLAUDE.md": "# Billing\n\nRun `uv run pytest` to test. Build with `uv build`.\n",
    "AGENTS.md": "# Agents\n\nUse ruff to lint.\n",
    ".claude/skills/pdf-report/SKILL.md": SKILL,
    ".claude/skills/pdf-report/scripts/render.py": "print('render')\n",
    ".claude/agents/code-reviewer.md": SUBAGENT,
    ".claude/commands/git/fix-issue.md": "---\ndescription: Fix a GitHub issue\n"
    "argument-hint: [issue-number]\n---\nFix issue $ARGUMENTS following our standards.\n",
    ".claude/settings.json": json.dumps(
        {
            "hooks": {
                "PostToolUse": [
                    {
                        "matcher": "Edit|Write",
                        "hooks": [{"type": "command", "command": "ruff format"}],
                    }
                ]
            }
        }
    ),
    ".mcp.json": json.dumps(
        {
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"],
                    "env": {"GITHUB_TOKEN": "ghp_supersecretvalue"},
                },
                "sentry": {"type": "http", "url": "https://mcp.sentry.dev/mcp"},
            }
        }
    ),
    ".cursor/rules/python.mdc": "---\ndescription: Python style\nglobs: *.py\n"
    "alwaysApply: false\n---\nUse type hints everywhere.\n",
    ".github/prompts/explain.prompt.md": "---\nmode: ask\ndescription: Explain code\n---\n"
    "Explain the selected code step by step.\n",
    ".github/copilot-instructions.md": "Prefer FastAPI dependency injection.\n",
    "crew/config/agents.yaml": yaml.safe_dump(
        {
            "researcher": {
                "role": "Market Researcher",
                "goal": "Find pricing data",
                "backstory": "Analyst",
            }
        }
    ),
    "agent/agent-card.json": json.dumps(
        {
            "name": "Billing Agent",
            "description": "Answers billing questions",
            "capabilities": {},
            "skills": [{"id": "explain-invoice", "name": "Explain invoice", "tags": ["billing"]}],
        }
    ),
    "prompts/summarize.md": "Summarize the following invoice for {audience}:\n\n{{invoice}}\n",
    "promptfooconfig.yaml": yaml.safe_dump(
        {
            "description": "Billing assistant evals",
            "providers": ["anthropic:messages:claude-opus-5"],
            "prompts": ["prompts/summarize.md"],
            "tests": [{"vars": {"x": 1}}],
        }
    ),
}


@pytest.fixture
def scanned(make_repo: Callable[..., tuple[RepoRef, Path]], tmp_path: Path) -> ScanResult:
    ref, root = make_repo(FILES, name="billing")
    return analyze_checkout(ref, root, ScanOptions(workdir=tmp_path / "work"))


def _by(assets: list[AIAsset], kind: str) -> dict[str, AIAsset]:
    return {a.name: a for a in assets if a.kind == kind}


def test_general_catalog(scanned: ScanResult) -> None:
    r = scanned.repo
    assert r.id == "acme/billing"
    assert r.summary.readme_title == "Billing Service"
    assert "Stripe payments" in (r.summary.readme_excerpt or "")
    assert r.summary.key_features == ["Invoice PDFs", "Refunds"]
    assert r.summary.one_liner == "billing description" and r.summary.source == "github"
    s = r.stack
    assert s.primary_language == "Python"
    assert "FastAPI" in s.frameworks
    assert {"PostgreSQL", "SQLAlchemy"} <= set(s.databases)
    assert "Stripe" in s.libraries and "payments" in r.capabilities
    assert {"Anthropic SDK", "Model Context Protocol"} <= set(s.ai)
    assert {"GitHub Actions", "Dependabot"} <= set(s.ci_cd)
    assert "Ruff" in s.linting and "uv" in s.package_managers
    assert r.structure.repo_type == "mcp-server"
    assert r.ownership.codeowners == ["@acme/billing-team"]
    assert r.ownership.commit_count == 1
    assert r.ownership.top_contributors[0].name == "Test Author"
    assert r.license == "MIT"
    checks = {c.id: c.passed for c in r.practices.checks}
    assert checks["tests"] and checks["ci"] and checks["ci-runs-tests"] and checks["lockfile"]
    assert checks["codeowners"] and checks["dependency-updates"] and checks["license"]
    assert checks["workflow-permissions"] is False  # claude.yml lacks a permissions block
    assert not checks["security-policy"]
    assert 0 < r.practices.score <= 100


def test_ai_asset_library(scanned: ScanResult) -> None:
    assets = scanned.assets
    skill = _by(assets, "skill")["pdf-report"]
    assert skill.ecosystem == "claude-code" and skill.license == "MIT"
    assert skill.tools == ["Read", "Bash(python:*)"]
    assert skill.files[0].path == "scripts/render.py"
    assert "owner:platform" in skill.tags
    assert (
        skill.url
        == "https://github.com/acme/billing/blob/abc123/.claude/skills/pdf-report/SKILL.md"
    )
    assert skill.last_author == "Test Author" and skill.commit_count == 1
    assert skill.quality_score >= 80, skill.quality_notes

    agent = _by(assets, "agent")["code-reviewer"]
    assert agent.tools == ["Read", "Grep", "Glob"] and agent.models == ["sonnet"]

    cmd = _by(assets, "command")
    # Claude Code invokes .claude/commands/git/fix-issue.md as /fix-issue; git is a label
    assert cmd["/fix-issue"].arguments[0] == "[issue-number]"
    assert "namespace:git" in cmd["/fix-issue"].tags
    assert _by(assets, "command")["/explain"].ecosystem == "copilot"

    instructions = {a.path: a for a in assets if a.kind == "instructions"}
    assert {
        "CLAUDE.md",
        "AGENTS.md",
        ".cursor/rules/python.mdc",
        ".github/copilot-instructions.md",
    } <= set(instructions)
    assert instructions[".cursor/rules/python.mdc"].triggers == ["*.py"]

    hook = _by(assets, "hook")["PostToolUse [Edit|Write]"]
    assert hook.frontmatter["commands"] == ["ruff format"]

    mcp_cfg = next(a for a in assets if a.kind == "mcp-config")
    assert set(mcp_cfg.mcp_servers) == {"github", "sentry"}
    assert "ghp_supersecretvalue" not in (mcp_cfg.content or "")  # secrets never stored
    assert mcp_cfg.frontmatter["servers"]["github"]["env"] == ["GITHUB_TOKEN"]

    server = _by(assets, "mcp-server")["billing-tools"]
    assert server.tools == ["get_invoice", "refund"]
    assert server.frontmatter["tool_descriptions"]["get_invoice"] == "Fetch an invoice by id."

    prompts = {a.name: a for a in assets if a.kind == "prompt"}
    inline = prompts["llm.py:SYSTEM_PROMPT"]
    assert inline.confidence == "medium" and inline.url.endswith("llm.py#L5")
    assert set(prompts["summarize"].arguments) == {"audience", "invoice"}

    sdk = next(a for a in assets if a.kind == "sdk-usage" and a.ecosystem == "anthropic")
    assert "claude-opus-5" in sdk.models and "src/billing/llm.py" in sdk.frontmatter["files"]

    assert _by(assets, "agent")["researcher"].ecosystem == "crewai"
    assert _by(assets, "agent")["Billing Agent"].tools == ["explain-invoice"]
    assert any(a.kind == "eval" and a.ecosystem == "promptfoo" for a in assets)
    wf = next(a for a in assets if a.kind == "workflow" and a.ecosystem == "claude-code")
    assert "Review this PR" in (wf.excerpt or "")

    ai = scanned.repo.ai
    assert ai.has_ai and ai.asset_count == len(assets)
    assert "billing-tools" in ai.mcp_servers_provided
    assert {"github", "sentry"} <= set(ai.mcp_servers_consumed)
    assert "claude-opus-5" in ai.models
    assert len({a.id for a in assets}) == len(assets)


def test_duplicates_across_repos(scanned: ScanResult) -> None:
    skills = [a for a in scanned.assets if a.kind == "skill"]
    copies = [a.model_copy(update={"id": "dup", "repo": "acme/other"}) for a in skills]
    mark_duplicates(skills + copies)
    assert skills[0].duplicates == ["dup"] and copies[0].duplicates == [skills[0].id]


def test_outputs_and_queries(scanned: ScanResult, tmp_path: Path) -> None:
    out = tmp_path / "data"
    store.write_repo(out, scanned.repo, scanned.assets)
    prev = store.load_previous(out)
    assert prev["acme/billing"][0] == scanned.repo  # round-trips losslessly
    meta = store.write_aggregates(out, [scanned.repo], scanned.assets, "test", False)
    db = out / "catalog.db"
    build_sqlite(db, [scanned.repo], scanned.assets, {"source": meta.source})
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row

    hits = search_repos(con, "stripe invoices")
    assert hits and hits[0]["id"] == "acme/billing"
    assert search_repos(con, "", technology="fastapi")[0]["id"] == "acme/billing"
    assert search_repos(con, "", capability="payments")
    assert not search_repos(con, "kubernetes helm")
    assert search_repos(con, "stripe nonexistentword")  # OR fallback
    assets = search_assets(con, "pdf report", kind="skill")
    assert assets[0]["name"] == "pdf-report"
    full = get_asset(con, assets[0]["id"])
    assert full and "ReportLab" in full["content"]
    assert any(r["matched"] == "Stripe" for r in repos_using(con, "stripe"))

    entities = exports.backstage_entities([scanned.repo])
    assert entities[0]["spec"]["owner"] == "group:default/billing-team"  # type: ignore[index]
    bom = exports.aibom([scanned.repo], scanned.assets, "test")
    types = {c["type"] for c in bom["components"]}  # type: ignore[attr-defined]
    assert {"machine-learning-model", "library", "application", "data"} <= types


def test_schemas_written(tmp_path: Path) -> None:
    store.write_schemas(tmp_path)
    schema = json.loads((tmp_path / "ai-asset.schema.json").read_text())
    assert "skill" in json.dumps(schema)


def test_mcp_server_tools(scanned: ScanResult, tmp_path: Path) -> None:
    pytest.importorskip("mcp")
    import anyio

    from repo_catalog.mcp_server import build_server

    db = tmp_path / "catalog.db"
    build_sqlite(db, [scanned.repo], scanned.assets, {})
    server = build_server(db)

    async def call() -> tuple[set[str], object]:
        tools = await server.list_tools()
        result = await server.call_tool("repos_using", {"technology": "stripe"})
        return {t.name for t in tools}, result

    names, result = anyio.run(call)
    assert {
        "search_repos",
        "get_repo",
        "search_ai_assets",
        "get_ai_asset",
        "repos_using",
        "technology_usage",
        "sql",
    } <= names
    assert "acme/billing" in str(result)


def test_rule_tables_and_tests_are_not_ai_usage(
    make_repo: Callable[..., tuple[RepoRef, Path]], tmp_path: Path
) -> None:
    """Strings that merely *mention* SDKs (rule tables, docs, tests) must not count as usage."""
    ref, root = make_repo(
        {
            "src/rules.py": 'PATTERNS = ["semantic_kernel", "AzureOpenAI", "ClientSession",\n'
            '    "from anthropic import", "ollama", "bedrock-runtime", "AI_COMPLETE"]\n',
            "tests/test_server.py": 'SRC = """from mcp.server.fastmcp import FastMCP\n'
            'server = FastMCP(\\"fake\\")"""\nimport anthropic\n',
            "src/app.ts": "import Anthropic from '@anthropic-ai/sdk';\n"
            "const client = new Anthropic();\nawait client.messages.create({});\n",
        },
        name="rules",
    )
    result = analyze_checkout(ref, root, ScanOptions(workdir=tmp_path / "w"))
    kinds = {(a.kind, a.ecosystem) for a in result.assets}
    assert kinds == {("sdk-usage", "anthropic")}
    assert result.repo.ai.sdks == ["Anthropic SDK"]
