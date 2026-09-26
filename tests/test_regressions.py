"""Regression tests for issues found by adversarial review and real-world scans.

Each test pins one reproduced bug so it can never silently come back.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest

from repo_catalog import git
from repo_catalog.analyzers.ai_common import parse_frontmatter
from repo_catalog.fs import RepoFiles, _glob_to_regex
from repo_catalog.github import GitHubClient, GitHubError, RepoRef, _parse_retry_after
from repo_catalog.models import AIAsset
from repo_catalog.outputs import store
from repo_catalog.outputs.exports import _bs_name, _bs_owner, _bs_tag
from repo_catalog.query import fts_query, read_only_sql
from repo_catalog.scanner import ScanOptions, ScanResult, analyze_checkout
from repo_catalog.textutil import load_yaml, redact_args, redact_url, sanitize_config

Maker = Callable[..., tuple[RepoRef, Path]]


def scan(make_repo: Maker, tmp_path: Path, files: dict[str, str], name: str = "r") -> ScanResult:
    ref, root = make_repo(files, name=name)
    return analyze_checkout(ref, root, ScanOptions(workdir=tmp_path / "w"))


def names(result: ScanResult, kind: str | None = None) -> set[str]:
    return {a.name for a in result.assets if kind is None or a.kind == kind}


def all_output(result: ScanResult) -> str:
    return result.repo.model_dump_json() + "".join(a.model_dump_json() for a in result.assets)


# ------------------------------------------------------------------------------ security


def test_token_never_reaches_errors_or_argv() -> None:
    env = git._auth_env("ghp_" + "S" * 36, "https://github.com/acme/x.git")
    assert all("ghp_" not in k for k in env)  # key names are safe; value is in env only
    with pytest.raises(git.GitError) as err:
        git._run(["ls-remote", "--", "https://github.invalid/acme/x.git"], timeout=20, env=env)
    msg = str(err.value)
    b64 = base64.b64encode(("x-access-token:ghp_" + "S" * 36).encode()).decode()
    assert "ghp_" not in msg and b64 not in msg
    with pytest.raises(git.GitError, match="timed out") as err:
        git._run(["hash-object", "--stdin"], timeout=0.000001, env=env)  # type: ignore[arg-type]
    assert "AUTHORIZATION" not in str(err.value)


def test_auth_env_appends_to_existing_git_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GIT_CONFIG_COUNT", "2")
    env = git._auth_env("t", "https://github.com/a/b")
    assert env["GIT_CONFIG_COUNT"] == "3" and "GIT_CONFIG_KEY_2" in env


def test_symlinks_cannot_escape_or_block(make_repo: Maker, tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("* @leaked-from-outside\nSECRET=1\n")
    ref, root = make_repo({"AGENTS.md": "# Agents\n\nUse ruff to lint and pytest to test.\n"})
    (root / ".github").mkdir()
    os.symlink(outside, root / ".github" / "CODEOWNERS")
    os.symlink("/dev/stdin", root / "CODEOWNERS")
    os.symlink("AGENTS.md", root / "CLAUDE.md")  # in-repo link: common and fine
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    start = time.time()
    result = analyze_checkout(ref, root, ScanOptions(workdir=tmp_path / "w"))
    assert time.time() - start < 20
    assert result.repo.ownership.codeowners == []
    assert "leaked" not in all_output(result)
    assert {"CLAUDE.md", "AGENTS.md"} <= {a.path for a in result.assets}


def test_damaged_clone_never_touches_parent_repo(tmp_path: Path) -> None:
    upstream = tmp_path / "up"
    upstream.mkdir()
    for cmd in (["init", "-q", "-b", "main"], ["commit", "-q", "--allow-empty", "-m", "i"]):
        subprocess.run(
            ["git", "-c", "user.name=T", "-c", "user.email=t@e", *cmd], cwd=upstream, check=True
        )
    project = tmp_path / "project"
    project.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=project, check=True)
    (project / "mine.txt").write_text("uncommitted work")
    dest = project / ".cache" / "repos" / "acme" / "demo"
    (dest / ".git").mkdir(parents=True)  # damaged: exists but is not a repository
    git.sync(str(upstream), dest, branch="main")
    assert (project / "mine.txt").read_text() == "uncommitted work"
    assert git._is_own_repo(dest)


def test_secrets_are_redacted_everywhere(make_repo: Maker, tmp_path: Path) -> None:
    secrets = [
        "ghp_" + "A" * 36,
        "tvly-" + "B" * 20,
        "sk-ak-" + "C" * 20,
        "HDRSECRET12345678",
        "sk-proj-" + "D" * 40,
        "BEARERSECRET123456789",
    ]
    result = scan(
        make_repo,
        tmp_path,
        {
            ".mcp.json": json.dumps(
                {
                    "mcpServers": {
                        "gh": {
                            "command": "docker",
                            "args": ["run", "-e", f"GITHUB_TOKEN={secrets[0]}"],
                        },
                        "tv": {"command": "npx", "args": ["tavily-mcp", "--api-key", secrets[1]]},
                        "zap": {
                            "type": "sse",
                            "url": f"https://actions.zapier.com/mcp/{secrets[2]}/sse",
                        },
                        "q": {
                            "url": "https://mcp.example.com/mcp?api_key=x",
                            "headers": {"X": secrets[3]},
                        },
                    }
                }
            ),
            "langgraph.json": json.dumps({"graphs": {"a": "./a.py:g"}, "env": {"K": secrets[4]}}),
            ".claude/settings.json": json.dumps(
                {
                    "hooks": {
                        "Stop": [
                            {
                                "hooks": [
                                    {
                                        "type": "http",
                                        "url": "https://h.example/x",
                                        "headers": {"Authorization": f"Bearer {secrets[5]}"},
                                    }
                                ]
                            }
                        ]
                    }
                }
            ),
            "prompts/p.md": f"Use token {secrets[0]} to call the API when summarising reports.\n",
        },
    )
    out = all_output(result)
    for secret in secrets:
        assert secret not in out, secret
    assert "api_key" not in out
    assert {"gh", "tv", "zap", "q"} <= set(result.repo.ai.mcp_servers_consumed)


def test_redaction_helpers() -> None:
    assert redact_args(["--token", "abc", "--port", "8080", "API_KEY=zz"]) == [
        "--token",
        "[REDACTED]",
        "--port",
        "8080",
        "API_KEY=[REDACTED]",
    ]
    assert redact_url("https://user:pw@h.io/p?k=v") == "https://h.io/p"
    assert sanitize_config({"env": {"A": "1"}, "password": "hunter2hunter"}) == {
        "env": ["A"],
        "password": "[REDACTED]",
    }


# ------------------------------------------------------------------------------ robustness


def test_yaml_alias_bomb_is_rejected_fast() -> None:
    lines = ["a: &a [x,x,x,x,x,x,x,x,x]"] + [
        f"{chr(98 + i)}: &{chr(98 + i)} [{','.join(['*' + chr(97 + i)] * 9)}]" for i in range(9)
    ]
    start = time.time()
    with pytest.raises(Exception, match="aliases"):
        load_yaml("\n".join(lines))
    fm, _ = parse_frontmatter("---\n" + "\n".join(lines) + "\n---\nbody")
    assert time.time() - start < 2 and len(json.dumps(fm)) < 5000


def test_one_bad_file_never_hides_others(make_repo: Maker, tmp_path: Path) -> None:
    result = scan(
        make_repo,
        tmp_path,
        {
            "a/.claude-plugin/plugin.json": '{"name": "good-plugin"}',
            "b/.claude-plugin/plugin.json": "{not json",
            "x.prompt.yml": "name: [unclosed\n",
            "y.prompt.yml": "name: fine\nmodel: openai/gpt-4o\nmessages: []\n",
            ".claude/agents/r.md": "---\nx: &a [*a]\n---\nRecursive frontmatter.\n",
            "AGENTS.md": "# Agents\n\nRun make test.\n",
            "package.json": "\ufeff"
            + json.dumps({"name": "bom-pkg", "dependencies": {"react": "19"}}),
            "CLAUDE.md": "\ufeff# Claude\n\nRun tests with pytest.\n",
        },
    )
    assert {"good-plugin", "fine", "AGENTS.md", "CLAUDE.md"} <= names(result)
    assert "React" in result.repo.stack.frameworks  # BOM-prefixed manifest parsed
    errors = " ".join(result.repo.scan_errors)
    assert "b/.claude-plugin/plugin.json" in errors and "x.prompt.yml" in errors


def test_utf16_instructions_are_read(make_repo: Maker, tmp_path: Path) -> None:
    ref, root = make_repo({"README.md": "x"})
    (root / "CLAUDE.md").write_bytes("# Build\n\nRun npm test.\n".encode("utf-16"))
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    result = analyze_checkout(ref, root, ScanOptions(workdir=tmp_path / "w"))
    assert "CLAUDE.md" in names(result, "instructions")


def test_malformed_descriptors_do_not_break_the_record(make_repo: Maker, tmp_path: Path) -> None:
    result = scan(
        make_repo,
        tmp_path,
        {
            "catalog-info.yaml": "apiVersion: backstage.io/v1alpha1\nkind: API\nmetadata:\n  name: "
            "billing-api\nspec:\n  owner: team-api\n---\napiVersion: backstage.io/v1alpha1\n"
            "kind: Component\nmetadata:\n  name: 2048\n  tags: solo\nspec:\n  owner: team-b\n"
            "  providesApis: billing-api\n",
            "cortex.yaml": "info:\n  x-cortex-owners: {name: team}\n",
        },
    )
    d = result.repo.declared
    assert d.owner == "team-b" and d.name == "2048"  # Component wins; scalars become strings
    assert d.tags == ["solo"] and d.provides_apis == ["billing-api"]
    # the stored record round-trips (it used to fail validation and rescan forever)
    assert type(result.repo).model_validate_json(result.repo.model_dump_json()) == result.repo


# --------------------------------------------------------------------------- AI detection


def test_mcp_tools_python_ts_go(make_repo: Maker, tmp_path: Path) -> None:
    result = scan(
        make_repo,
        tmp_path,
        {
            "py/server.py": 'from mcp.server.fastmcp import FastMCP\nmcp = FastMCP("weather")\n\n'
            '@mcp.tool()\n@traced\ndef forecast(city: str) -> str:\n    """Get forecast."""\n\n'
            '@mcp.tool\ndef bare() -> str:\n    """Bare decorator."""\n\n'
            '@mcp.tool("alerts_v2")\ndef alerts() -> str:\n    """Get alerts."""\n\n'
            'def helper():\n    """Not a tool."""\n',
            "py/docs.py": 'from mcp.server import x\n"""Example:\n'
            '    server = MCPServer("fake")\n"""\n',
            "ts/index.ts": 'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
            'const server = new McpServer({ version: "1", name: "ts-srv" });\n'
            'server.tool("echo", { msg: z.string() }, async () => ({}));\n'
            'server.registerTool("add", { title: "Add", inputSchema: { a: z.number() }, '
            'description: "Add numbers" }, h);\n',
            "go/main.go": 'import "github.com/mark3labs/mcp-go/server"\n'
            's := server.NewMCPServer("go-calc", "1")\n'
            't1 := mcp.NewTool("noop")\n'
            't2 := mcp.NewTool("calculate", mcp.WithDescription("Do math"))\n',
        },
    )
    servers = {a.name: a for a in result.assets if a.kind == "mcp-server"}
    assert set(servers) == {"weather", "ts-srv", "go-calc"}  # docstring example ignored
    assert servers["weather"].tools == ["forecast", "bare", "alerts_v2"]
    assert servers["ts-srv"].tools == ["echo", "add"]
    assert servers["ts-srv"].frontmatter["tool_descriptions"]["add"] == "Add numbers"
    assert servers["go-calc"].frontmatter["tool_descriptions"] == {
        "noop": None,
        "calculate": "Do math",
    }


def test_mcp_client_is_not_a_server(make_repo: Maker, tmp_path: Path) -> None:
    result = scan(
        make_repo,
        tmp_path,
        {
            "client.ts": 'const r = await rpc({ method: "tools/list" });\n'
            'await rpc({ method: "tools/call", params: {} });\n',
            "server.py": 'import json\nSERVER_INFO = {"name": "hand-rolled", "version": "1"}\n'
            'def handle(m):\n    if m == "tools/list":\n        return TOOLS\n'
            '    if m == "tools/call":\n        return run()\n'
            'TOOLS = [{"name": "get_labs", "description": "Lab results", "inputSchema": {}}]\n',
        },
    )
    servers = [a for a in result.assets if a.kind == "mcp-server"]
    assert [(s.name, s.tools) for s in servers] == [("hand-rolled", ["get_labs"])]


def test_2026_conventions(make_repo: Maker, tmp_path: Path) -> None:
    result = scan(
        make_repo,
        tmp_path,
        {
            "instructions/python.instructions.md": (
                "---\napplyTo: '**/*.py'\n---\nUse type hints.\n"
            ),
            "agents/Planner.agent.md": "---\ndescription: Plans\ntools: ['search']\n---\nPlan.\n",
            "rules/react.mdc": (
                "---\ndescription: React rules\nglobs: *.tsx\nalwaysApply: true\n---\nx\n"
            ),
            "docs/not-a-rule.mdc": "Just a markdown components file.\n",
            ".github/workflows/triage.md": "---\non:\n  issues:\n    types: [opened]\n"
            "permissions:\n"
            "  contents: read\nsafe-outputs:\n  add-comment:\n---\nTriage new issues.\n",
            "hooks/guard/hooks.json": json.dumps(
                {"version": 1, "hooks": {"preToolUse": [{"type": "command", "bash": "./guard.sh"}]}}
            ),
            "plugins/k/plugin.json": json.dumps(
                {
                    "$schema": "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
                    "name": "k",
                }
            ),
            ".well-known/agent.json": json.dumps(
                {"name": "Helper", "capabilities": {}, "skills": [{"id": "s1"}]}
            ),
            ".claude/commands/frontend/component.md": "Create a component named $ARGUMENTS.\n",
        },
    )
    by = {(a.kind, a.ecosystem, a.name) for a in result.assets}
    assert ("instructions", "copilot", "python") in by
    assert ("agent", "copilot", "Planner") in by
    assert ("instructions", "cursor", "react") in by
    assert not any(a.path == "docs/not-a-rule.mdc" for a in result.assets)
    assert ("workflow", "gh-aw", ".github/workflows/triage.md") in by
    assert ("hook", "copilot", "preToolUse") in by
    assert ("plugin", "agent-plugins", "k") in by
    assert ("agent", "a2a", "Helper") in by
    assert ("command", "claude-code", "/component") in by


def test_inline_prompts_do_not_collide(make_repo: Maker, tmp_path: Path) -> None:
    body = "You are a helpful assistant that answers questions about invoices. " * 5
    result = scan(
        make_repo,
        tmp_path,
        {
            "llm.py": "import anthropic\nc = anthropic.Anthropic()\n"
            f'c.messages.create(system="""{body}A""")\nc.messages.create(system="""{body}B""")\n',
        },
    )
    prompts = names(result, "prompt")
    assert prompts == {"llm.py:system", "llm.py:system #2"}


def test_examples_and_tests_are_not_the_stack(make_repo: Maker, tmp_path: Path) -> None:
    result = scan(
        make_repo,
        tmp_path,
        {
            "pyproject.toml": '[project]\nname = "cli"\ndependencies = ["typer"]\n'
            '[project.scripts]\ncli = "cli:main"\n',
            "examples/web/package.json": json.dumps(
                {"dependencies": {"next": "15", "react": "19"}}
            ),
            "examples/web/next.config.js": "module.exports = {}\n",
            "tests/test_x.py": "from anthropic import Anthropic\nAnthropic().messages.create()\n",
        },
    )
    assert result.repo.structure.repo_type == "cli"
    assert "Next.js" not in result.repo.stack.frameworks
    assert result.repo.stack.ai == []


# ------------------------------------------------------------------------ repo analyzers


def test_manifest_edge_cases(make_repo: Maker, tmp_path: Path) -> None:
    result = scan(
        make_repo,
        tmp_path,
        {
            "Cargo.toml": '[workspace]\nmembers = ["a"]\n[workspace.dependencies]\naxum = "0.7"\n',
            "a/Cargo.toml": '[package]\nname = "a"\ndescription.workspace = true\n[dependencies]\n'
            'axum = { workspace = true }\n[target."cfg(unix)".dependencies]\nnix = "0.29"\n',
            "setup.py": 'setup(name="s", install_requires=["requests[security]>=2", "attrs"])\n',
            "Gemfile": "gem 'rails'\ngem 'rspec', group: :test\ngroup :development do\n"
            "  platforms :mri do\n    gem 'byebug'\n  end\n  gem 'rubocop'\nend\n",
            "go.mod": (
                "module x\n\ngo 1.24\n\nrequire (\n\tgithub.com/gin-gonic/gin v1 // indirect\n)\n"
            ),
            "App.Tests/App.Tests.csproj": '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>'
            '<PackageReference Include="xunit" /></ItemGroup></Project>',
        },
    )
    deps = {(d.ecosystem, d.name): d for d in result.repo.dependencies}
    assert {("cargo", "nix"), ("cargo", "axum"), ("pypi", "requests"), ("pypi", "attrs")} <= set(
        deps
    )
    assert deps[("gem", "rspec")].scope == "dev" and deps[("gem", "rubocop")].scope == "dev"
    assert deps[("gem", "rails")].scope == "runtime"
    assert deps[("go", "github.com/gin-gonic/gin")].scope == "transitive"
    assert deps[("nuget", "xunit")].scope == "dev"
    assert "Gin" not in result.repo.stack.frameworks
    assert "a" in {p.name for p in result.repo.structure.packages}


def test_practice_checks_edge_cases(make_repo: Maker, tmp_path: Path) -> None:
    result = scan(
        make_repo,
        tmp_path,
        {
            "README.md": "# Real\n\n" + "A real README with enough words. " * 40,
            "README.ja.md": "# 日本語\n",
            "LICENSE-MIT": "MIT License\n",
            "LICENSE-APACHE": "Apache License\n",
            ".env.local.example": "KEY=\n",
            ".env.test": "KEY=1\n",
            ".github/workflows/ci.yml": "on: push\npermissions: write-all\n"
            "jobs:\n  t:\n    steps:\n"
            "      - uses: 'actions/checkout@v4'\n      - run: pytest\n",
            "Makefile": "test:\n\tpytest\n",
        },
    )
    checks = {c.id: c for c in result.repo.practices.checks}
    assert checks["readme"].evidence == "README.md" and checks["readme-substantial"].passed
    assert checks["license"].passed and result.repo.license == "Apache-2.0 OR MIT"
    assert checks["no-env-files"].evidence == ".env.test"
    assert not checks["workflow-permissions"].passed and not checks["actions-pinned"].passed
    assert checks["ci-runs-tests"].passed


def test_readme_title_ignores_code_fences(make_repo: Maker, tmp_path: Path) -> None:
    result = scan(
        make_repo,
        tmp_path,
        {
            "README.md": '<h1 align="center">Acme Widgets</h1>\n\n<p align="center">'
            '<a href="x">Docs</a> · <a href="y">Discord</a> · <a href="z">Blog</a></p>\n\n'
            "```bash\n# Install dependencies first\n```\n\n"
            "Widgets for everyone, fast and reliable.\n",
        },
    )
    assert result.repo.summary.readme_title == "Acme Widgets"
    assert result.repo.summary.readme_excerpt == "Widgets for everyone, fast and reliable."


# ------------------------------------------------------------------ outputs, query, infra


def test_prune_only_touches_scanned_owners(tmp_path: Path, make_repo: Maker) -> None:
    result = scan(make_repo, tmp_path, {"README.md": "x"})
    for rid in ("alpha/a1", "beta/b1", "local/l"):
        repo = result.repo.model_copy(update={"id": rid, "owner": rid.split("/")[0]})
        store.write_repo(tmp_path / "out", repo, [])
    removed = store.prune(tmp_path / "out", {"beta/b2"}, {"beta"})
    assert removed == ["beta__b1"]
    assert store.prune(tmp_path / "out", set(), set()) == []  # empty discovery never wipes


def test_backstage_names_tags_and_owners_are_valid() -> None:
    import re

    name_rx = re.compile(r"^([A-Za-z0-9][-_.]?)*[A-Za-z0-9]$")
    tag_rx = re.compile(r"^[a-z0-9:+#]+(-[a-z0-9:+#]+)*$")
    for raw in ["My Repo__v2..x", "---", "a" * 100 + "-", "é-ü", "x..y--z"]:
        assert name_rx.match(_bs_name(raw)) and len(_bs_name(raw)) <= 63
        tag = _bs_tag(raw)
        assert not tag or (tag_rx.match(tag) and len(tag) <= 63)
    assert _bs_owner("@acme/payments") == "group:default/payments"
    assert _bs_owner("dev@acme.io") == "user:default/dev"


def test_sql_guard_and_fts_tokens() -> None:
    import sqlite3

    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    for bad in ("SELECT 1 -- x", "SELECT 1 /* x */", "SELECT 1; ATTACH 'x' AS y", "PRAGMA x"):
        with pytest.raises(ValueError):
            read_only_sql(con, bad)
    assert read_only_sql(con, "SELECT ';' AS s") == [{"s": ";"}]
    assert read_only_sql(con, "SELECT 1 AS a", limit=-5) == [{"a": 1}]
    with pytest.raises(ValueError, match="exceeded"):
        read_only_sql(
            con,
            "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c) SELECT count(*) FROM c",
            timeout_s=0.3,
        )
    assert fts_query("c++ weasy") == '"weasy"*'


def test_github_retry_edge_cases(monkeypatch: pytest.MonkeyPatch) -> None:
    from repo_catalog import github

    sleeps: list[float] = []
    monkeypatch.setattr(github.time, "sleep", sleeps.append)
    assert _parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT") == 1.0  # past date -> minimum
    calls = iter([httpx.ConnectTimeout("boom"), httpx.Response(429), httpx.Response(200, json=[])])

    def handler(req: httpx.Request) -> httpx.Response:
        item = next(calls)
        if isinstance(item, Exception):
            raise item
        return item

    gh = GitHubClient(None, transport=httpx.MockTransport(handler))
    assert gh.paginate("/x") == [] and sleeps == [1.0, 120.0]  # attempts shared across kinds

    saml = GitHubClient(
        "t",
        transport=httpx.MockTransport(
            lambda r: httpx.Response(
                403, json={"message": "Resource protected by organization SAML enforcement."}
            )
        ),
    )
    with pytest.raises(GitHubError, match="SAML"):
        saml.list_owner_repos("acme")


def test_incremental_reuse_respects_scan_options(make_repo: Maker, tmp_path: Path) -> None:
    from repo_catalog.scanner import _unchanged

    ref, root = make_repo({"README.md": "x"})
    full = ScanOptions(workdir=tmp_path)
    repo = analyze_checkout(ref, root, full).repo
    assert _unchanged(ref, repo, full)
    assert not _unchanged(ref, repo, ScanOptions(workdir=tmp_path, shallow=True))
    ref.custom_properties = {"team": "new-owner"}
    assert not _unchanged(ref, repo, full)


def test_glob_negation_and_nested_alternation() -> None:
    assert _glob_to_regex("[!a]*.py").match("b.py") and not _glob_to_regex("[!a]*.py").match("a.py")
    assert _glob_to_regex("{*.yml,*.yaml}").match("x.yaml")
    assert _glob_to_regex("[]]x").match("]x")


def test_repo_files_listing_uses_git_and_keeps_real_build_dirs(make_repo: Maker) -> None:
    _, root = make_repo(
        {"src/build/compile.ts": "x", "env/prod/main.tf": "x", "node_modules/x/index.js": "x"}
    )
    (root / "untracked.txt").write_text("not committed")
    paths = RepoFiles.scan(root).paths
    assert {"src/build/compile.ts", "env/prod/main.tf"} <= paths
    assert "untracked.txt" not in paths and "node_modules/x/index.js" not in paths


def test_enrichment_failures_are_contained(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("anthropic")
    from repo_catalog import enrich

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    e = enrich.Enricher(cache_dir=tmp_path)
    (tmp_path / "junk.json").write_text("{")

    def boom(*_: object, **__: object) -> None:
        raise ValueError("1 validation error: Invalid JSON: EOF while parsing")

    monkeypatch.setattr(e.client.beta.messages, "parse", boom)
    asset = AIAsset(
        id="1", kind="skill", ecosystem="x", name="n", repo="r", path="p", url="u", detector="d"
    )
    e.enrich_assets([asset])  # must not raise
    assert asset.summary is None


def test_mcp_server_without_catalog_explains_itself(tmp_path: Path) -> None:
    pytest.importorskip("mcp")
    import anyio

    from repo_catalog.mcp_server import build_server

    server = build_server(tmp_path / "missing.db")

    async def call() -> object:
        return await server.call_tool("search_repos", {"query_text": "x"})

    with pytest.raises(Exception, match="repo-catalog scan"):
        anyio.run(call)


# --------------------------------------------------------------- found by the corpus scan


def test_yaml_anchors_are_fine_but_recursion_is_not() -> None:
    doc = "base: &b {model: gpt-4o}\nproviders:\n  - <<: *b\n    id: a\n  - *b\n"
    assert load_yaml(doc)["providers"] == [{"model": "gpt-4o", "id": "a"}, {"model": "gpt-4o"}]
    with pytest.raises(Exception, match="recursive"):
        load_yaml("x: &a [*a]\n")


def test_non_network_urls_are_not_errors() -> None:
    assert redact_url("file://prompts.py:format_prompt") == "file://prompts.py:format_prompt"


def test_devcontainer_and_example_dockerfiles_do_not_make_a_service(
    make_repo: Maker, tmp_path: Path
) -> None:
    result = scan(
        make_repo,
        tmp_path,
        {
            "src/index.ts": "export const x = 1;\n",
            ".devcontainer/Dockerfile": "FROM node:22\n",
            "examples/gateway/Dockerfile": "FROM node:22\n",
        },
    )
    assert result.repo.structure.repo_type != "service"


def test_docs_snippets_are_tagged_example(make_repo: Maker, tmp_path: Path) -> None:
    result = scan(
        make_repo,
        tmp_path,
        {
            "docs_src/server.py": 'from mcp.server.fastmcp import FastMCP\nmcp = FastMCP("demo")\n',
        },
    )
    assert "example" in next(a for a in result.assets if a.kind == "mcp-server").tags


def test_sdk_internals_are_not_mcp_servers(make_repo: Maker, tmp_path: Path) -> None:
    result = scan(
        make_repo,
        tmp_path,
        {
            "src/methods.py": 'import x\nTABLE = {"tools/call": 1, "tools/list": 2}\n'
            'def route(m):\n    if m == "tools/call":\n        return TABLE[m]\n',
            "src/wrapper.py": "from mcp.server.lowlevel import Server\n\nclass Framework:\n"
            "    def __init__(self, name):\n        self._server = Server(name=name)\n",
        },
    )
    assert not [a for a in result.assets if a.kind == "mcp-server"]
