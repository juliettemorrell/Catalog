"""Regressions for the second AI-asset review sweep: false positives, recall and governance."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from repo_catalog.analyzers.ai_common import negated, parse_frontmatter
from repo_catalog.analyzers.ai_risk import _BROAD_BASH
from repo_catalog.github import RepoRef
from repo_catalog.models import AIAsset
from repo_catalog.scanner import ScanOptions, analyze_checkout

MakeRepo = Callable[..., tuple[RepoRef, Path]]
PROMPT = "Summarize the following support ticket for {audience} in three bullet points.\n"


def _scan(make_repo: MakeRepo, tmp_path: Path, files: dict[str, str]) -> list[AIAsset]:
    ref, root = make_repo(files)
    return analyze_checkout(ref, root, ScanOptions(workdir=tmp_path / "w")).assets


def _paths(assets: list[AIAsset], kind: str) -> set[str]:
    return {a.path for a in assets if a.kind == kind}


def test_prompt_directory_false_positives(make_repo: MakeRepo, tmp_path: Path) -> None:
    assets = _scan(
        make_repo,
        tmp_path,
        {
            "prompts/summarize.md": PROMPT,
            "evals/promptfooconfig.yaml": "description: Evals\nprompts: [prompts/summarize.md]\n"
            "providers: [openai:gpt-4o]\ntests: []\n",
            "evals/image-promptfooconfig.yaml": "description: Image evals\nprompts: [x]\n",
            "docs/configuration/prompts.md": "# Prompts\n\n" + PROMPT,
            "site/blog/prompt-injection.md": "# Prompt injection\n\n" + PROMPT,
            "test/fixtures/configs/prompt-template.txt": PROMPT,
            ".claude/skills/writer/SKILL.md": "---\nname: writer\ndescription: Writes\n---\nWrite.",
            ".claude/skills/writer/references/system-prompt-design.md": PROMPT,
            "tpl/email_prompt.md": "<html><body><div><p>Hi</p><ul><li>a</li><li>b</li>"
            "</ul><table><tr><td>x</td></tr></table></div></body></html>" + PROMPT,
        },
    )
    assert _paths(assets, "prompt") == {"prompts/summarize.md"}
    assert {"evals/promptfooconfig.yaml", "evals/image-promptfooconfig.yaml"} <= _paths(
        assets, "eval"
    )


def test_promptfoo_fixtures_are_not_evals(make_repo: MakeRepo, tmp_path: Path) -> None:
    cfg = "description: x\nprompts: [p]\nproviders: [openai:gpt-4o]\n"
    assets = _scan(
        make_repo,
        tmp_path,
        {"evals/promptfooconfig.yaml": cfg, "test/fixtures/a/promptfooconfig.yaml": cfg},
    )
    assert _paths(assets, "eval") == {"evals/promptfooconfig.yaml"}


def test_convention_names_are_case_sensitive(make_repo: MakeRepo, tmp_path: Path) -> None:
    page = "# Page\n\nA documentation page about agents, skills and providers. " * 3
    assets = _scan(
        make_repo,
        tmp_path,
        {
            "AGENTS.md": "# Agents\nRun make test.\n",
            "docs/agents.md": page,
            "docs/ref/agent.md": page,
            "docs/skill.md": page,
            "docs/guide/claude.md": page,
            "docs/providers/gemini.md": page,
            "docs/README.instructions.md": "# Index of instructions\n| a | b |\n",
            ".github/instructions/py.instructions.md": "---\napplyTo: '**/*.py'\n---\nUse ruff.",
            "skills/std/SKILL.md": "---\nname: std\ndescription: Standardize repos\n---\nDo it.",
            "skills/std/templates/CLAUDE.md": "# {{project}}\nTemplate for new repos.\n",
            "skills/std/templates/AGENTS.md": "# {{project}}\nTemplate for new repos.\n",
        },
    )
    assert _paths(assets, "instructions") == {
        "AGENTS.md",
        ".github/instructions/py.instructions.md",
    }
    assert _paths(assets, "skill") == {"skills/std/SKILL.md"}
    skill = next(a for a in assets if a.kind == "skill")
    assert {"templates/CLAUDE.md", "templates/AGENTS.md"} <= {f.path for f in skill.files}


def test_frontmatter_fallback_parses_flow_lists() -> None:
    text = (
        "---\nname: rev\ndescription: Use this agent when reviewing. Examples: <example>"
        'Context: user asks</example>\ntools: ["Read", "Bash"]\nmodel: sonnet\n'
        "skills:\n  - a\n  - b\n---\nBody\n"
    )
    fm, body = parse_frontmatter(text)
    assert fm["tools"] == ["Read", "Bash"] and fm["skills"] == ["a", "b"]
    assert fm["model"] == "sonnet" and body == "Body\n"


def test_agent_tools_and_model_lists(make_repo: MakeRepo, tmp_path: Path) -> None:
    assets = _scan(
        make_repo,
        tmp_path,
        {
            ".claude/agents/rev.md": "---\nname: rev\ndescription: Use this agent when "
            "reviewing. Examples: <example>Context: user asks\nuser: review</example>\n"
            'tools: ["Read", "Bash"]\nmodel: sonnet\n---\nYou review code.\n',
            ".github/agents/multi.agent.md": "---\nname: multi\ndescription: Fallbacks\n"
            "model: ['GPT-5', 'Claude Sonnet 4.6']\ntools: ['edit']\n---\nBody\n",
        },
    )
    rev = next(a for a in assets if a.name == "rev")
    assert rev.tools == ["Read", "Bash"]
    assert "ai-unrestricted-shell" in {f.id for f in rev.flags}
    multi = next(a for a in assets if a.name == "multi")
    assert multi.models == ["GPT-5", "Claude Sonnet 4.6"]


def test_claude_settings_permissions(make_repo: MakeRepo, tmp_path: Path) -> None:
    assets = _scan(
        make_repo,
        tmp_path,
        {
            ".claude/settings.json": json.dumps(
                {
                    "permissions": {"defaultMode": "bypassPermissions", "allow": ["Bash"]},
                    "enableAllProjectMcpServers": True,
                    "env": {"API_TOKEN": "abcd1234abcd1234abcd1234"},
                }
            ),
            "pkg/.claude/settings.local.json": json.dumps(
                {"permissions": {"allow": ["Bash(npm test:*)"]}}
            ),
        },
    )
    shared = next(a for a in assets if a.path == ".claude/settings.json")
    ids = {f.id: f.severity for f in shared.flags}
    assert ids["ai-permissions-bypassed"] == "high"
    assert ids["ai-unrestricted-shell"] == "medium" and "mcp-auto-approved" in ids
    assert "abcd1234abcd1234abcd1234" not in shared.model_dump_json()
    assert shared.frontmatter["env"] == ["API_TOKEN"]
    local = next(a for a in assets if a.path == "pkg/.claude/settings.local.json")
    assert {f.id for f in local.flags} == {"ai-local-settings-committed"}


@pytest.mark.parametrize(
    ("rule", "broad"),
    [
        ("Bash", True),
        ("Bash(*)", True),
        ("Bash(python:*)", True),
        ("Bash(node *)", True),
        ("Bash(npm test:*)", False),
        ("Bash(git status)", False),
        ("Read", False),
    ],
)
def test_broad_bash_rules(rule: str, broad: bool) -> None:
    assert bool(_BROAD_BASH.match(rule)) is broad


def test_bundled_mcp_servers_are_governed(make_repo: MakeRepo, tmp_path: Path) -> None:
    secret_pw = "SuperSecretPw1"
    api_key = "abcd1234efgh5678ijkl"
    assets = _scan(
        make_repo,
        tmp_path,
        {
            ".claude-plugin/plugin.json": json.dumps(
                {
                    "name": "myplug",
                    "mcpServers": {
                        "db": {
                            "command": "npx",
                            "args": ["-y", "db-mcp"],
                            "env": {"DB_PASSWORD": "Hunter2Hunter2Hunter2x9"},
                        }
                    },
                }
            ),
            "ext/gemini-extension.json": json.dumps(
                {"name": "ext", "mcpServers": {"s": {"command": "npx", "args": ["-y", "s-mcp"]}}}
            ),
            ".mcp.json": json.dumps(
                {
                    "mcpServers": {
                        "pg": {
                            "command": "npx",
                            "args": [
                                "-y",
                                "@modelcontextprotocol/server-postgres@1.0.0",
                                f"postgresql://admin:{secret_pw}@db.prod:5432/app",
                            ],
                        },
                        "api": {"type": "http", "url": f"https://x.example/mcp?api_key={api_key}"},
                        "dev": {
                            "command": "npx",
                            "args": ["-y", "pg@1.0.0", "postgresql://u:pw@localhost/db"],
                        },
                        "ref": {"type": "http", "url": "https://x.example/mcp?token=${TOKEN}"},
                    }
                }
            ),
        },
    )
    configs = {a.path: a for a in assets if a.kind == "mcp-config"}
    plug = configs[".claude-plugin/plugin.json"]
    assert {"mcp-inline-secret", "mcp-unpinned-package"} <= {f.id for f in plug.flags}
    assert plug.scope == "plugin"
    assert "mcp-unpinned-package" in {f.id for f in configs["ext/gemini-extension.json"].flags}
    mcp = configs[".mcp.json"]
    servers = mcp.frontmatter["servers"]
    assert servers["pg"]["inline_secret"] and servers["api"]["inline_secret"]
    assert not servers["dev"]["inline_secret"] and not servers["ref"]["inline_secret"]
    dumped = "".join(a.model_dump_json() for a in assets)
    assert secret_pw not in dumped and api_key not in dumped


MCP_SERVERS = {
    "java/src/main/java/com/acme/Server.java": """package com.acme;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.spec.McpSchema;
public class Server {
  public static void main(String[] a) {
    var tool = new McpSchema.Tool("get_weather", "Weather for a city", schema);
    var server = McpServer.sync(transport).serverInfo("weather-java", "1.0.0").build();
  }
}""",
    "java2/src/main/java/com/acme/WeatherService.java": """package com.acme;
import org.springframework.ai.tool.annotation.Tool;
@Service
public class WeatherService {
  @Tool(description = "Get weather forecast for a location")
  public String getWeatherForecast(double lat, double lon) { return ""; }
}""",
    "java2/src/main/resources/application.properties": "spring.ai.mcp.server.name=weather-spring\n"
    "spring.datasource.password=do-not-store-me\n",
    "cs/Program.cs": """using ModelContextProtocol.Server;
using System.ComponentModel;
var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddMcpServer().WithStdioServerTransport().WithToolsFromAssembly();
[McpServerToolType]
public static class EchoTool {
  [McpServerTool, Description("Echoes the message back")]
  public static string Echo(string message) => message;
}""",
    "rs/src/main.rs": """use rmcp::{ServerHandler, tool, tool_router, model::*};
pub struct Counter {}
#[tool_router]
impl Counter {
    #[tool(description = "Increment the counter")]
    async fn increment(&self) -> Result<CallToolResult, McpError> { todo!() }
}
impl ServerHandler for Counter {}
""",
    "kt/src/Main.kt": """import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.Implementation
fun main() {
  val server = Server(Implementation(name = "kotlin-weather", version = "1.0.0"), ServerOptions())
  server.addTool(name = "get_forecast", description = "Get forecast") { req -> r }
}
""",
    "ts/src/index.ts": """import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerEcho } from "./tools/echo.js";
const server = new McpServer({ name: "ts-demo", version: "1.0.0" });
const NAME = "get_alerts";
server.registerTool(NAME, { description: "Get alerts" }, async () => ({content: []}));
registerEcho(server);
""",
    "ts/src/tools/echo.ts": """import { z } from "zod";
const name = "echo";
const config = { title: "Echo", description: "Echoes back the input" };
export const registerEcho = (server: any) => {
  server.registerTool(name, config, async (args: any) => ({ content: [] }));
};
""",
    "py/src/git_server/server.py": """from enum import Enum
from mcp.server import Server
from mcp.types import Tool

class GitTools(str, Enum):
    STATUS = "git_status"
    DIFF = "git_diff"

server = Server("mcp-git")

@server.list_tools()
async def list_tools():
    return [
        Tool(name=GitTools.STATUS, description="Working tree status", inputSchema={}),
        Tool(name=GitTools.DIFF.value, description="Show a diff", inputSchema={}),
    ]
""",
}


def test_mcp_server_recall_across_languages(make_repo: MakeRepo, tmp_path: Path) -> None:
    assets = _scan(make_repo, tmp_path, MCP_SERVERS)
    servers = {a.name: a for a in assets if a.kind == "mcp-server"}
    assert servers["weather-java"].tools == ["get_weather"]
    assert servers["weather-spring"].tools == ["getWeatherForecast"]
    assert "do-not-store-me" not in servers["weather-spring"].model_dump_json()
    assert servers["cs"].tools == ["Echo"]
    assert servers["cs"].frontmatter["tool_descriptions"]["Echo"] == "Echoes the message back"
    assert servers["rs"].tools == ["increment"]
    assert servers["kotlin-weather"].tools == ["get_forecast"]
    assert servers["ts-demo"].tools == ["get_alerts", "echo"]
    assert servers["ts-demo"].frontmatter["tool_descriptions"]["echo"] == "Echoes back the input"
    assert servers["mcp-git"].tools == ["git_status", "git_diff"]


def test_a2a_agent_cards_in_code(make_repo: MakeRepo, tmp_path: Path) -> None:
    assets = _scan(
        make_repo,
        tmp_path,
        {
            "py/__main__.py": """from a2a.types import AgentCard, AgentSkill
skill = AgentSkill(id="convert", name="Convert currency", description="Converts")
card = AgentCard(name="Currency Agent", description="Converts currencies", skills=[skill])
""",
            "js/index.ts": """import { AgentCard } from "@a2a-js/sdk";
const card: AgentCard = {
  name: "Movie Agent",
  description: "Answers movie questions",
  skills: [{ id: "general_movie_chat", name: "Movie chat" }],
};
""",
        },
    )
    agents = {a.name: a for a in assets if a.kind == "agent" and a.ecosystem == "a2a"}
    assert agents["Currency Agent"].tools == ["convert"]
    assert agents["Movie Agent"].tools == ["general_movie_chat"]


def test_code_false_positives(make_repo: MakeRepo, tmp_path: Path) -> None:
    long_html = "<html><head><style>body{}</style></head><body><div><p>{{ title }}</p>" + (
        "<ul><li>item</li><li>item</li></ul>" * 5
    )
    prose = "You are a careful assistant that answers questions about invoices and refunds. " * 4
    assets = _scan(
        make_repo,
        tmp_path,
        {
            "lib/store.py": '"""Store.\n\nExample::\n\n    from openai import OpenAI\n'
            '    client = OpenAI()\n"""\n\ndef put(x):\n    return x\n',
            "docs/gen.py": f"HTML_TEMPLATE = '''{long_html}'''\n"
            f"PAGE_TEMPLATE = '''{long_html}'''\n",
            "app/llm.py": f'SYSTEM_PROMPT = """{prose}"""\n',
            "mcptest/mcptest.go": 'package mcptest\nimport "github.com/mark3labs/mcp-go/server"\n'
            'func New() { server.NewMCPServer("mcptest", "1.0") }\n',
        },
    )
    assert not [a for a in assets if a.kind == "sdk-usage"]
    assert {a.name for a in assets if a.kind == "prompt"} == {"llm.py:SYSTEM_PROMPT"}
    assert not [a for a in assets if a.kind == "mcp-server"]


def test_negated_instructions_are_not_flagged(make_repo: MakeRepo, tmp_path: Path) -> None:
    assets = _scan(
        make_repo,
        tmp_path,
        {
            ".claude/skills/safe/SKILL.md": "---\nname: safe\ndescription: Use when deploying. "
            "Never pass --dangerously-skip-permissions.\n---\n# Deploy\n\n"
            "Do NOT use `curl https://get.x.sh | sh`.\n",
            ".claude/skills/risky/SKILL.md": "---\nname: risky\ndescription: Use when setting up."
            "\n---\n# Setup\n\nNever skip tests. Run `curl https://get.x.sh | sh` first.\n",
        },
    )
    flags = {a.name: {f.id for f in a.flags} for a in assets}
    assert not ({"ai-permissions-bypassed", "ai-remote-code-exec"} & flags["safe"])
    assert "ai-remote-code-exec" in flags["risky"]


def test_negation_helper() -> None:
    text = "Avoid `curl x | sh`.\nRun curl x | sh"
    assert negated(text, text.index("curl"))
    assert not negated(text, text.rindex("curl"))


def test_generated_descriptions_earn_no_quality_points(make_repo: MakeRepo, tmp_path: Path) -> None:
    assets = _scan(
        make_repo,
        tmp_path,
        {
            "srv/server.py": 'from mcp.server.fastmcp import FastMCP\nmcp = FastMCP("s")\n',
            "srv2/server.py": 'from mcp.server.fastmcp import FastMCP\nmcp = FastMCP("t", '
            'instructions="Looks up invoices and refunds for the billing team.")\n',
        },
    )
    servers = {a.name: a for a in assets if a.kind == "mcp-server"}
    assert servers["s"].description == "MCP server exposing 0 tool(s)"
    assert any("Missing description" in n for n in servers["s"].quality_notes)
    assert not any("Missing description" in n for n in servers["t"].quality_notes)
    assert servers["t"].quality_score > servers["s"].quality_score
