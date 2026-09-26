"""Detect AI assets that live in well-known files: skills, agents, commands, rules,
instruction files, MCP configs, hooks, plugins, prompt files, evals and AI CI workflows.

Conventions covered (as of 2026): Agent Skills (SKILL.md), Claude Code, AGENTS.md,
GitHub Copilot, Cursor, Windsurf, Cline, Roo, Kiro, Amazon Q, Junie, Continue, Gemini CLI,
OpenAI Codex, OpenCode, Prompty, GitHub Models prompt files, promptfoo, CrewAI, LangGraph,
MCP registry ``server.json`` and ``llms.txt``.
"""

from __future__ import annotations

import json
import logging
import re
import tomllib
from collections.abc import Callable
from pathlib import PurePosixPath
from typing import Any

import yaml

from ..fs import FileEntry, RepoFiles
from ..models import AssetFile
from .ai_common import AssetDraft, as_list, parse_frontmatter

log = logging.getLogger(__name__)

# (glob, kind, ecosystem, detector-id). First match wins, so specific rules come first.
MARKDOWN_RULES: list[tuple[str, str, str, str]] = [
    ("**/SKILL.md", "skill", "*", "agent-skill"),
    ("**/.claude/agents/**/*.md", "agent", "claude-code", "claude-subagent"),
    ("**/.claude/commands/**/*.md", "command", "claude-code", "claude-command"),
    ("**/.claude/rules/**/*.md", "instructions", "claude-code", "claude-rules"),
    ("**/.claude/output-styles/**/*.md", "prompt", "claude-code", "claude-output-style"),
    ("**/CLAUDE.md", "instructions", "claude-code", "claude-md"),
    ("**/CLAUDE.local.md", "instructions", "claude-code", "claude-md"),
    ("**/AGENTS.md", "instructions", "agents-md", "agents-md"),
    ("**/AGENT.md", "instructions", "agents-md", "agents-md"),
    ("**/GEMINI.md", "instructions", "gemini", "gemini-md"),
    ("**/.github/copilot-instructions.md", "instructions", "copilot", "copilot-instructions"),
    (
        "**/.github/instructions/**/*.instructions.md",
        "instructions",
        "copilot",
        "copilot-instructions",
    ),
    ("**/.github/prompts/**/*.prompt.md", "command", "copilot", "copilot-prompt"),
    ("**/.github/agents/**/*.md", "agent", "copilot", "copilot-agent"),
    ("**/.github/chatmodes/**/*.chatmode.md", "agent", "copilot", "copilot-chatmode"),
    ("**/.cursor/rules/**/*.{mdc,md}", "instructions", "cursor", "cursor-rule"),
    ("**/.cursorrules", "instructions", "cursor", "cursor-rule"),
    ("**/.cursor/commands/**/*.md", "command", "cursor", "cursor-command"),
    ("**/.windsurf/rules/**/*.md", "instructions", "windsurf", "windsurf-rule"),
    ("**/.windsurfrules", "instructions", "windsurf", "windsurf-rule"),
    ("**/.windsurf/workflows/**/*.md", "command", "windsurf", "windsurf-workflow"),
    ("**/.clinerules", "instructions", "cline", "cline-rule"),
    ("**/.clinerules/**/*.md", "instructions", "cline", "cline-rule"),
    ("**/.cline/rules/**/*.md", "instructions", "cline", "cline-rule"),
    ("**/.roo/rules*/**/*.md", "instructions", "roo", "roo-rule"),
    ("**/.kiro/steering/**/*.md", "instructions", "kiro", "kiro-steering"),
    ("**/.amazonq/rules/**/*.md", "instructions", "amazon-q", "amazonq-rule"),
    ("**/.junie/guidelines.md", "instructions", "junie", "junie-guidelines"),
    ("**/.continue/rules/**/*.md", "instructions", "continue", "continue-rule"),
    ("**/.continue/prompts/**/*.{prompt,md}", "command", "continue", "continue-prompt"),
    ("**/.codex/prompts/**/*.md", "command", "codex", "codex-prompt"),
    ("**/.opencode/agents/**/*.md", "agent", "opencode", "opencode-agent"),
    ("**/.opencode/agent/**/*.md", "agent", "opencode", "opencode-agent"),
    ("**/.opencode/commands/**/*.md", "command", "opencode", "opencode-command"),
    ("**/.opencode/command/**/*.md", "command", "opencode", "opencode-command"),
    ("**/*.prompty", "prompt", "prompty", "prompty"),
    ("**/*.prompt.md", "prompt", "generic", "prompt-file"),
    ("**/*.prompt", "prompt", "generic", "prompt-file"),
    ("llms.txt", "instructions", "llms-txt", "llms-txt"),
    ("llms-full.txt", "instructions", "llms-txt", "llms-txt"),
]

_PROMPT_DIR = re.compile(
    r"(^|/)(prompts?|prompt[-_]templates|system[-_]prompts)/|"
    r"(^|/)[^/]*(system[-_]?prompt|prompt[-_]?template|[-_.]prompt)[^/]*$|(^|/)prompt[^/]*$",
    re.I,
)
_PROMPT_EXT = (
    ".md",
    ".txt",
    ".j2",
    ".jinja",
    ".jinja2",
    ".hbs",
    ".mustache",
    ".tmpl",
    ".yaml",
    ".yml",
    ".xml",
    ".liquid",
)
_SKIP_NAMES = {"readme.md", "license", "license.md", "changelog.md", "index.md"}


class FileDetector:
    def __init__(self, files: RepoFiles):
        self.files = files
        self.drafts: list[AssetDraft] = []
        self.claimed: set[str] = set()
        self.mcp_consumed: set[str] = set()
        self.mcp_provided: set[str] = set()
        self.plugin_roots = self._plugin_roots()

    def run(self) -> list[AssetDraft]:
        steps: list[Callable[[], None]] = [
            self._plugins,
            self._markdown,
            self._plugin_components,
            self._prompt_dirs,
            self._prompt_yaml,
            self._mcp_configs,
            self._claude_settings,
            self._gemini,
            self._roomodes,
            self._a2a_cards,
            self._crewai,
            self._langgraph,
            self._mcp_registry,
            self._evals,
            self._ai_workflows,
        ]
        for step in steps:
            try:
                step()
            except Exception as exc:  # one bad file must never sink the repo scan
                log.warning("AI detector %s failed: %s", step.__name__, exc)
        return self.drafts

    # -- helpers -------------------------------------------------------------------------

    def _add(self, draft: AssetDraft) -> None:
        self.drafts.append(draft)
        self.claimed.add(draft.path)

    def _plugin_roots(self) -> list[str]:
        roots = []
        for f in self.files.glob("**/.claude-plugin/plugin.json"):
            parent = str(PurePosixPath(f.path).parent.parent)
            roots.append("" if parent == "." else parent)
        return roots

    def _plugin_root_of(self, path: str) -> str | None:
        for root in sorted(self.plugin_roots, key=len, reverse=True):
            if root == "" or path.startswith(root + "/"):
                return root
        return None

    def _bundle(self, folder: str, exclude: str) -> list[AssetFile]:
        prefix = f"{folder}/" if folder else ""
        return [
            AssetFile(path=f.path[len(prefix) :], size=f.size)
            for f in self.files.files
            if f.path.startswith(prefix) and f.path != exclude
        ][:100]

    def _read(self, entry: FileEntry) -> str | None:
        return self.files.read(entry.path, 400_000)

    # -- markdown conventions ----------------------------------------------------------------

    def _markdown(self) -> None:
        for glob, kind, eco, detector in MARKDOWN_RULES:
            for entry in self.files.glob(glob):
                if entry.path in self.claimed:
                    continue
                text = self._read(entry)
                if text is None:
                    continue
                self._add(self._markdown_asset(entry, text, kind, eco, detector))

    def _markdown_asset(
        self, entry: FileEntry, text: str, kind: str, eco: str, detector: str
    ) -> AssetDraft:
        fm, body = parse_frontmatter(text)
        path = PurePosixPath(entry.path)
        plugin_root = self._plugin_root_of(entry.path)
        if eco == "*":
            eco = _skill_ecosystem(entry.path, plugin_root is not None)
        name = str(fm.get("name") or "")
        if kind == "skill":
            name = name or path.parent.name
        elif kind == "command":
            name = name or _command_name(entry.path)
        elif kind == "instructions" and not name:
            name = (
                entry.path
                if path.name.upper() in {"CLAUDE.MD", "AGENTS.MD", "GEMINI.MD"}
                else path.name.split(".")[0]
            )
        else:
            name = name or path.name.split(".")[0]
        draft = AssetDraft(
            kind=kind,
            ecosystem=eco,
            name=name,
            path=entry.path,
            detector=detector,
            text=text,
            body=body,
            frontmatter=fm,
            description=_str(fm.get("description"))
            or (_first_line(body) if kind in ("command", "prompt") else None),
            title=_str(fm.get("title")),
            scope="plugin" if plugin_root is not None and kind != "instructions" else "repo",
            license=_str(fm.get("license")),
            version=_str(fm.get("version")),
        )
        draft.tools = as_list(fm.get("allowed-tools") or fm.get("tools") or fm.get("allowedTools"))
        model = fm.get("model")
        if isinstance(model, dict):
            model = model.get("configuration", {}).get("model") or model.get("name")
        if model and str(model) != "inherit":
            draft.models.append(str(model))
        for key in ("globs", "applyTo", "paths"):
            draft.triggers += as_list(fm.get(key))
        for key in ("trigger", "when-to-use", "when_to_use"):
            if fm.get(key):
                draft.triggers.append(str(fm[key]))
        if fm.get("alwaysApply") is True:
            draft.triggers.append("always")
        hint = fm.get("argument-hint")
        if hint:  # unquoted "[issue-number]" parses as a YAML list
            draft.arguments.append(
                " ".join(f"[{h}]" for h in hint) if isinstance(hint, list) else str(hint)
            )
        draft.arguments += re.findall(r"\$ARGUMENTS|\$\d\b", body)[:5]
        draft.mcp_servers = as_list(fm.get("mcpServers") or fm.get("mcp-servers"))
        meta = fm.get("metadata")
        if isinstance(meta, dict):
            draft.tags += [f"{k}:{v}" for k, v in meta.items() if isinstance(v, str)][:10]
        draft.tags += as_list(fm.get("tags"))
        if kind == "skill":
            draft.files = self._bundle(str(path.parent), entry.path)
        if detector == "prompty" and isinstance(fm.get("model"), dict):
            conn = fm["model"].get("configuration") or {}
            draft.providers.append(str(conn.get("type") or fm["model"].get("api") or ""))
        return draft

    def _plugin_components(self) -> None:
        """Claude Code plugins keep agents/commands at the plugin root, not under .claude/."""
        for root in self.plugin_roots:
            prefix = f"{root}/" if root else ""
            for sub, kind, det in (
                ("agents", "agent", "claude-plugin-agent"),
                ("commands", "command", "claude-plugin-command"),
            ):
                for entry in self.files.glob(f"{prefix}{sub}/**/*.md"):
                    if entry.path in self.claimed:
                        continue
                    text = self._read(entry)
                    if text:
                        self._add(self._markdown_asset(entry, text, kind, "claude-code", det))
            for entry in self.files.glob(f"{prefix}hooks/hooks.json"):
                self._hooks_from_json(entry, "claude-plugin-hooks", scope="plugin")

    def _prompt_dirs(self) -> None:
        for entry in self.files.files:
            if (
                entry.path in self.claimed
                or not _PROMPT_DIR.search(entry.path)
                or not entry.name.lower().endswith(_PROMPT_EXT)
                or entry.name.lower() in _SKIP_NAMES
                or entry.size > 200_000
            ):
                continue
            text = self._read(entry)
            if not text or len(text.strip()) < 40:
                continue
            fm, body = parse_frontmatter(text)
            name = str(fm.get("name") or PurePosixPath(entry.path).stem)
            variables = sorted(set(re.findall(r"\{\{\s*([\w.]+)\s*\}\}|\{(\w+)\}", body)))
            self._add(
                AssetDraft(
                    kind="prompt",
                    ecosystem="generic",
                    name=name,
                    path=entry.path,
                    detector="prompt-directory",
                    text=text,
                    body=body,
                    frontmatter=fm,
                    description=_str(fm.get("description")),
                    confidence="medium",
                    arguments=[a or b for a, b in variables][:20],
                )
            )

    def _prompt_yaml(self) -> None:
        """GitHub Models ``*.prompt.yml`` files: name, description, model, messages."""
        for entry in self.files.glob("**/*.prompt.yml", "**/*.prompt.yaml"):
            text = self._read(entry)
            if not text:
                continue
            data = yaml.safe_load(text) or {}
            if not isinstance(data, dict):
                continue
            self._add(
                AssetDraft(
                    kind="prompt",
                    ecosystem="github-models",
                    name=str(data.get("name") or PurePosixPath(entry.path).stem),
                    path=entry.path,
                    detector="github-models-prompt",
                    text=text,
                    description=_str(data.get("description")),
                    models=[str(data["model"])] if data.get("model") else [],
                    frontmatter={k: v for k, v in data.items() if k != "messages"},
                    arguments=sorted(set(re.findall(r"\{\{\s*(\w+)\s*\}\}", text)))[:20],
                )
            )

    # -- MCP --------------------------------------------------------------------------------

    def _mcp_configs(self) -> None:
        json_globs = (
            "**/.mcp.json",
            "**/mcp.json",
            "**/.cursor/mcp.json",
            "**/.vscode/mcp.json",
            "**/.roo/mcp.json",
            "**/.kiro/settings/mcp.json",
            "**/.amazonq/mcp.json",
            "**/claude_desktop_config.json",
            "**/.gemini/settings.json",
            "**/.claude/settings.json",
        )
        for entry in self.files.glob(*json_globs):
            text = self._read(entry)
            if not text:
                continue
            try:
                data = json.loads(_strip_jsonc(text))
            except json.JSONDecodeError:
                continue
            servers = (
                (data.get("mcpServers") or data.get("servers") or {})
                if isinstance(data, dict)
                else {}
            )
            if not isinstance(servers, dict) or not servers:
                continue
            self._mcp_config_asset(entry, text, servers, _mcp_eco(entry.path))
        for entry in self.files.glob("**/.codex/config.toml"):
            text = self._read(entry)
            try:
                servers = tomllib.loads(text or "").get("mcp_servers") or {}
            except tomllib.TOMLDecodeError:
                continue
            if servers:
                self._mcp_config_asset(entry, text or "", servers, "codex")

    def _mcp_config_asset(
        self, entry: FileEntry, text: str, servers: dict[str, Any], eco: str
    ) -> None:
        summary = {}
        for name, cfg in servers.items():
            cfg = cfg if isinstance(cfg, dict) else {}
            summary[name] = {
                "type": cfg.get("type") or ("http" if cfg.get("url") else "stdio"),
                "command": " ".join(
                    [str(cfg.get("command", "")), *[str(a) for a in cfg.get("args", [])][:6]]
                ).strip()
                or None,
                "url": cfg.get("url") or cfg.get("serverUrl"),
                "env": sorted((cfg.get("env") or {}).keys()),  # names only, never values
            }
            self.mcp_consumed.add(name)
        # never store raw config: env values / headers may contain secrets
        redacted = json.dumps({"mcpServers": summary}, indent=2)
        self.drafts.append(
            AssetDraft(
                kind="mcp-config",
                ecosystem=eco,
                name=f"MCP servers ({entry.path})",
                path=entry.path,
                detector="mcp-config",
                text=redacted,
                frontmatter={"servers": summary},
                mcp_servers=list(servers),
                description=f"Configures {len(servers)} MCP server(s): "
                + ", ".join(list(servers)[:8]),
            )
        )

    def _mcp_registry(self) -> None:
        for entry in self.files.glob("**/server.json"):
            text = self._read(entry) or ""
            if "modelcontextprotocol" not in text:
                continue
            data = json.loads(text)
            name = str(data.get("name") or entry.path)
            self.mcp_provided.add(name)
            self._add(
                AssetDraft(
                    kind="mcp-server",
                    ecosystem="mcp",
                    name=name,
                    path=entry.path,
                    detector="mcp-registry-server-json",
                    text=text,
                    description=_str(data.get("description")),
                    version=_str(data.get("version")),
                    frontmatter={
                        k: data[k] for k in ("packages", "remotes", "repository") if k in data
                    },
                )
            )

    # -- hooks / settings -----------------------------------------------------------------------

    def _claude_settings(self) -> None:
        for entry in self.files.glob("**/.claude/settings.json", "**/.claude/settings.local.json"):
            self._hooks_from_json(entry, "claude-settings-hooks")

    def _hooks_from_json(self, entry: FileEntry, detector: str, scope: str = "repo") -> None:
        text = self._read(entry)
        if not text:
            return
        try:
            data = json.loads(_strip_jsonc(text))
        except json.JSONDecodeError:
            return
        hooks = data.get("hooks") if isinstance(data, dict) else None
        if not isinstance(hooks, dict):
            return
        for event, groups in hooks.items():
            commands, matchers = [], []
            for group in groups if isinstance(groups, list) else []:
                if not isinstance(group, dict):
                    continue
                if group.get("matcher"):
                    matchers.append(str(group["matcher"]))
                for hook in group.get("hooks", []):
                    if isinstance(hook, dict):
                        commands.append(
                            str(hook.get("command") or hook.get("prompt") or hook.get("type"))
                        )
            snippet = json.dumps({event: groups}, indent=2)
            self.drafts.append(
                AssetDraft(
                    kind="hook",
                    ecosystem="claude-code",
                    name=f"{event}" + (f" [{', '.join(matchers)}]" if matchers else ""),
                    path=entry.path,
                    detector=detector,
                    text=snippet,
                    scope=scope,
                    triggers=[event, *matchers],
                    description=f"{event} hook running: "
                    + "; ".join(c[:120] for c in commands[:3]),
                    frontmatter={"event": event, "matchers": matchers, "commands": commands},
                )
            )

    # -- plugins / extensions ---------------------------------------------------------------------

    def _plugins(self) -> None:
        for entry in self.files.glob("**/.claude-plugin/plugin.json"):
            text = self._read(entry) or "{}"
            data = json.loads(text)
            root = str(PurePosixPath(entry.path).parent.parent)
            root = "" if root == "." else root
            components = {
                c: len(self.files.glob(f"{root + '/' if root else ''}{pat}"))
                for c, pat in (
                    ("skills", "skills/*/SKILL.md"),
                    ("agents", "agents/**/*.md"),
                    ("commands", "commands/**/*.md"),
                    ("hooks", "hooks/hooks.json"),
                    ("mcp", ".mcp.json"),
                )
            }
            author = data.get("author")
            self._add(
                AssetDraft(
                    kind="plugin",
                    ecosystem="claude-code",
                    name=str(data.get("name") or root),
                    path=entry.path,
                    detector="claude-plugin",
                    text=text,
                    description=_str(data.get("description")),
                    version=_str(data.get("version")),
                    license=_str(data.get("license")),
                    tags=as_list(data.get("keywords")),
                    frontmatter={
                        "author": author,
                        "components": components,
                        "homepage": data.get("homepage"),
                    },
                    files=self._bundle(root, entry.path)[:50],
                    scope="plugin",
                )
            )
        for entry in self.files.glob("**/.claude-plugin/marketplace.json"):
            text = self._read(entry) or "{}"
            data = json.loads(text)
            plugins = data.get("plugins") or []
            self._add(
                AssetDraft(
                    kind="plugin",
                    ecosystem="claude-code",
                    name=str(data.get("name") or "marketplace"),
                    path=entry.path,
                    detector="claude-marketplace",
                    text=text,
                    description=_str((data.get("metadata") or {}).get("description"))
                    or f"Plugin marketplace listing {len(plugins)} plugin(s)",
                    frontmatter={
                        "plugins": [
                            {
                                "name": p.get("name"),
                                "description": p.get("description"),
                                "source": p.get("source")
                                if isinstance(p.get("source"), str)
                                else None,
                            }
                            for p in plugins
                            if isinstance(p, dict)
                        ],
                        "owner": data.get("owner"),
                    },
                    tags=["marketplace"],
                )
            )
        for entry in self.files.glob("**/gemini-extension.json"):
            text = self._read(entry) or "{}"
            data = json.loads(text)
            servers = list((data.get("mcpServers") or {}).keys())
            self.mcp_consumed.update(servers)
            self._add(
                AssetDraft(
                    kind="plugin",
                    ecosystem="gemini",
                    name=str(data.get("name") or entry.path),
                    path=entry.path,
                    detector="gemini-extension",
                    text=text,
                    version=_str(data.get("version")),
                    mcp_servers=servers,
                    description=_str(data.get("description")),
                    frontmatter={
                        "contextFileName": data.get("contextFileName"),
                        "excludeTools": data.get("excludeTools"),
                    },
                )
            )

    def _gemini(self) -> None:
        for entry in self.files.glob("**/.gemini/commands/**/*.toml"):
            text = self._read(entry)
            if not text:
                continue
            data = tomllib.loads(text)
            rel = entry.path.split(".gemini/commands/", 1)[1].rsplit(".", 1)[0]
            self._add(
                AssetDraft(
                    kind="command",
                    ecosystem="gemini",
                    name="/" + rel.replace("/", ":"),
                    path=entry.path,
                    detector="gemini-command",
                    text=text,
                    body=str(data.get("prompt", "")),
                    description=_str(data.get("description")),
                    arguments=["{{args}}"] if "{{args}}" in text else [],
                )
            )

    def _roomodes(self) -> None:
        for entry in self.files.glob("**/.roomodes"):
            text = self._read(entry) or ""
            try:
                data = yaml.safe_load(text)  # JSON is valid YAML
            except yaml.YAMLError:
                continue
            for mode in (data or {}).get("customModes", []):
                if not isinstance(mode, dict):
                    continue
                body = "\n\n".join(
                    str(mode.get(k, "")) for k in ("roleDefinition", "customInstructions")
                )
                self.drafts.append(
                    AssetDraft(
                        kind="agent",
                        ecosystem="roo",
                        name=str(mode.get("name") or mode.get("slug")),
                        path=entry.path,
                        detector="roo-mode",
                        text=body,
                        body=body,
                        description=_str(mode.get("whenToUse") or mode.get("description")),
                        tools=as_list(mode.get("groups")),
                    )
                )

    def _a2a_cards(self) -> None:
        """Agent2Agent (A2A) agent cards: name, description, url, capabilities, skills."""
        for entry in self.files.glob(
            "**/.well-known/agent.json",
            "**/.well-known/agent-card.json",
            "**/agent-card.json",
            "**/agent_card.json",
            "**/agentcard.json",
        ):
            text = self._read(entry) or ""
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                continue
            if not isinstance(data, dict) or not ({"skills", "capabilities"} & data.keys()):
                continue
            skills = [s for s in data.get("skills") or [] if isinstance(s, dict)]
            body = "\n\n".join(
                f"## {s.get('name') or s.get('id')}\n{s.get('description', '')}\n"
                + "\n".join(f"- Example: {ex}" for ex in s.get("examples") or [])
                for s in skills
            )
            self._add(
                AssetDraft(
                    kind="agent",
                    ecosystem="a2a",
                    name=str(data.get("name") or entry.path),
                    path=entry.path,
                    detector="a2a-agent-card",
                    text=text,
                    body=body,
                    description=_str(data.get("description")),
                    version=_str(data.get("version")),
                    tools=[str(s.get("id") or s.get("name")) for s in skills],
                    tags=sorted({str(t) for s in skills for t in s.get("tags") or []})[:15],
                    frontmatter={
                        "url": data.get("url"),
                        "capabilities": data.get("capabilities"),
                        "input_modes": data.get("defaultInputModes"),
                        "output_modes": data.get("defaultOutputModes"),
                    },
                )
            )

    # -- frameworks with declarative configs -------------------------------------------------------

    def _crewai(self) -> None:
        for entry in self.files.glob("**/config/agents.{yaml,yml}"):
            text = self._read(entry) or ""
            data = yaml.safe_load(text) or {}
            if not isinstance(data, dict):
                continue
            for key, spec in data.items():
                if isinstance(spec, dict) and {"role", "goal"} <= spec.keys():
                    body = (
                        f"Role: {spec['role']}\nGoal: {spec['goal']}\n\n{spec.get('backstory', '')}"
                    )
                    self.drafts.append(
                        AssetDraft(
                            kind="agent",
                            ecosystem="crewai",
                            name=str(key),
                            path=entry.path,
                            detector="crewai-agents-yaml",
                            text=yaml.safe_dump({key: spec}),
                            body=body,
                            description=str(spec["goal"]).strip()[:500],
                            title=str(spec["role"]).strip(),
                            tools=as_list(spec.get("tools")),
                            models=[str(spec["llm"])] if spec.get("llm") else [],
                        )
                    )
            self.claimed.add(entry.path)
        for entry in self.files.glob("**/config/tasks.{yaml,yml}"):
            text = self._read(entry) or ""
            data = yaml.safe_load(text) or {}
            if isinstance(data, dict) and any(
                isinstance(v, dict) and "expected_output" in v for v in data.values()
            ):
                self._add(
                    AssetDraft(
                        kind="workflow",
                        ecosystem="crewai",
                        name=f"CrewAI tasks ({entry.path})",
                        path=entry.path,
                        detector="crewai-tasks-yaml",
                        text=text,
                        description=f"{len(data)} task(s): " + ", ".join(list(data)[:8]),
                        frontmatter={
                            "tasks": {
                                k: (v or {}).get("agent")
                                for k, v in data.items()
                                if isinstance(v, dict)
                            }
                        },
                    )
                )

    def _langgraph(self) -> None:
        for entry in self.files.glob("**/langgraph.json"):
            text = self._read(entry) or "{}"
            data = json.loads(text)
            graphs = data.get("graphs") or {}
            self._add(
                AssetDraft(
                    kind="workflow",
                    ecosystem="langgraph",
                    name=f"LangGraph app ({entry.path})",
                    path=entry.path,
                    detector="langgraph-json",
                    text=text,
                    description="LangGraph deployment with graphs: " + ", ".join(graphs),
                    frontmatter={"graphs": graphs},
                )
            )

    def _evals(self) -> None:
        for entry in self.files.glob(
            "**/promptfooconfig.{yaml,yml,json}", "**/promptfoo*.{yaml,yml}"
        ):
            text = self._read(entry) or ""
            data = (json.loads(text) if entry.suffix == ".json" else yaml.safe_load(text)) or {}
            if not isinstance(data, dict):
                continue
            providers = [
                p if isinstance(p, str) else p.get("id", "")
                for p in as_list_raw(data.get("providers"))
            ]
            self._add(
                AssetDraft(
                    kind="eval",
                    ecosystem="promptfoo",
                    name=str(data.get("description") or entry.path),
                    path=entry.path,
                    detector="promptfoo-config",
                    text=text,
                    description=_str(data.get("description")),
                    models=[p for p in providers if p],
                    frontmatter={
                        "prompts": as_list_raw(data.get("prompts"))[:20],
                        "test_count": len(as_list_raw(data.get("tests"))),
                    },
                )
            )

    def _ai_workflows(self) -> None:
        actions = {
            "anthropics/claude-code-action": "claude-code",
            "anthropics/claude-code-base-action": "claude-code",
            "openai/codex-action": "codex",
            "google-github-actions/run-gemini-cli": "gemini",
            "promptfoo/promptfoo-action": "promptfoo",
            "github/ai-inference": "github-models",
            "actions/ai-inference": "github-models",
        }
        for entry in self.files.glob(".github/workflows/*.{yml,yaml}"):
            text = self._read(entry) or ""
            used = {eco for action, eco in actions.items() if action in text}
            if not used:
                continue
            try:
                data = yaml.safe_load(text) or {}
            except yaml.YAMLError:
                data = {}
            prompts = [
                m.strip()
                for m in re.findall(
                    r"(?:prompt|direct_prompt|custom_instructions):\s*\|?\s*\n?((?:\s{6,}.*\n?)+)",
                    text,
                )
            ]
            events = (
                list((data.get(True) or data.get("on") or {}).keys())
                if isinstance(data.get(True) or data.get("on"), dict)
                else as_list(data.get(True) or data.get("on"))
            )
            model = re.search(r"--model[ =]['\"]?([\w.\-:/]+)|model:\s*['\"]?([\w.\-:/]+)", text)
            eco = sorted(used)[0]
            self._add(
                AssetDraft(
                    kind="eval" if eco == "promptfoo" else "workflow",
                    ecosystem=eco,
                    name=str(data.get("name") or entry.path),
                    path=entry.path,
                    detector="ai-github-action",
                    text=text,
                    body="\n\n".join(prompts) or text,
                    description=f"GitHub Actions workflow using {', '.join(sorted(used))}"
                    + (f" on {', '.join(map(str, events))}" if events else ""),
                    triggers=[str(e) for e in events],
                    models=[g for g in (model.groups() if model else ()) if g],
                    tags=["ci", "automation"],
                )
            )


def as_list_raw(v: Any) -> list[Any]:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _skill_ecosystem(path: str, in_plugin: bool) -> str:
    p = path.lower()
    for marker, eco in (
        (".claude/skills/", "claude-code"),
        (".github/skills/", "copilot"),
        (".cursor/skills/", "cursor"),
        (".codex/skills/", "codex"),
        (".opencode/skill", "opencode"),
        (".agents/skills/", "agent-skills"),
    ):
        if marker in p:
            return eco
    return "claude-code" if in_plugin else "agent-skills"


def _command_name(path: str) -> str:
    for marker in ("/commands/", "/prompts/", "/workflows/", "/command/"):
        if marker in "/" + path:
            rel = ("/" + path).split(marker, 1)[1]
            stem = rel.rsplit(".", 1)[0].removesuffix(".prompt")
            return "/" + stem.replace("/", ":")
    return "/" + PurePosixPath(path).stem


def _mcp_eco(path: str) -> str:
    p = path.lower()
    for marker, eco in (
        (".cursor/", "cursor"),
        (".vscode/", "vscode"),
        (".roo/", "roo"),
        (".kiro/", "kiro"),
        (".amazonq/", "amazon-q"),
        (".gemini/", "gemini"),
        ("claude_desktop", "claude-desktop"),
    ):
        if marker in p:
            return eco
    return "claude-code" if p.endswith(".mcp.json") or ".claude/" in p else "mcp"


def _strip_jsonc(text: str) -> str:
    text = re.sub(r"^\s*//.*$", "", text, flags=re.M)
    return re.sub(r",(\s*[}\]])", r"\1", text)


def _first_line(body: str) -> str | None:
    for line in body.splitlines():
        s = line.strip().lstrip("#").strip()
        if len(s) > 10:
            return s[:300]
    return None


def _str(v: Any) -> str | None:
    if v is None or v == "":
        return None
    return str(v).strip()
