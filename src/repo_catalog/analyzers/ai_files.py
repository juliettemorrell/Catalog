"""Detect AI assets that live in well-known files: skills, agents, commands, rules,
instruction files, MCP configs, hooks, plugins, prompt files, evals and AI CI workflows.

Conventions covered (as of 2026): Agent Skills (SKILL.md), Claude Code (incl. plugins and
marketplaces), AGENTS.md, GitHub Copilot (instructions, prompts, agents, skills, hooks,
agent plugins, agentic workflows), Cursor, Windsurf, Cline, Roo, Kiro, Amazon Q, Junie,
Continue, Gemini CLI, OpenAI Codex, OpenCode, Trae, Augment, Firebase Studio, Antigravity,
Factory, A2A agent cards, Prompty, GitHub Models prompt files, promptfoo, CrewAI,
LangGraph, MCP registry ``server.json`` and ``llms.txt``.

Every file is parsed in isolation: a malformed file is recorded in ``errors`` (surfaced as
the repo's ``scan_errors``) and never hides other assets.
"""

from __future__ import annotations

import json
import logging
import re
import tomllib
from collections.abc import Callable, Iterable
from pathlib import PurePosixPath
from typing import Any

from ..fs import FileEntry, RepoFiles, escape_glob
from ..models import AssetFile
from ..textutil import (
    SECRET_NAME,
    load_json,
    load_yaml,
    redact_args,
    redact_url,
    sanitize_config,
)
from .ai_common import AssetDraft, as_list, parse_frontmatter
from .flags import find_secrets

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
    ("**/.github/prompts/**/*.prompt.md", "command", "copilot", "copilot-prompt"),
    ("**/.github/agents/**/*.md", "agent", "copilot", "copilot-agent"),
    # Copilot file-name conventions are also used outside .github (shared libraries)
    ("**/*.instructions.md", "instructions", "copilot", "copilot-instructions"),
    ("**/*.agent.md", "agent", "copilot", "copilot-agent"),
    ("**/*.chatmode.md", "agent", "copilot", "copilot-chatmode"),
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
    ("**/.opencode/agent{,s}/**/*.md", "agent", "opencode", "opencode-agent"),
    ("**/.opencode/command{,s}/**/*.md", "command", "opencode", "opencode-command"),
    ("**/.trae/rules/**/*.md", "instructions", "trae", "trae-rule"),
    ("**/.augment/rules/**/*.md", "instructions", "augment", "augment-rule"),
    ("**/.augment-guidelines", "instructions", "augment", "augment-rule"),
    ("**/.idx/airules.md", "instructions", "firebase-studio", "idx-airules"),
    ("**/.agent/rules/**/*.md", "instructions", "antigravity", "antigravity-rule"),
    ("**/.agent/workflows/**/*.md", "command", "antigravity", "antigravity-workflow"),
    ("**/.factory/droids/**/*.md", "agent", "factory", "factory-droid"),
    ("**/*.prompty", "prompt", "prompty", "prompty"),
    ("**/*.prompt.md", "prompt", "copilot", "prompt-file"),
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
_TRIGGER_KEYS = ("globs", "applyTo", "paths", "fileMatchPattern", "regex")
_TRIGGER_SCALARS = ("trigger", "when-to-use", "when_to_use", "inclusion")

MCP_CONFIG_GLOBS = (
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
    "**/.idx/mcp.json",
    "**/.trae/mcp.json",
)


class FileDetector:
    def __init__(self, files: RepoFiles, repo_name: str = ""):
        self.files = files
        self.repo_name = repo_name
        self.drafts: list[AssetDraft] = []
        self.claimed: set[str] = set()
        self.errors: list[str] = []
        self.mcp_consumed: set[str] = set()
        self.mcp_provided: set[str] = set()
        self.plugin_roots = self._plugin_roots()

    def run(self) -> list[AssetDraft]:
        steps: list[tuple[Callable[[], Iterable[Any]], Callable[[Any], None]]] = [
            (lambda: self.files.glob("**/.claude-plugin/plugin.json"), self._claude_plugin),
            (lambda: self.files.glob("**/plugin.json"), self._agent_plugin),
            (lambda: self.files.glob("**/.claude-plugin/marketplace.json"), self._marketplace),
            (lambda: self.files.glob("**/gemini-extension.json"), self._gemini_extension),
            (self._markdown_entries, self._markdown_one),
            (lambda: self.files.glob("**/*.mdc"), self._cursor_mdc),
            (
                lambda: self.files.glob("**/.github/workflows/*.md", "workflows/*.md"),
                self._agentic_workflow,
            ),
            (self._plugin_component_entries, self._plugin_component),
            (
                lambda: self.files.glob("**/hooks.json", "**/.github/hooks/**/*.json"),
                self._hook_file,
            ),
            (
                lambda: self.files.glob(
                    "**/.claude/settings.json", "**/.claude/settings.local.json"
                ),
                lambda e: self._hooks_from_json(e, "claude-settings-hooks"),
            ),
            (lambda: self.files.glob("**/*.prompt.yml", "**/*.prompt.yaml"), self._prompt_yaml),
            (lambda: self.files.files, self._prompt_dir),
            (lambda: self.files.glob(*MCP_CONFIG_GLOBS), self._mcp_config_json),
            (lambda: self.files.glob("**/.codex/config.toml"), self._mcp_config_codex),
            (lambda: self.files.glob("**/server.json"), self._mcp_registry),
            (lambda: self.files.glob("**/.gemini/commands/**/*.toml"), self._gemini_command),
            (lambda: self.files.glob("**/.roomodes"), self._roomodes),
            (
                lambda: self.files.glob(
                    "**/.well-known/agent{,-card}.json", "**/agent{-,_,}card.json"
                ),
                self._a2a_card,
            ),
            (lambda: self.files.glob("**/config/agents.{yaml,yml}"), self._crewai_agents),
            (lambda: self.files.glob("**/config/tasks.{yaml,yml}"), self._crewai_tasks),
            (lambda: self.files.glob("**/langgraph.json"), self._langgraph),
            (
                lambda: self.files.glob(
                    "**/promptfooconfig.{yaml,yml,json}", "**/promptfoo*.{yaml,yml}"
                ),
                self._promptfoo,
            ),
            (lambda: self.files.glob(".github/workflows/*.{yml,yaml}"), self._ai_workflow),
        ]
        for entries, handler in steps:
            try:
                items = list(entries())
            except Exception as exc:
                self.errors.append(f"AI detector listing failed: {type(exc).__name__}: {exc}")
                continue
            for item in items:
                entry = item[0] if isinstance(item, tuple) else item
                try:
                    handler(item)
                except RecursionError:
                    self.errors.append(f"{entry.path}: too deeply nested to parse")
                except Exception as exc:  # one bad file must never hide other assets
                    self.errors.append(f"{entry.path}: {type(exc).__name__}: {str(exc)[:200]}")
        return self.drafts

    # -- helpers -------------------------------------------------------------------------

    def _add(self, draft: AssetDraft) -> None:
        self.drafts.append(draft)
        self.claimed.add(draft.path)

    def _read(self, entry: FileEntry) -> str | None:
        return self.files.read(entry.path, 400_000)

    def _json(self, entry: FileEntry) -> Any:
        text = self._read(entry)
        return load_json(text) if text else None

    def _yaml(self, entry: FileEntry) -> Any:
        text = self._read(entry)
        return load_yaml(text) if text else None

    def _plugin_roots(self) -> list[str]:
        roots: set[str] = set()
        for f in self.files.glob("**/.claude-plugin/plugin.json"):
            parent = str(PurePosixPath(f.path).parent.parent)
            roots.add("" if parent == "." else parent)
        # plugins listed in a marketplace need no plugin.json of their own ("strict": false)
        for f in self.files.glob("**/.claude-plugin/marketplace.json"):
            try:
                data = load_json(self.files.read(f.path) or "{}")
            except ValueError:
                continue
            base = PurePosixPath(f.path).parent.parent
            for p in (data.get("plugins") or []) if isinstance(data, dict) else []:
                src = p.get("source") if isinstance(p, dict) else None
                if isinstance(src, str) and src.startswith("./"):
                    root = (base / src[2:]).as_posix().strip("/")
                    roots.add("" if root == "." else root)
        return sorted(roots)

    def _plugin_root_of(self, path: str) -> str | None:
        for root in sorted(self.plugin_roots, key=len, reverse=True):
            if root == "" or path.startswith(root + "/"):
                return root
        return None

    def _bundle(self, folder: str, exclude: str) -> list[AssetFile]:
        folder = "" if folder == "." else folder
        prefix = f"{folder}/" if folder else ""
        return [
            AssetFile(path=f.path[len(prefix) :], size=f.size)
            for f in self.files.under(folder)
            if f.path != exclude
        ][:100]

    # -- markdown conventions ----------------------------------------------------------------

    def _markdown_entries(self) -> list[tuple[FileEntry, str, str, str]]:
        out: list[tuple[FileEntry, str, str, str]] = []
        seen: set[str] = set()
        for glob, kind, eco, detector in MARKDOWN_RULES:
            for entry in self.files.glob(glob):
                if entry.path not in seen:
                    seen.add(entry.path)
                    out.append((entry, kind, eco, detector))
        return out

    def _markdown_one(self, item: tuple[FileEntry, str, str, str]) -> None:
        entry, kind, eco, detector = item
        if entry.path in self.claimed:
            return
        text = self._read(entry)
        if text is not None:
            self._add(self._markdown_asset(entry, text, kind, eco, detector))

    def _markdown_asset(
        self, entry: FileEntry, text: str, kind: str, eco: str, detector: str
    ) -> AssetDraft:
        fm, body = parse_frontmatter(text)
        path = PurePosixPath(entry.path)
        plugin_root = self._plugin_root_of(entry.path)
        if eco == "*":
            eco = _skill_ecosystem(entry.path, plugin_root is not None)
        name = _str(fm.get("name")) or ""
        tags: list[str] = []
        if kind == "skill":
            name = name or path.parent.name or self.repo_name or "skill"
        elif kind == "command":
            if not name:
                name, namespace = _command_name(entry.path, eco)
                if namespace:
                    tags.append(f"namespace:{namespace}")
        elif kind == "instructions" and not name:
            name = (
                entry.path
                if path.name.upper() in {"CLAUDE.MD", "AGENTS.MD", "GEMINI.MD", "AGENT.MD"}
                else path.name.split(".")[0] or path.name
            )
        else:
            name = name or path.name.split(".")[0] or path.name
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
            tags=tags,
        )
        draft.tools = as_list(fm.get("allowed-tools") or fm.get("tools") or fm.get("allowedTools"))
        model = fm.get("model")
        if isinstance(model, dict):
            conf = model.get("configuration")
            model = (conf.get("model") if isinstance(conf, dict) else None) or model.get("name")
        if model and str(model) != "inherit":
            draft.models.append(str(model))
        for key in _TRIGGER_KEYS:
            draft.triggers += as_list(fm.get(key))
        for key in _TRIGGER_SCALARS:
            if fm.get(key):
                draft.triggers.append(str(fm[key]))
        if fm.get("alwaysApply") in (True, "true"):
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
            conf = fm["model"].get("configuration")
            conf = conf if isinstance(conf, dict) else {}
            draft.providers.append(str(conf.get("type") or fm["model"].get("api") or ""))
        return draft

    def _cursor_mdc(self, entry: FileEntry) -> None:
        """``.mdc`` files with Cursor rule frontmatter, wherever they live (rule libraries)."""
        if entry.path in self.claimed:
            return
        text = self._read(entry)
        if not text:
            return
        fm, _ = parse_frontmatter(text)
        if not ({"description", "globs", "alwaysApply"} & fm.keys()):
            return
        draft = self._markdown_asset(entry, text, "instructions", "cursor", "cursor-rule")
        draft.confidence = "medium"
        self._add(draft)

    def _agentic_workflow(self, entry: FileEntry) -> None:
        """GitHub Agentic Workflows: markdown with ``on:`` frontmatter compiled by gh-aw."""
        if entry.path in self.claimed:
            return
        text = self._read(entry)
        if not text:
            return
        fm, body = parse_frontmatter(text)
        trigger = fm.get("on", fm.get("True"))  # YAML 1.1 reads a bare `on` key as True
        if trigger is None or not (
            {"permissions", "safe-outputs", "engine", "tools"} & {str(k) for k in fm}
        ):
            return
        events = list(trigger) if isinstance(trigger, dict) else as_list(trigger)
        engine = fm.get("engine")
        self._add(
            AssetDraft(
                kind="workflow",
                ecosystem="gh-aw",
                name=_str(fm.get("name")) or entry.path,
                path=entry.path,
                detector="github-agentic-workflow",
                text=text,
                body=body,
                frontmatter=fm,
                description=_str(fm.get("description")),
                triggers=[str(e) for e in events],
                tools=as_list(fm.get("tools")),
                models=[str(engine["model"])]
                if isinstance(engine, dict) and engine.get("model")
                else [],
                tags=["ci", "automation"],
            )
        )

    def _plugin_component_entries(self) -> list[tuple[FileEntry, str, str]]:
        """Claude Code plugins keep agents/commands at the plugin root, not under .claude/."""
        out = []
        for root in self.plugin_roots:
            prefix = f"{escape_glob(root)}/" if root else ""
            for sub, kind in (("agents", "agent"), ("commands", "command")):
                out += [
                    (e, kind, f"claude-plugin-{kind}")
                    for e in self.files.glob(f"{prefix}{sub}/**/*.md")
                ]
        return out

    def _plugin_component(self, item: tuple[FileEntry, str, str]) -> None:
        entry, kind, detector = item
        if entry.path in self.claimed:
            return
        text = self._read(entry)
        if text:
            self._add(self._markdown_asset(entry, text, kind, "claude-code", detector))

    def _prompt_dir(self, entry: FileEntry) -> None:
        name_lc = entry.name.lower()
        if (
            entry.path in self.claimed
            or not _PROMPT_DIR.search(entry.path)
            or not name_lc.endswith(_PROMPT_EXT)
            or name_lc.endswith((".prompt.yml", ".prompt.yaml"))
            or name_lc in _SKIP_NAMES
            or entry.size > 200_000
        ):
            return
        text = self._read(entry)
        if not text or len(text.strip()) < 40:
            return
        fm, body = parse_frontmatter(text)
        variables = sorted(set(re.findall(r"\{\{\s*([\w.]+)\s*\}\}|\{(\w+)\}", body)))
        self._add(
            AssetDraft(
                kind="prompt",
                ecosystem="generic",
                name=_str(fm.get("name")) or PurePosixPath(entry.path).stem,
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

    def _prompt_yaml(self, entry: FileEntry) -> None:
        """GitHub Models ``*.prompt.yml`` files: name, description, model, messages."""
        text = self._read(entry)
        data = load_yaml(text) if text else None
        if not text or not isinstance(data, dict):
            return
        self._add(
            AssetDraft(
                kind="prompt",
                ecosystem="github-models",
                name=_str(data.get("name")) or entry.name.split(".")[0],
                path=entry.path,
                detector="github-models-prompt",
                text=text,
                description=_str(data.get("description")),
                models=[str(data["model"])] if data.get("model") else [],
                frontmatter=sanitize_config({k: v for k, v in data.items() if k != "messages"}),
                arguments=sorted(set(re.findall(r"\{\{\s*(\w+)\s*\}\}", text)))[:20],
            )
        )

    # -- MCP --------------------------------------------------------------------------------

    def _mcp_config_json(self, entry: FileEntry) -> None:
        data = self._json(entry)
        if not isinstance(data, dict):
            return
        servers = data.get("mcpServers") or data.get("servers") or {}
        if isinstance(servers, dict) and servers:
            self._mcp_config_asset(entry, servers, _mcp_eco(entry.path))

    def _mcp_config_codex(self, entry: FileEntry) -> None:
        servers = tomllib.loads(self._read(entry) or "").get("mcp_servers") or {}
        if isinstance(servers, dict) and servers:
            self._mcp_config_asset(entry, servers, "codex")

    def _mcp_config_asset(self, entry: FileEntry, servers: dict[str, Any], eco: str) -> None:
        summary: dict[str, dict[str, Any]] = {}
        for name, cfg in servers.items():
            cfg = cfg if isinstance(cfg, dict) else {}
            args: list[Any] = cfg["args"] if isinstance(cfg.get("args"), list) else []
            url = cfg.get("url") or cfg.get("serverUrl") or cfg.get("httpUrl")
            env: dict[str, Any] = cfg["env"] if isinstance(cfg.get("env"), dict) else {}
            summary[str(name)] = {
                "type": cfg.get("type") or ("http" if url else "stdio"),
                "command": " ".join(
                    redact_args([str(cfg.get("command", "")), *[str(a) for a in args][:8]])
                ).strip()
                or None,
                "url": redact_url(str(url)) if url else None,
                "env": sorted(env),  # names only, never values
                # a literal credential in a committed file is a leak even though we drop it
                "inline_secret": _has_inline_secret(cfg, env),
            }
            self.mcp_consumed.add(str(name))
        self.drafts.append(
            AssetDraft(
                kind="mcp-config",
                ecosystem=eco,
                name=f"MCP servers ({entry.path})",
                path=entry.path,
                detector="mcp-config",
                # never store the raw file: env values, headers and args may carry secrets
                text=json.dumps({"mcpServers": summary}, indent=2),
                frontmatter={"servers": summary},
                mcp_servers=list(summary),
                description=f"Configures {len(summary)} MCP server(s): "
                + ", ".join(list(summary)[:8]),
            )
        )
        self.claimed.add(entry.path)

    def _mcp_registry(self, entry: FileEntry) -> None:
        text = self._read(entry) or ""
        if "modelcontextprotocol" not in text:
            return
        data = load_json(text)
        if not isinstance(data, dict):
            return
        name = _str(data.get("name")) or entry.path
        self.mcp_provided.add(name)
        clean = sanitize_config(data)
        self._add(
            AssetDraft(
                kind="mcp-server",
                ecosystem="mcp",
                name=name,
                path=entry.path,
                detector="mcp-registry-server-json",
                text=json.dumps(clean, indent=1),
                description=_str(data.get("description")),
                version=_str(data.get("version")),
                frontmatter={
                    k: clean[k] for k in ("packages", "remotes", "repository") if k in clean
                },
            )
        )

    # -- hooks ------------------------------------------------------------------------------

    def _hook_file(self, entry: FileEntry) -> None:
        if entry.path in self.claimed:
            return
        root = self._plugin_root_of(entry.path)
        in_claude = root is not None or "/.claude/" in "/" + entry.path
        self._hooks_from_json(
            entry,
            "hook-file",
            scope="plugin" if root is not None else "repo",
            ecosystem="claude-code" if in_claude else None,
        )

    def _hooks_from_json(
        self, entry: FileEntry, detector: str, scope: str = "repo", ecosystem: str | None = None
    ) -> None:
        """Claude Code format: {event: [{matcher, hooks: [{type, command}]}]}.
        Copilot format: {"version": 1, "hooks": {event: [{type, bash, powershell}]}}."""
        data = self._json(entry)
        hooks = data.get("hooks") if isinstance(data, dict) else None
        if not isinstance(hooks, dict):
            return
        self.claimed.add(entry.path)
        for event, groups in hooks.items():
            commands: list[str] = []
            matchers: list[str] = []
            copilot_style = False
            for group in groups if isinstance(groups, list) else []:
                if not isinstance(group, dict):
                    continue
                if group.get("matcher"):
                    matchers.append(str(group["matcher"]))
                inner = group.get("hooks")
                if not isinstance(inner, list):  # flat entry: the group *is* the hook
                    inner = [group]
                    copilot_style = copilot_style or any(k in group for k in ("bash", "powershell"))
                for hook in inner:
                    if isinstance(hook, dict):
                        cmd = (
                            hook.get("command")
                            or hook.get("bash")
                            or hook.get("prompt")
                            or hook.get("powershell")
                            or hook.get("url")
                            or hook.get("type")
                        )
                        commands.append(str(sanitize_config(str(cmd))))
            eco = ecosystem or ("copilot" if copilot_style or "version" in data else "claude-code")
            self.drafts.append(
                AssetDraft(
                    kind="hook",
                    ecosystem=eco,
                    name=f"{event}" + (f" [{', '.join(matchers)}]" if matchers else ""),
                    path=entry.path,
                    detector=detector,
                    text=json.dumps({event: sanitize_config(groups)}, indent=2),
                    scope=scope,
                    triggers=[str(event), *matchers],
                    description=f"{event} hook running: "
                    + "; ".join(c[:120] for c in commands[:3]),
                    frontmatter={"event": event, "matchers": matchers, "commands": commands},
                )
            )

    # -- plugins / extensions ---------------------------------------------------------------------

    def _claude_plugin(self, entry: FileEntry) -> None:
        data = self._json(entry)
        if not isinstance(data, dict):
            return
        root = str(PurePosixPath(entry.path).parent.parent)
        root = "" if root == "." else root
        prefix = escape_glob(root) + "/" if root else ""
        components = {
            c: len(self.files.glob(f"{prefix}{pat}"))
            for c, pat in (
                ("skills", "skills/*/SKILL.md"),
                ("agents", "agents/**/*.md"),
                ("commands", "commands/**/*.md"),
                ("hooks", "hooks/hooks.json"),
                ("mcp", ".mcp.json"),
            )
        }
        self._add(
            AssetDraft(
                kind="plugin",
                ecosystem="claude-code",
                name=_str(data.get("name")) or root or self.repo_name,
                path=entry.path,
                detector="claude-plugin",
                text=json.dumps(sanitize_config(data), indent=1),
                description=_str(data.get("description")),
                version=_str(data.get("version")),
                license=_str(data.get("license")),
                tags=as_list(data.get("keywords")),
                frontmatter={
                    "author": sanitize_config(data.get("author")),
                    "components": components,
                    "homepage": _str(data.get("homepage")),
                },
                files=self._bundle(root, entry.path)[:50],
                scope="plugin",
            )
        )

    def _agent_plugin(self, entry: FileEntry) -> None:
        """Open agent-plugin manifests (e.g. Copilot plugins): ``plugin.json`` with a schema."""
        if entry.path in self.claimed or "/.claude-plugin/" in "/" + entry.path:
            return
        data = self._json(entry)
        if (
            not isinstance(data, dict)
            or not data.get("name")
            or not (
                "plugin" in str(data.get("$schema", ""))
                or {"skills", "agents", "commands", "hooks", "mcpServers"} & data.keys()
            )
        ):
            return
        root = str(PurePosixPath(entry.path).parent)
        root = "" if root == "." else root
        self._add(
            AssetDraft(
                kind="plugin",
                ecosystem="agent-plugins",
                name=str(data["name"]),
                path=entry.path,
                detector="agent-plugin",
                text=json.dumps(sanitize_config(data), indent=1),
                description=_str(data.get("description")),
                version=_str(data.get("version")),
                license=_str(data.get("license")),
                tags=as_list(data.get("keywords")),
                frontmatter={
                    "author": sanitize_config(data.get("author")),
                    "$schema": _str(data.get("$schema")),
                },
                files=self._bundle(root, entry.path)[:50],
                scope="plugin",
            )
        )

    def _marketplace(self, entry: FileEntry) -> None:
        data = self._json(entry)
        if not isinstance(data, dict):
            return
        plugins = [p for p in data.get("plugins") or [] if isinstance(p, dict)]
        meta: dict[str, Any] = data["metadata"] if isinstance(data.get("metadata"), dict) else {}
        self._add(
            AssetDraft(
                kind="plugin",
                ecosystem="claude-code",
                name=_str(data.get("name")) or "marketplace",
                path=entry.path,
                detector="claude-marketplace",
                text=json.dumps(sanitize_config(data), indent=1),
                description=_str(meta.get("description"))
                or f"Plugin marketplace listing {len(plugins)} plugin(s)",
                tools=[str(p.get("name")) for p in plugins if p.get("name")][:100],
                frontmatter={
                    "plugins": [
                        {
                            "name": _str(p.get("name")),
                            "description": _str(p.get("description")),
                            "source": p.get("source") if isinstance(p.get("source"), str) else None,
                        }
                        for p in plugins
                    ],
                    "owner": sanitize_config(data.get("owner")),
                },
                tags=["marketplace"],
            )
        )

    def _gemini_extension(self, entry: FileEntry) -> None:
        data = self._json(entry)
        if not isinstance(data, dict):
            return
        servers = (
            list(data.get("mcpServers") or {}) if isinstance(data.get("mcpServers"), dict) else []
        )
        self.mcp_consumed.update(servers)
        self._add(
            AssetDraft(
                kind="plugin",
                ecosystem="gemini",
                name=_str(data.get("name")) or entry.path,
                path=entry.path,
                detector="gemini-extension",
                text=json.dumps(sanitize_config(data), indent=1),
                version=_str(data.get("version")),
                mcp_servers=servers,
                description=_str(data.get("description")),
                frontmatter={
                    "contextFileName": data.get("contextFileName"),
                    "excludeTools": data.get("excludeTools"),
                },
            )
        )

    def _gemini_command(self, entry: FileEntry) -> None:
        text = self._read(entry)
        if not text:
            return
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

    def _roomodes(self, entry: FileEntry) -> None:
        data = self._yaml(entry)  # JSON is valid YAML
        modes = data.get("customModes") if isinstance(data, dict) else None
        for mode in modes if isinstance(modes, list) else []:
            if not isinstance(mode, dict):
                continue
            body = "\n\n".join(
                str(mode.get(k) or "") for k in ("roleDefinition", "customInstructions")
            )
            self.drafts.append(
                AssetDraft(
                    kind="agent",
                    ecosystem="roo",
                    name=_str(mode.get("name")) or _str(mode.get("slug")) or "mode",
                    path=entry.path,
                    detector="roo-mode",
                    text=body,
                    body=body,
                    description=_str(mode.get("whenToUse") or mode.get("description")),
                    tools=as_list(mode.get("groups")),
                )
            )
        self.claimed.add(entry.path)

    def _a2a_card(self, entry: FileEntry) -> None:
        """Agent2Agent (A2A) agent cards: name, description, url, capabilities, skills."""
        data = self._json(entry)
        if not isinstance(data, dict) or not ({"skills", "capabilities"} & data.keys()):
            return
        skills = [s for s in data.get("skills") or [] if isinstance(s, dict)]
        body = "\n\n".join(
            f"## {s.get('name') or s.get('id')}\n{s.get('description', '')}\n"
            + "\n".join(f"- Example: {ex}" for ex in as_list_raw(s.get("examples")))
            for s in skills
        )
        self._add(
            AssetDraft(
                kind="agent",
                ecosystem="a2a",
                name=_str(data.get("name")) or entry.path,
                path=entry.path,
                detector="a2a-agent-card",
                text=json.dumps(sanitize_config(data), indent=1),
                body=body,
                description=_str(data.get("description")),
                version=_str(data.get("version")),
                tools=[str(s.get("id") or s.get("name")) for s in skills],
                tags=sorted({str(t) for s in skills for t in as_list_raw(s.get("tags"))})[:15],
                frontmatter=sanitize_config(
                    {
                        "url": data.get("url"),
                        "capabilities": data.get("capabilities"),
                        "input_modes": data.get("defaultInputModes"),
                        "output_modes": data.get("defaultOutputModes"),
                    }
                ),
            )
        )

    # -- frameworks with declarative configs -------------------------------------------------------

    def _crewai_agents(self, entry: FileEntry) -> None:
        data = self._yaml(entry)
        if not isinstance(data, dict):
            return
        for key, spec in data.items():
            if isinstance(spec, dict) and {"role", "goal"} <= spec.keys():
                body = f"Role: {spec['role']}\nGoal: {spec['goal']}\n\n{spec.get('backstory', '')}"
                self.drafts.append(
                    AssetDraft(
                        kind="agent",
                        ecosystem="crewai",
                        name=str(key),
                        path=entry.path,
                        detector="crewai-agents-yaml",
                        text=json.dumps({str(key): sanitize_config(spec)}, indent=1),
                        body=body,
                        description=str(spec["goal"]).strip()[:500],
                        title=str(spec["role"]).strip(),
                        tools=as_list(spec.get("tools")),
                        models=[str(spec["llm"])] if spec.get("llm") else [],
                    )
                )
        self.claimed.add(entry.path)

    def _crewai_tasks(self, entry: FileEntry) -> None:
        data = self._yaml(entry)
        if not isinstance(data, dict) or not any(
            isinstance(v, dict) and "expected_output" in v for v in data.values()
        ):
            return
        self._add(
            AssetDraft(
                kind="workflow",
                ecosystem="crewai",
                name=f"CrewAI tasks ({entry.path})",
                path=entry.path,
                detector="crewai-tasks-yaml",
                text=json.dumps(sanitize_config(data), indent=1),
                description=f"{len(data)} task(s): " + ", ".join(map(str, list(data)[:8])),
                frontmatter={
                    "tasks": {
                        str(k): _str(v.get("agent")) for k, v in data.items() if isinstance(v, dict)
                    }
                },
            )
        )

    def _langgraph(self, entry: FileEntry) -> None:
        data = self._json(entry)
        if not isinstance(data, dict):
            return
        graphs: dict[str, Any] = data["graphs"] if isinstance(data.get("graphs"), dict) else {}
        self._add(
            AssetDraft(
                kind="workflow",
                ecosystem="langgraph",
                name=f"LangGraph app ({entry.path})",
                path=entry.path,
                detector="langgraph-json",
                text=json.dumps(sanitize_config(data), indent=1),
                description="LangGraph deployment with graphs: " + ", ".join(map(str, graphs)),
                frontmatter={"graphs": sanitize_config(graphs)},
            )
        )

    def _promptfoo(self, entry: FileEntry) -> None:
        text = self._read(entry) or ""
        data = load_json(text) if entry.suffix == ".json" else load_yaml(text)
        if not isinstance(data, dict):
            return
        providers = [
            p if isinstance(p, str) else str(p.get("id", "")) if isinstance(p, dict) else ""
            for p in as_list_raw(data.get("providers"))
        ]
        self._add(
            AssetDraft(
                kind="eval",
                ecosystem="promptfoo",
                name=_str(data.get("description")) or entry.path,
                path=entry.path,
                detector="promptfoo-config",
                text=text,
                description=_str(data.get("description")),
                models=[m for m in (_promptfoo_model(p) for p in providers) if m],
                frontmatter=sanitize_config(
                    {
                        "prompts": as_list_raw(data.get("prompts"))[:20],
                        "test_count": len(as_list_raw(data.get("tests"))),
                    }
                ),
            )
        )

    def _ai_workflow(self, entry: FileEntry) -> None:
        actions = {
            "anthropics/claude-code-action": "claude-code",
            "anthropics/claude-code-base-action": "claude-code",
            "openai/codex-action": "codex",
            "google-github-actions/run-gemini-cli": "gemini",
            "promptfoo/promptfoo-action": "promptfoo",
            "github/ai-inference": "github-models",
            "actions/ai-inference": "github-models",
        }
        text = self._read(entry) or ""
        used = {eco for action, eco in actions.items() if action in text}
        if not used:
            return
        try:
            data = load_yaml(text)
        except Exception:
            data = None
        data = data if isinstance(data, dict) else {}
        prompts = [
            m.strip()
            for m in re.findall(
                r"(?:prompt|direct_prompt|custom_instructions):\s*\|?\s*\n?((?:\s{6,}.*\n?)+)", text
            )
        ]
        on = data.get(True, data.get("on"))
        events = list(on) if isinstance(on, dict) else as_list(on)
        model = re.search(r"--model[ =]['\"]?([\w.\-:/]+)|\bmodel:\s*['\"]?([\w.\-:/]+)", text)
        eco = sorted(used)[0]
        self._add(
            AssetDraft(
                kind="eval" if eco == "promptfoo" else "workflow",
                ecosystem=eco,
                name=_str(data.get("name")) or entry.path,
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
    p = "/" + path.lower()
    for marker, eco in (
        ("/.claude/skills/", "claude-code"),
        ("/.github/skills/", "copilot"),
        ("/.cursor/skills/", "cursor"),
        ("/.codex/skills/", "codex"),
        ("/.opencode/skill", "opencode"),
        ("/.agents/skills/", "agent-skills"),
    ):
        if marker in p:
            return eco
    return "claude-code" if in_plugin else "agent-skills"


def _command_name(path: str, eco: str) -> tuple[str, str | None]:
    """Slash-command name and namespace label.

    Claude Code invokes ``.claude/commands/frontend/component.md`` as ``/component``
    (the folder is only a label); tools like Codex/OpenCode use ``/folder:name``.
    """
    for marker in ("/commands/", "/prompts/", "/workflows/", "/command/"):
        if marker in "/" + path:
            rel = ("/" + path).split(marker, 1)[1]
            stem = rel.rsplit(".", 1)[0].removesuffix(".prompt")
            parts = stem.split("/")
            if eco == "claude-code":
                return "/" + parts[-1], ("/".join(parts[:-1]) or None)
            return "/" + ":".join(parts), None
    return "/" + PurePosixPath(path).stem.removesuffix(".prompt"), None


def _mcp_eco(path: str) -> str:
    p = "/" + path.lower()
    for marker, eco in (
        ("/.cursor/", "cursor"),
        ("/.vscode/", "vscode"),
        ("/.roo/", "roo"),
        ("/.kiro/", "kiro"),
        ("/.amazonq/", "amazon-q"),
        ("/.gemini/", "gemini"),
        ("/.idx/", "firebase-studio"),
        ("/.trae/", "trae"),
        ("claude_desktop", "claude-desktop"),
    ):
        if marker in p:
            return eco
    return "claude-code" if p.endswith("/.mcp.json") or "/.claude/" in p else "mcp"


def _first_line(body: str) -> str | None:
    for line in body.splitlines():
        s = line.strip().lstrip("#").strip()
        if len(s) > 10:
            return s[:300]
    return None


def _str(v: Any) -> str | None:
    if v is None or v == "" or isinstance(v, dict | list):
        return None
    return str(v).strip() or None


_ENV_REF = re.compile(r"^\s*(?:\$\{?|%|<|\{\{|\$env:|op://|vault:)|^\s*$")


def _has_inline_secret(cfg: dict[str, Any], env: dict[str, Any]) -> bool:
    raw = json.dumps(cfg, default=str)
    if next(iter(find_secrets(raw)), None):
        return True
    for key, value in {**env, **_headers(cfg)}.items():
        if not isinstance(value, str) or not SECRET_NAME.search(str(key)):
            continue
        value = re.sub(r"(?i)^(?:bearer|basic|token)\s+", "", value)
        # credential-looking: long, no spaces, mixes letters and digits (not "github-app")
        if (
            len(value) >= 16
            and not _ENV_REF.match(value)
            and not re.search(r"\s", value)
            and re.search(r"\d", value)
            and re.search(r"[A-Za-z]", value)
        ):
            return True
    return False


def _headers(cfg: dict[str, Any]) -> dict[str, Any]:
    h = cfg.get("headers") or cfg.get("http_headers")
    return h if isinstance(h, dict) else {}


def _promptfoo_model(provider: str) -> str | None:
    """``openai:gpt-4o`` / ``anthropic:messages:claude-sonnet-4-6`` -> the model id. HTTP,
    file, script and exec providers are not models (and URLs may carry credentials)."""
    provider = provider.strip()
    if not provider or re.match(r"^(https?|wss?|file|exec|python|js|golang|ruby)\b", provider):
        return None
    model = provider.rsplit(":", 1)[-1]
    return model if re.fullmatch(r"[A-Za-z0-9][\w.\-/@]{1,120}", model) else None
