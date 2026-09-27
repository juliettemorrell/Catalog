"""Governance flags for AI assets: what a security or platform team would want to review.

Everything here works on the already-built (redacted) asset, so no secret value is
ever needed or kept.
"""

from __future__ import annotations

import re
import shlex
from typing import Any

from ..models import AIAsset, Flag, Severity
from .ai_common import negated

_BYPASS = re.compile(
    r"--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|"
    r"permission[-_]?mode[\"']?\s*[=:,]?\s*[\"']?bypassPermissions|defaultMode[\"']?\s*[:=]\s*"
    r"[\"']?bypassPermissions|--yolo\b|--allow-all-tools\b|--approval-mode[=\s]+yolo|"
    r"danger-full-access"
)
_REMOTE_EXEC = re.compile(
    r"\b(?:curl|wget)\b[^|;&\n]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|"
    r"\b(?:ba|z)?sh\s+-c\s+[\"']?\$\((?:curl|wget)\b|\biex\s*\(\s*(?:irm|iwr|Invoke-WebRequest)"
)
_SHELL_TOOLS = {"Bash", "Bash(*)", "Bash(:*)", "Bash(*:*)", "run_shell_command"}
_LOCAL_HOSTS = re.compile(
    r"^https?://(?:localhost|127\.|0\.0\.0\.0|\[::1\]|host\.docker\.internal)"
)
_BYPASS_KINDS = {
    "hook",
    "mcp-config",
    "settings",
    "workflow",
    "plugin",
    "command",
    "agent",
    "skill",
}


def asset_flags(a: AIAsset) -> list[Flag]:
    flags: list[Flag] = []

    def add(fid: str, sev: Severity, msg: str) -> None:
        if not any(f.id == fid and f.message == msg for f in flags):
            flags.append(
                Flag(id=fid, category="ai-governance", severity=sev, message=msg, path=a.path)
            )

    content = a.content or ""
    if a.kind in _BYPASS_KINDS and (m := _affirmed(_BYPASS, content)):
        # docs-like assets describing the flag are less certain than configs running it
        sev: Severity = "medium" if a.kind in ("skill", "agent", "command") else "high"
        add("ai-permissions-bypassed", sev, f"Runs an agent with approvals disabled ({m.group(0)})")
    if a.kind in ("hook", "command", "skill", "workflow", "plugin") and _affirmed(
        _REMOTE_EXEC, content
    ):
        # hooks/workflows run it automatically; skills and commands tell an agent to
        remote_sev: Severity = "high" if a.kind in ("hook", "workflow", "plugin") else "medium"
        add("ai-remote-code-exec", remote_sev, "Downloads and executes remote code (curl | sh)")
    if a.kind in ("skill", "agent", "command") and _SHELL_TOOLS & set(a.tools):
        add(
            "ai-unrestricted-shell",
            "low",
            "Allows any shell command; scope it (e.g. Bash(git:*), Bash(npm test:*))",
        )
    if a.detector == "claude-settings":
        _settings_flags(a.frontmatter, add)
    if a.kind in ("mcp-config", "settings"):
        servers = a.frontmatter.get("servers")
        for name, cfg in (servers if isinstance(servers, dict) else {}).items():
            if isinstance(cfg, dict):
                _mcp_server_flags(str(name), cfg, add)
    return flags


def _affirmed(rx: re.Pattern[str], text: str) -> re.Match[str] | None:
    """First match that is not in a clearly negated sentence ("Never pass --yolo")."""
    for m in rx.finditer(text):
        if not negated(text, m.start()):
            return m
    return None


# interpreters and launchers: ``Bash(python:*)`` approves arbitrary code, not one tool
_INTERPRETERS = (
    "python",
    "python3",
    "node",
    "bash",
    "sh",
    "zsh",
    "fish",
    "pwsh",
    "powershell",
    "ruby",
    "perl",
    "php",
    "deno",
    "bun",
    "npx",
    "uvx",
    "eval",
    "sudo",
    "env",
    "xargs",
    "curl",
    "wget",
)
_BROAD_BASH = re.compile(
    r"^Bash(?:\(\s*(?:\*|:\*|\*:\*|(?:" + "|".join(_INTERPRETERS) + r")(?:\s*:?\s*\*))\s*\))?$"
)


def _settings_flags(settings: dict[str, Any], add: Any) -> None:
    """Claude Code settings committed to the repo apply to everyone who opens it."""
    perms = settings.get("permissions")
    perms = perms if isinstance(perms, dict) else {}
    allow = [str(x) for x in perms.get("allow") or [] if isinstance(x, str)]
    broad = [x for x in allow if _BROAD_BASH.match(x.strip())]
    if broad:
        add(
            "ai-unrestricted-shell",
            "medium",
            "Settings auto-approve arbitrary shell commands ("
            + ", ".join(broad[:3])
            + "); allow specific commands instead",
        )
    if settings.get("enableAllProjectMcpServers") is True:
        add(
            "mcp-auto-approved",
            "medium",
            "Settings auto-enable every MCP server in .mcp.json (enableAllProjectMcpServers); "
            "list approved servers in enabledMcpjsonServers",
        )
    if settings.get("local"):
        add(
            "ai-local-settings-committed",
            "low",
            "settings.local.json holds personal overrides and should be git-ignored",
        )


def _mcp_server_flags(name: str, cfg: dict[str, Any], add: Any) -> None:
    if cfg.get("inline_secret"):
        add(
            "mcp-inline-secret",
            "high",
            f"MCP server '{name}' has a credential written into the config; use env references",
        )
    url = cfg.get("url")
    if isinstance(url, str) and url.startswith("http://") and not _LOCAL_HOSTS.match(url):
        add("mcp-plaintext-http", "medium", f"MCP server '{name}' is reached over plain HTTP")
    command = cfg.get("command")
    if isinstance(command, str) and (pkg := unpinned_package(command)):
        add(
            "mcp-unpinned-package",
            "medium",
            f"MCP server '{name}' runs {pkg} without a pinned version (supply-chain risk)",
        )


# script runners resolve from the repo's own devDependencies; the script is the server
_RUNNERS = {"tsx", "ts-node", "node", "vite-node", "bun", "deno", "jiti", "esno", "tsm"}
_DOCKER_VALUE_FLAGS = {
    "-e",
    "--env",
    "-v",
    "--volume",
    "--name",
    "-p",
    "--publish",
    "--network",
    "--mount",
    "-w",
    "--workdir",
    "--env-file",
    "-u",
    "--user",
    "--entrypoint",
    "--platform",
    "-l",
    "--label",
}


def launched_package(command: str) -> tuple[str, str] | None:
    """(ecosystem, spec) of what an MCP launcher runs: ``npx -y @acme/mcp@1`` ->
    ("npm", "@acme/mcp@1"); ``uvx pkg==2`` -> ("pypi", "pkg==2"); images -> ("docker", ..).
    Local scripts and runners (``npx tsx src/server.ts``) return None."""
    try:
        argv = shlex.split(command)
    except ValueError:
        argv = command.split()
    if not argv:
        return None
    exe = argv[0].rsplit("/", 1)[-1]
    rest = argv[1:]
    if exe in ("npx", "bunx", "pnpx") or argv[:2] in (["pnpm", "dlx"], ["yarn", "dlx"]):
        rest = rest[1:] if exe in ("pnpm", "yarn") else rest
        pkg = _first_positional(rest, {"-p", "--package"})
        if pkg and pkg.split("@")[0] not in _RUNNERS and not pkg.startswith((".", "/")):
            return "npm", pkg
        return None
    if exe in ("uvx", "pipx") or argv[:2] == ["uv", "tool"]:
        if exe == "pipx":
            rest = rest[1:] if rest[:1] == ["run"] else rest
        if exe == "uv":
            rest = rest[2:] if rest[1:2] == ["run"] else rest[1:]
        if "--from" in rest:
            i = rest.index("--from")
            spec = rest[i + 1] if i + 1 < len(rest) else ""
        else:
            spec = _first_positional(rest, {"--python", "--with", "--index-url"}) or ""
        return ("pypi", spec) if spec and not spec.startswith((".", "/")) else None
    if exe in ("docker", "podman") and rest[:1] == ["run"]:
        image = _first_positional(rest[1:], _DOCKER_VALUE_FLAGS)
        return ("docker", image) if image else None
    return None


def unpinned_package(command: str) -> str | None:
    """The package/image an MCP launcher fetches without pinning a version, if any."""
    launched = launched_package(command)
    if not launched:
        return None
    ecosystem, spec = launched
    if ecosystem == "npm":
        _, _, version = spec[1:].partition("@") if spec.startswith("@") else spec.partition("@")
        return spec if not version or version == "latest" else None
    if ecosystem == "pypi":
        return spec if not re.search(r"==|@|\.whl$|^git\+|/", spec) else None
    last = spec.rsplit("/", 1)[-1]
    if "@sha256:" not in spec and (":" not in last or last.endswith(":latest")):
        return spec
    return None


def _first_positional(args: list[str], value_flags: set[str]) -> str | None:
    skip = False
    for arg in args:
        if skip:
            skip = False
            continue
        if arg in value_flags:
            skip = True
            continue
        if arg.startswith("-"):
            continue
        return arg
    return None
