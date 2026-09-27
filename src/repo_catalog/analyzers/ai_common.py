"""Shared helpers for AI asset detection: frontmatter parsing, asset construction, scoring."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

import yaml

from ..models import AIAsset, AssetFile, Flag
from ..textutil import load_yaml, redact_secrets, sanitize_config

MAX_CONTENT = 100_000

_FM = re.compile(r"\A﻿?---[ \t]*\r?\n(.*?)\r?\n---[ \t]*(?:\r?\n|\Z)", re.S)


def parse_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    """Split YAML frontmatter from a markdown body. Falls back to a line parser because
    real-world rule files often contain YAML-invalid values such as ``globs: *.ts``."""
    m = _FM.match(text)
    if not m:
        return {}, text
    raw, body = m.group(1), text[m.end() :]
    try:
        data = load_yaml(raw)
        if isinstance(data, dict):
            return _jsonable(data), body
    except (yaml.YAMLError, RecursionError, ValueError):
        pass
    fallback: dict[str, Any] = {}
    last_key: str | None = None
    for line in raw.splitlines():
        item = line.strip()
        if last_key and item.startswith("- ") and (line[:1] in (" ", "\t", "-")):
            # block list under the previous key (``tools:`` then ``  - Read`` lines)
            current = fallback.get(last_key)
            if current == "" or isinstance(current, list):
                items = current if isinstance(current, list) else []
                items.append(_fallback_value(item[2:]))
                fallback[last_key] = items
            continue
        key, sep, val = line.partition(":")
        if sep and key.strip() and not key.startswith((" ", "\t", "-")):
            last_key = key.strip()
            fallback[last_key] = _fallback_value(val.strip())
    return fallback, body


def _fallback_value(v: str) -> Any:
    """One frontmatter value when the whole block is not valid YAML: flow lists and maps
    (``tools: ["Read", "Grep"]``, ``[Read, Grep]``) are parsed on their own."""
    if v[:1] in ("[", "{"):
        for parse in (json.loads, load_yaml):
            try:
                parsed = parse(v)
            except (ValueError, yaml.YAMLError, RecursionError, TypeError):
                continue
            if isinstance(parsed, list | dict):
                return _jsonable(parsed)
    v = v.strip("'\"")
    return {"true": True, "false": False}.get(v.lower(), v)


def _jsonable(v: Any, depth: int = 0) -> Any:
    if depth > 30:
        return "…"
    if isinstance(v, dict):
        return {str(k): _jsonable(x, depth + 1) for k, x in list(v.items())[:500]}
    if isinstance(v, list | tuple):
        return [_jsonable(x, depth + 1) for x in v[:500]]
    if isinstance(v, str | int | float | bool) or v is None:
        return v
    return str(v)


def as_list(value: Any) -> list[str]:
    """Normalise tool/glob lists given as YAML lists, comma strings or space strings.
    Parenthesised groups stay together: ``Bash(git add:*) Read`` -> 2 items."""
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value[:200] if str(v).strip()]
    if isinstance(value, dict):
        return [str(k) for k in list(value)[:200]]
    s = str(value)[:20_000]
    sep_comma = "," in s
    items: list[str] = []
    buf: list[str] = []
    depth = 0
    for ch in s:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        if depth == 0 and (ch == "," or (not sep_comma and ch.isspace())):
            items.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    items.append("".join(buf))
    return [i.strip() for i in items if i.strip()][:200]


def headings(body: str, limit: int = 25) -> list[str]:
    out = [h.strip() for h in re.findall(r"^#{1,3}\s+(.+)$", body, re.M)]
    return out[:limit]


def excerpt(body: str, limit: int = 280) -> str | None:
    text = re.sub(r"```.*?```", " ", body, flags=re.S)
    text = re.sub(r"^#+\s.*$", " ", text, flags=re.M)
    text = re.sub(r"<[^<>\n]{1,200}>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        return None
    return text if len(text) <= limit else text[: limit - 1].rsplit(" ", 1)[0] + "…"


_HTML = re.compile(
    r"<(?:!doctype\s+html|html|head|body|div|span|table|tr|td|th|style|script|meta|link|br|"
    r"img|form|input|button|ul|ol|li|h[1-6]|p|a\s+href)\b[^>]{0,300}>",
    re.I,
)


def looks_like_html(text: str) -> bool:
    """HTML templates and pages, which are not prompts even when named ``*_template``."""
    head = text.lstrip()[:200].lower()
    if head.startswith(("<!doctype html", "<html", "<svg")):
        return True
    return len(_HTML.findall(text[:50_000])) >= 8


NEGATION = re.compile(
    r"(?i)\b(?:never|don'?t|do\s+not|does\s+not|must\s+not|should\s+not|shouldn'?t|avoid|"
    r"without|instead\s+of|forbid(?:den)?|prohibited|disallow(?:ed)?)\b"
)


def negated(text: str, start: int) -> bool:
    """True when the match at ``start`` sits in a clearly negated sentence on its line
    ("Never pass --dangerously-skip-permissions", "Do NOT use curl ... | sh")."""
    line_start = text.rfind("\n", 0, start) + 1
    prefix = text[line_start:start]
    # only the current sentence: "Never do X. Run curl | sh" is not negated
    prefix = re.split(r"[.!?;](?:\s|$)", prefix)[-1]
    return NEGATION.search(prefix) is not None


EXAMPLE_PATH = re.compile(
    r"(^|/)(examples?|samples?|demos?|templates?|cookbooks?|tutorials?|starters?|snippets|docs_src)/",
    re.I,
)


def asset_id(repo: str, path: str, kind: str, name: str) -> str:
    return hashlib.sha1(f"{repo}|{path}|{kind}|{name}".encode()).hexdigest()[:16]


@dataclass
class RepoContext:
    repo: str  # owner/name
    html_url: str
    ref: str  # commit sha or branch for blob links

    def url(self, path: str, line: int | None = None) -> str:
        anchor = f"#L{line}" if line else ""
        return f"{self.html_url}/blob/{self.ref}/{path}{anchor}"


@dataclass
class AssetDraft:
    """Mutable builder that becomes an ``AIAsset`` once finalised."""

    kind: str
    ecosystem: str
    name: str
    path: str
    detector: str
    text: str | None = None
    description: str | None = None
    title: str | None = None
    frontmatter: dict[str, Any] = field(default_factory=dict)
    body: str | None = None
    tools: list[str] = field(default_factory=list)
    models: list[str] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)
    triggers: list[str] = field(default_factory=list)
    arguments: list[str] = field(default_factory=list)
    mcp_servers: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    files: list[AssetFile] = field(default_factory=list)
    scope: str = "repo"
    confidence: str = "high"
    license: str | None = None
    version: str | None = None
    line: int | None = None
    # the description was written by the scanner (e.g. "MCP server exposing 3 tool(s)"),
    # not by the asset's author: it must not earn quality points
    auto_description: bool = False

    def build(self, ctx: RepoContext) -> AIAsset:
        from .flags import find_secrets  # local import: flags depends on manifests

        raw = "\n".join(x for x in (self.text, self.body, self.description) if x)
        leak = next(iter(find_secrets(raw)), None)
        text = redact_secrets(self.text or "")
        body = redact_secrets(self.body) if self.body is not None else text
        if EXAMPLE_PATH.search(self.path) and "example" not in self.tags:
            self.tags.append("example")
        truncated = len(text) > MAX_CONTENT
        content = text[:MAX_CONTENT] if text else None
        words = len(re.findall(r"\S+", body))
        asset = AIAsset(
            id=asset_id(ctx.repo, self.path, self.kind, self.name),
            kind=self.kind,  # type: ignore[arg-type]
            ecosystem=self.ecosystem,
            name=self.name,
            title=self.title,
            description=redact_secrets(self.description or "").strip() or None,
            repo=ctx.repo,
            path=self.path,
            url=ctx.url(self.path, self.line),
            scope=self.scope,  # type: ignore[arg-type]
            confidence=self.confidence,  # type: ignore[arg-type]
            detector=self.detector,
            frontmatter=sanitize_config(self.frontmatter),
            tools=_uniq(self.tools),
            models=_uniq(self.models),
            providers=_uniq(self.providers),
            triggers=_uniq(self.triggers),
            arguments=_uniq(self.arguments),
            mcp_servers=_uniq(self.mcp_servers),
            tags=_uniq(self.tags),
            license=self.license,
            version=self.version,
            content=content,
            content_truncated=truncated,
            excerpt=excerpt(body),
            headings=headings(body),
            files=self.files,
            line_count=text.count("\n") + 1 if text else 0,
            word_count=words,
            token_estimate=len(text) // 4,
            content_sha=hashlib.sha256(text.encode()).hexdigest() if text else None,
        )
        if leak:
            asset.flags.append(
                Flag(
                    id="secret-in-asset",
                    category="security",
                    severity="high",
                    message=f"{leak[0]} committed in this file (redacted here); rotate it",
                    path=self.path,
                )
            )
        score_asset(asset, body, authored_description=not self.auto_description)
        return asset


def _uniq(items: list[str]) -> list[str]:
    seen: list[str] = []
    for i in items:
        if i and i not in seen:
            seen.append(i)
    return seen


# -- quality heuristics -----------------------------------------------------------------------

_SKILL_NAME = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")


def score_asset(a: AIAsset, body: str, authored_description: bool = True) -> None:
    """0-100 heuristic of how reusable/well-specified an asset is, with actionable notes.
    ``authored_description=False`` when the scanner generated the description itself."""
    score, notes = 0, []

    def add(points: int, ok: bool, note: str) -> None:
        nonlocal score
        if ok:
            score += points
        else:
            notes.append(note)

    desc = (a.description or "") if authored_description else ""
    add(25, bool(desc), "Missing description (agents route on it).")
    add(10, 40 <= len(desc) <= 1024 or not desc, "Description is very short or over 1024 chars.")
    add(15, a.word_count >= 60, "Body is thin; add instructions, context or examples.")
    add(
        10,
        bool(a.headings) or a.kind in ("mcp-config", "settings", "hook", "sdk-usage", "mcp-server"),
        "No section headings; structure helps both humans and models.",
    )
    add(
        10,
        bool(re.search(r"```|<example>|\bexample", body, re.I))
        or a.kind in ("mcp-config", "settings", "hook", "instructions", "sdk-usage"),
        "No examples.",
    )
    add(10, a.line_count <= 500, "Very long (>500 lines); consider splitting into references.")
    add(10, bool(a.name) and not a.name.lower().startswith(("untitled", "new ")), "Unnamed.")

    if a.kind == "skill":
        name = str(a.frontmatter.get("name", ""))
        add(
            5,
            bool(_SKILL_NAME.match(name)) and len(name) <= 64,
            "Skill name must be lowercase-hyphenated, <= 64 chars (Agent Skills spec).",
        )
        folder = a.path.rsplit("/", 2)[-2] if a.path.count("/") >= 1 else ""
        add(5, name == folder, "Skill name should match its folder name (Agent Skills spec).")
        add(
            0,
            bool(re.search(r"\b(use (this )?when|when (the )?user|trigger)", desc, re.I)),
            "Description does not say when to use the skill.",
        )
    elif a.kind == "agent":
        add(5, bool(a.tools), "Agent does not restrict its tools (least privilege).")
        add(5, bool(a.models) or "model" in a.frontmatter, "Agent does not pin a model.")
    elif a.kind in ("command", "prompt"):
        add(
            10,
            bool(a.arguments) or bool(re.search(r"\$ARGUMENTS|\$\d|\{\{\s*\w+|\{\w+\}", body)),
            "No parameters/variables; prompt may be too specific to reuse.",
        )
    elif a.kind == "instructions":
        add(
            10,
            bool(re.search(r"\b(test|build|lint|run)\b", body, re.I)),
            "Does not mention how to build/test/lint.",
        )
    else:
        score += 10
    a.quality_score = max(0, min(100, score))
    a.quality_notes = notes
