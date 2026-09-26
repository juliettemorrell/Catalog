"""Shared helpers for AI asset detection: frontmatter parsing, asset construction, scoring."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

import yaml

from ..models import AIAsset, AssetFile

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
        data = yaml.safe_load(raw)
        if isinstance(data, dict):
            return _jsonable(data), body
    except yaml.YAMLError:
        pass
    data = {}
    for line in raw.splitlines():
        key, sep, val = line.partition(":")
        if sep and key.strip() and not key.startswith((" ", "\t", "-")):
            data[key.strip()] = val.strip().strip("'\"")
    return data, body


def _jsonable(v: Any) -> Any:
    if isinstance(v, dict):
        return {str(k): _jsonable(x) for k, x in v.items()}
    if isinstance(v, list | tuple):
        return [_jsonable(x) for x in v]
    if isinstance(v, str | int | float | bool) or v is None:
        return v
    return str(v)


def as_list(value: Any) -> list[str]:
    """Normalise tool/glob lists given as YAML lists, comma strings or space strings."""
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, dict):
        return [str(k) for k in value]
    s = str(value)
    parts = re.split(r",\s*|\s+(?![^()]*\))", s) if "," in s or " " in s else [s]
    return [p.strip() for p in parts if p.strip()]


def headings(body: str, limit: int = 25) -> list[str]:
    out = [h.strip() for h in re.findall(r"^#{1,3}\s+(.+)$", body, re.M)]
    return out[:limit]


def excerpt(body: str, limit: int = 280) -> str | None:
    text = re.sub(r"```.*?```", " ", body, flags=re.S)
    text = re.sub(r"^#+\s.*$", " ", text, flags=re.M)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        return None
    return text if len(text) <= limit else text[: limit - 1].rsplit(" ", 1)[0] + "…"


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

    def build(self, ctx: RepoContext) -> AIAsset:
        text = self.text or ""
        body = self.body if self.body is not None else text
        truncated = len(text) > MAX_CONTENT
        content = text[:MAX_CONTENT] if text else None
        words = len(re.findall(r"\S+", body))
        asset = AIAsset(
            id=asset_id(ctx.repo, self.path, self.kind, self.name),
            kind=self.kind,  # type: ignore[arg-type]
            ecosystem=self.ecosystem,
            name=self.name,
            title=self.title,
            description=(self.description or "").strip() or None,
            repo=ctx.repo,
            path=self.path,
            url=ctx.url(self.path, self.line),
            scope=self.scope,  # type: ignore[arg-type]
            confidence=self.confidence,  # type: ignore[arg-type]
            detector=self.detector,
            frontmatter=self.frontmatter,
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
        score_asset(asset, body)
        return asset


def _uniq(items: list[str]) -> list[str]:
    seen: list[str] = []
    for i in items:
        if i and i not in seen:
            seen.append(i)
    return seen


# -- quality heuristics -----------------------------------------------------------------------

_SKILL_NAME = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")


def score_asset(a: AIAsset, body: str) -> None:
    """0-100 heuristic of how reusable/well-specified an asset is, with actionable notes."""
    score, notes = 0, []

    def add(points: int, ok: bool, note: str) -> None:
        nonlocal score
        if ok:
            score += points
        else:
            notes.append(note)

    desc = a.description or ""
    add(25, bool(desc), "Missing description (agents route on it).")
    add(10, 40 <= len(desc) <= 1024 or not desc, "Description is very short or over 1024 chars.")
    add(15, a.word_count >= 60, "Body is thin; add instructions, context or examples.")
    add(
        10,
        bool(a.headings) or a.kind in ("mcp-config", "hook", "sdk-usage", "mcp-server"),
        "No section headings; structure helps both humans and models.",
    )
    add(
        10,
        bool(re.search(r"```|<example>|\bexample", body, re.I))
        or a.kind in ("mcp-config", "hook", "instructions", "sdk-usage"),
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
