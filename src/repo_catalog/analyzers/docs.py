"""README summarisation (heuristic), CODEOWNERS and self-declared catalog descriptors."""

from __future__ import annotations

import logging
import re
from typing import Any

import yaml

from ..fs import RepoFiles
from ..models import Declared, Summary

log = logging.getLogger(__name__)

_BADGE = re.compile(r"\[!\[[^\]]*\]\([^)]*\)\]\([^)]*\)|!\[[^\]]*\]\([^)]*\)")
_HTML = re.compile(r"<[^>]+>")
_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")


def find_readme(files: RepoFiles) -> str | None:
    hit = files.first(
        "README.md",
        "README.markdown",
        "README.rst",
        "README.txt",
        "README",
        "readme.md",
        "docs/README.md",
        ".github/README.md",
    )
    return hit.path if hit else None


def summarize_readme(files: RepoFiles) -> tuple[Summary, str]:
    """Heuristic summary plus the raw README text (for optional LLM enrichment)."""
    path = find_readme(files)
    text = files.read(path, 200_000) if path else None
    if not text:
        return Summary(), ""
    title: str | None = None
    m = re.search(r"^#\s+(.+)$", text, re.M) or re.search(r"^(.+)\n=+\s*$", text, re.M)
    if m:
        title = _clean(m.group(1))
    excerpt = _first_paragraphs(text)
    features = _features(text)
    return Summary(
        readme_title=title,
        readme_excerpt=excerpt,
        key_features=features,
        source="readme" if excerpt else "none",
    ), text


def _clean(s: str) -> str:
    s = _BADGE.sub("", s)
    s = _LINK.sub(r"\1", s)
    s = _HTML.sub("", s)
    s = re.sub(r"(\*\*|__|\*|`)", "", s)
    return re.sub(r"\s+", " ", s).strip(" #*_`")


def _first_paragraphs(text: str, limit: int = 700) -> str | None:
    body = re.sub(r"```.*?```", "", text, flags=re.S)
    body = re.sub(r"<!--.*?-->", "", body, flags=re.S)
    paras: list[str] = []
    for block in re.split(r"\n\s*\n", body):
        b = block.strip()
        if not b or b.startswith(("#", "|", "---", "===")) or re.match(r"^[-*+]\s", b):
            if paras and b.startswith("#"):
                break
            continue
        cleaned = _clean(b)
        if len(cleaned) < 25 or cleaned.lower().startswith(("table of contents", "contents")):
            continue
        paras.append(cleaned)
        if sum(len(p) for p in paras) >= limit:
            break
    out = " ".join(paras)
    return (out[: limit - 1] + "…") if len(out) > limit else (out or None)


def _features(text: str, max_items: int = 10) -> list[str]:
    m = re.search(
        r"^#{2,3}\s+.*\b(features?|highlights|capabilities|what it does)\b.*$", text, re.M | re.I
    )
    if not m:
        return []
    section = text[m.end() :]
    nxt = re.search(r"^#{1,3}\s", section, re.M)
    section = section[: nxt.start()] if nxt else section
    items = [_clean(x) for x in re.findall(r"^\s*[-*+]\s+(.+)$", section, re.M)]
    return [i for i in items if 3 < len(i) < 200][:max_items]


def first_sentence(text: str | None) -> str | None:
    if not text:
        return None
    m = re.match(r"(.+?[.!?])(\s|$)", text)
    return (m.group(1) if m else text)[:240]


# -- CODEOWNERS ---------------------------------------------------------------------------


def parse_codeowners(files: RepoFiles) -> list[str]:
    for path in (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"):
        text = files.read(path)
        if text:
            owners: list[str] = []
            for line in text.splitlines():
                line = line.split("#", 1)[0].strip()
                for tok in line.split()[1:]:
                    if "@" in tok and tok not in owners:
                        owners.append(tok)
            return owners
    return []


# -- self-declared metadata -------------------------------------------------------------------

_DESCRIPTORS = (
    "catalog-info.yaml",
    "catalog-info.yml",
    ".backstage/catalog-info.yaml",
    "cortex.yaml",
    "cortex.yml",
    "opslevel.yml",
    "opslevel.yaml",
    ".opslevel.yml",
    "compass.yml",
    "compass.yaml",
    "port.yml",
    ".port/port.yml",
)


def parse_declared(files: RepoFiles, custom_properties: dict[str, Any]) -> Declared:
    declared = Declared(custom_properties=custom_properties)
    for path in _DESCRIPTORS:
        text = files.read(path)
        if not text:
            continue
        try:
            docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
        except yaml.YAMLError as exc:
            log.info("bad descriptor %s: %s", path, exc)
            continue
        declared.source_files.append(path)
        for doc in docs:
            if "apiVersion" in doc and "backstage.io" in str(doc.get("apiVersion")):
                _backstage(doc, declared)
            elif "info" in doc and any(k.startswith("x-cortex") for k in doc["info"]):
                _cortex(doc["info"], declared)
            else:
                _generic(doc, declared)
    # custom properties commonly used for the same concepts
    for key, attr in (
        ("owner", "owner"),
        ("team", "owner"),
        ("system", "system"),
        ("domain", "domain"),
        ("lifecycle", "lifecycle"),
        ("tier", "tier"),
        ("service_tier", "tier"),
        ("type", "type"),
    ):
        for prop, val in custom_properties.items():
            if prop.lower().replace("-", "_") == key and val and not getattr(declared, attr):
                setattr(declared, attr, str(val) if not isinstance(val, list) else ",".join(val))
    return declared


def _backstage(doc: dict[str, Any], d: Declared) -> None:
    meta = doc.get("metadata") or {}
    spec = doc.get("spec") or {}
    if doc.get("kind") not in (None, "Component", "API", "Resource", "System"):
        return
    d.name = d.name or meta.get("name")
    d.owner = d.owner or _s(spec.get("owner"))
    d.system = d.system or _s(spec.get("system"))
    d.domain = d.domain or _s(spec.get("domain"))
    d.lifecycle = d.lifecycle or _s(spec.get("lifecycle"))
    d.type = d.type or _s(spec.get("type"))
    d.tags += [t for t in meta.get("tags") or [] if isinstance(t, str) and t not in d.tags]
    d.links += [
        {"url": str(link.get("url")), "title": str(link.get("title", ""))}
        for link in meta.get("links") or []
        if isinstance(link, dict) and link.get("url")
    ]
    d.provides_apis += [str(x) for x in spec.get("providesApis") or []]
    d.consumes_apis += [str(x) for x in spec.get("consumesApis") or []]
    d.depends_on += [str(x) for x in spec.get("dependsOn") or []]


def _cortex(info: dict[str, Any], d: Declared) -> None:
    d.name = d.name or info.get("x-cortex-tag") or info.get("title")
    owners = info.get("x-cortex-owners") or []
    if owners and isinstance(owners[0], dict):
        d.owner = d.owner or owners[0].get("name") or owners[0].get("email")
    d.tier = d.tier or _s(info.get("x-cortex-tier"))
    d.lifecycle = d.lifecycle or _s(info.get("x-cortex-lifecycle"))
    groups = info.get("x-cortex-groups") or []
    d.tags += [str(g) for g in groups if str(g) not in d.tags]
    for link in info.get("x-cortex-link") or []:
        if isinstance(link, dict) and link.get("url"):
            d.links.append({"url": str(link["url"]), "title": str(link.get("name", ""))})


def _generic(doc: dict[str, Any], d: Declared) -> None:
    """OpsLevel / Compass / Port style files: best-effort field mapping."""
    svc = doc.get("service") or doc.get("component") or doc
    if not isinstance(svc, dict):
        return
    d.name = d.name or _s(svc.get("name"))
    d.owner = d.owner or _s(svc.get("owner") or svc.get("ownerId") or svc.get("team"))
    d.lifecycle = d.lifecycle or _s(svc.get("lifecycle"))
    d.tier = d.tier or _s(svc.get("tier"))
    d.type = d.type or _s(svc.get("typeId") or svc.get("type"))
    for tag in svc.get("tags") or svc.get("labels") or []:
        val = (
            tag
            if isinstance(tag, str)
            else f"{tag.get('key')}:{tag.get('value')}"
            if isinstance(tag, dict)
            else None
        )
        if val and val not in d.tags:
            d.tags.append(val)
    for link in svc.get("links") or []:
        if isinstance(link, dict) and link.get("url"):
            d.links.append(
                {"url": str(link["url"]), "title": str(link.get("name") or link.get("title") or "")}
            )


def _s(v: Any) -> str | None:
    return str(v) if v not in (None, "") else None
