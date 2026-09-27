"""README summarisation (heuristic), CODEOWNERS and self-declared catalog descriptors."""

from __future__ import annotations

import logging
import re
from typing import Any

from ..fs import RepoFiles
from ..models import Declared, Summary
from ..textutil import load_yaml_all

log = logging.getLogger(__name__)

_BADGE = re.compile(
    r"\[!\[[^\]]*\]\([^)]*\)\]\([^)]*\)|!\[[^\]]*\]\([^)]*\)|"  # inline badges / images
    r"\[!\[[^\]]*\]\[[^\]]*\]\]\[[^\]]*\]|!\[[^\]]*\]\[[^\]]*\]"  # reference-style badges
)
_HTML = re.compile(r"<[^<>\n]{1,400}>")
_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)|\[([^\]]+)\]\[[^\]]*\]")
_REF_DEF = re.compile(r"^[ \t]*\[[^\]]+\]:\s*\S+.*$", re.M)
_FENCE = re.compile(r"^(```|~~~).*?^\1[^\n]*$", re.S | re.M)
_RST_DIRECTIVE = re.compile(r"^\.\. [\w|:-]+.*(?:\n[ \t]+.*)*", re.M)

README_CANDIDATES = (
    "README.md",
    "README.markdown",
    "README.mdx",
    "README.rst",
    "README.txt",
    "README",
    "readme.md",
    "Readme.md",
    "docs/README.md",
    ".github/README.md",
)


def find_readme(files: RepoFiles) -> str | None:
    """The main README: exact names only (``README.ja.md`` is a translation, not the one)."""
    hit = files.first(*README_CANDIDATES)
    return hit.path if hit else None


def summarize_readme(files: RepoFiles) -> tuple[Summary, str]:
    """Heuristic summary plus the raw README text (for optional LLM enrichment)."""
    path = find_readme(files)
    text = files.read(path, 200_000) if path else None
    if not text:
        return Summary(), ""
    body = _strip_noise(text)
    title = _title(body)
    excerpt = _first_paragraphs(body, title)
    features = _features(body)
    return Summary(
        readme_title=title,
        readme_excerpt=excerpt,
        key_features=features,
        source="readme" if excerpt else "none",
    ), text


def _strip_noise(text: str) -> str:
    text = text.replace("\r\n", "\n")
    text = _FENCE.sub("", text)
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    text = _REF_DEF.sub("", text)
    return _RST_DIRECTIVE.sub("", text)


def _title(body: str) -> str | None:
    candidates: list[tuple[int, str]] = []
    for rx in (
        re.compile(r"^#\s+(.+?)\s*#*\s*$", re.M),  # ATX
        re.compile(r"^(?!\s*$)([^\n]+)\n=+[ \t]*$", re.M),  # setext / RST
        re.compile(r"<h1[^>]*>(.*?)</h1>", re.S | re.I),  # HTML heading
    ):
        m = rx.search(body)
        if m:
            candidates.append((m.start(), m.group(1)))
    for _, raw in sorted(candidates):
        cleaned = _clean(raw)
        if cleaned:
            return cleaned[:200]
    return None


def _clean(s: str) -> str:
    s = _BADGE.sub("", s)
    s = _LINK.sub(lambda m: m.group(1) or m.group(2) or "", s)
    s = _HTML.sub(" ", s)
    s = re.sub(r"(\*\*|__|\*|`)", "", s)
    s = re.sub(
        r"&(nbsp|amp|lt|gt|quot|#39);",
        lambda m: {"nbsp": " ", "amp": "&", "lt": "<", "gt": ">", "quot": '"', "#39": "'"}[
            m.group(1)
        ],
        s,
    )
    return re.sub(r"\s+", " ", s).strip(" #*_`|\u00b7\u2022-")


def _is_nav(block: str) -> bool:
    """Link bars ("Docs · Website · Discord") and badge rows are not a description."""
    links = len(re.findall(r"\]\(|\]\[|<a\s", block, re.I))
    if links < 2:
        return False
    without = _LINK.sub("", _BADGE.sub("", block))
    without = re.sub(r"<a\b[^>]*>.*?</a>", "", without, flags=re.S | re.I)
    return len(re.sub(r"[\W_]+", "", _HTML.sub("", without))) < 20


def _first_paragraphs(body: str, title: str | None, limit: int = 700) -> str | None:
    paras: list[str] = []
    for block in re.split(r"\n\s*\n", body):
        b = block.strip()
        if not b or b.startswith(("|", "---", "===", "***")) or re.match(r"^[-*+]\s", b):
            continue
        if b.startswith("#") or re.match(r"^[^\n]+\n[=-]+\s*$", b):
            if paras:
                break
            continue
        if _is_nav(b):
            continue
        cleaned = _clean(b)
        if title and re.match(re.escape(title) + r"\s*(?:[:\-\u2013\u2014|]|$)", cleaned):
            cleaned = cleaned[len(title) :].strip(" :-|\u2013\u2014")  # "Acme: does X" -> "does X"
        if (
            len(cleaned) < 12
            or " " not in cleaned
            or cleaned.lower().startswith(("table of contents", "contents"))
        ):
            continue
        paras.append(cleaned)
        if sum(len(p) for p in paras) >= limit:
            break
    out = " ".join(paras)
    return (out[: limit - 1] + "…") if len(out) > limit else (out or None)


def _features(body: str, max_items: int = 10) -> list[str]:
    m = re.search(
        r"^#{2,3}\s+.*\b(features?|highlights|capabilities|what it does)\b.*$", body, re.M | re.I
    )
    if not m:
        return []
    section = body[m.end() :]
    nxt = re.search(r"^#{1,3}\s", section, re.M)
    section = section[: nxt.start()] if nxt else section
    items = [_clean(x) for x in re.findall(r"^[ \t]*[-*+]\s+(.+)$", section, re.M)]
    return [i for i in items if 3 < len(i) < 200][:max_items]


def first_sentence(text: str | None) -> str | None:
    if not text:
        return None
    m = re.match(r"(.+?[.!?])(\s|$)", text)
    return (m.group(1) if m else text)[:240]


# -- CODEOWNERS ---------------------------------------------------------------------------


def parse_codeowners(files: RepoFiles) -> list[str]:
    for path in (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"):
        text = files.read(path, 200_000)
        if text:
            owners: list[str] = []
            for line in text.splitlines():
                line = line.split("#", 1)[0].strip()
                for tok in line.split()[1:]:
                    if "@" in tok and tok not in owners:
                        owners.append(tok)
            return owners[:200]
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
_KIND_RANK = {"Component": 0, None: 1, "Resource": 2, "System": 3, "API": 4}


def parse_declared(
    files: RepoFiles, custom_properties: dict[str, Any], errors: list[str] | None = None
) -> Declared:
    declared = Declared(custom_properties=custom_properties)
    for path in _DESCRIPTORS:
        text = files.read(path, 500_000)
        if not text:
            continue
        try:
            docs = [d for d in load_yaml_all(text) if isinstance(d, dict)]
        except Exception as exc:
            if errors is not None:
                errors.append(f"{path}: {type(exc).__name__}: {str(exc)[:200]}")
            continue
        declared.source_files.append(path)
        # the Component describes the repo; APIs/Systems in the same file only fill gaps
        docs.sort(key=lambda d: _KIND_RANK.get(d.get("kind"), 5))
        for doc in docs:
            try:
                if "backstage.io" in str(doc.get("apiVersion", "")):
                    _backstage(doc, declared)
                elif isinstance(doc.get("info"), dict) and any(
                    str(k).startswith("x-cortex") for k in doc["info"]
                ):
                    _cortex(doc["info"], declared)
                else:
                    _generic(doc, declared)
            except Exception as exc:
                if errors is not None:
                    errors.append(f"{path}: {type(exc).__name__}: {str(exc)[:200]}")
    # custom properties commonly used for the same concepts
    aliases = {
        "owner": "owner",
        "team": "owner",
        "system": "system",
        "domain": "domain",
        "lifecycle": "lifecycle",
        "tier": "tier",
        "service_tier": "tier",
        "type": "type",
    }
    for prop, val in custom_properties.items():
        attr = aliases.get(str(prop).lower().replace("-", "_"))
        if attr and val and not getattr(declared, attr):
            value = ",".join(map(str, val)) if isinstance(val, list) else _s(val)
            setattr(declared, attr, value)
    return declared


def _backstage(doc: dict[str, Any], d: Declared) -> None:
    if doc.get("kind") not in _KIND_RANK:
        return  # Location, Group, User, Template...
    meta = _dict(doc.get("metadata"))
    spec = _dict(doc.get("spec"))
    d.name = d.name or _s(meta.get("name"))
    d.owner = d.owner or _s(spec.get("owner"))
    d.system = d.system or _s(spec.get("system"))
    d.domain = d.domain or _s(spec.get("domain"))
    d.lifecycle = d.lifecycle or _s(spec.get("lifecycle"))
    d.type = d.type or _s(spec.get("type"))
    d.tags += [t for t in _strs(meta.get("tags")) if t not in d.tags]
    d.links += _links(meta.get("links"))
    d.provides_apis += _strs(spec.get("providesApis"))
    d.consumes_apis += _strs(spec.get("consumesApis"))
    d.depends_on += _strs(spec.get("dependsOn"))


def _cortex(info: dict[str, Any], d: Declared) -> None:
    d.name = d.name or _s(info.get("x-cortex-tag")) or _s(info.get("title"))
    owners = info.get("x-cortex-owners")
    first = owners[0] if isinstance(owners, list) and owners else owners
    if isinstance(first, dict):
        d.owner = d.owner or _s(first.get("name")) or _s(first.get("email"))
    elif first is not None:
        d.owner = d.owner or _s(first)
    d.tier = d.tier or _s(info.get("x-cortex-tier"))
    d.lifecycle = d.lifecycle or _s(info.get("x-cortex-lifecycle"))
    d.tags += [g for g in _strs(info.get("x-cortex-groups")) if g not in d.tags]
    d.links += _links(info.get("x-cortex-link"), title_key="name")


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
    raw_tags = svc.get("tags") or svc.get("labels") or []
    for tag in raw_tags if isinstance(raw_tags, list) else [raw_tags]:
        val = (
            _s(tag) if not isinstance(tag, dict) else f"{_s(tag.get('key'))}:{_s(tag.get('value'))}"
        )
        if val and val not in d.tags:
            d.tags.append(val)
    d.links += _links(svc.get("links"), title_key="name")


def _links(raw: Any, title_key: str = "title") -> list[dict[str, str]]:
    out = []
    for link in raw if isinstance(raw, list) else []:
        if isinstance(link, dict) and _s(link.get("url")):
            title = _s(link.get(title_key)) or _s(link.get("title")) or ""
            out.append({"url": str(link["url"]), "title": title})
    return out


def _s(v: Any) -> str | None:
    """Scalars only: a mapping or list where a string belongs is ignored, not stringified."""
    if v is None or isinstance(v, dict | list | tuple | bool):
        return None
    s = str(v).strip()
    return s or None


def _strs(v: Any) -> list[str]:
    if isinstance(v, str):
        return [v.strip()] if v.strip() else []  # a lone string is one item, not characters
    return [s for x in v if (s := _s(x))] if isinstance(v, list) else []


def _dict(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}
