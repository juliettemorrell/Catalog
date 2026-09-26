"""Org-wide analysis, run every time the catalog is built from stored scan results.

* Links repositories that consume each other's packages, actions, reusable workflows,
  Terraform modules, container images and submodules (depends_on / used_by).
* Flags that depend on the calendar (end-of-life runtimes, retired models) or on other
  repos (depending on an archived repo). Computing them at build time keeps them
  current even for repos that were not re-scanned because nothing changed.
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import UTC, date, datetime, timedelta

from ..models import AIAsset, Flag, Repo, RepoLink, Severity
from .flags import release_cycle
from .reference import MODEL_DEPRECATIONS, RUNTIME_EOL

DERIVED_FLAGS = {"eol-runtime", "deprecated-model", "depends-on-archived"}
MAX_LINKS = 200
_EOL_KEY = {"node": "nodejs"}
_RUNTIME_LABEL = {
    "node": "Node.js",
    "python": "Python",
    "java": "Java",
    "dotnet": ".NET",
    "go": "Go",
    "ruby": "Ruby",
    "php": "PHP",
}
_GITHUB_REF = re.compile(
    r"github(?:\.com[/:]|:)([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?=$|[#@/?\s])", re.I
)


def link_org(repos: list[Repo], assets: list[AIAsset], today: date | None = None) -> None:
    today = today or datetime.now(UTC).date()
    for repo in repos:
        repo.flags = [f for f in repo.flags if f.id not in DERIVED_FLAGS]
        repo.depends_on, repo.used_by = [], []
    for asset in assets:
        asset.flags = [f for f in asset.flags if f.id not in DERIVED_FLAGS]
    by_repo: dict[str, list[AIAsset]] = defaultdict(list)
    for asset in assets:
        by_repo[asset.repo].append(asset)
    for repo in repos:
        if repo.archived:
            continue
        repo.flags += eol_flags(repo, today)
        repo.flags += model_flags(repo, by_repo.get(repo.id, []))
    _link(repos)


# ------------------------------------------------------------------------ end of life


def eol_flags(repo: Repo, today: date) -> list[Flag]:
    flags: list[Flag] = []
    seen: set[tuple[str, str]] = set()
    for rv in repo.stack.runtime_versions:
        cycle = release_cycle(rv.runtime, rv.version)
        table = RUNTIME_EOL.get(_EOL_KEY.get(rv.runtime, rv.runtime), {})
        if not cycle or cycle not in table or (rv.runtime, cycle) in seen:
            continue
        seen.add((rv.runtime, cycle))
        eol = table[cycle]
        if not eol:
            continue
        end = date.fromisoformat(eol)
        label = f"{_RUNTIME_LABEL.get(rv.runtime, rv.runtime)} {cycle}"
        sev: Severity
        if end <= today:
            sev = "high" if today - end > timedelta(days=365) else "medium"
            msg = f"{label} reached end of life on {eol}"
        elif end - today <= timedelta(days=180):
            sev, msg = "low", f"{label} reaches end of life on {eol}"
        else:
            continue
        flags.append(
            Flag(id="eol-runtime", category="maintenance", severity=sev, message=msg, path=rv.path)
        )
    return flags


# ---------------------------------------------------------------------- retired models


def _model_index() -> dict[str, tuple[str, str, str | None, str | None]]:
    index: dict[str, tuple[str, str, str | None, str | None]] = {}
    for model_id, (status, when, replacement) in MODEL_DEPRECATIONS.items():
        entry = (model_id, status, when, replacement)
        index[model_id] = entry
        if m := re.fullmatch(r"(.+)-\d{8}", model_id):
            family = m.group(1)
            for alias in (family, f"{family}-latest", f"{family}-0"):
                index.setdefault(alias, entry)
    return index


_MODELS = _model_index()


def lookup_model(raw: str) -> tuple[str, str, str | None, str | None] | None:
    """(canonical id, status, date, replacement) for a retired/deprecated model reference.

    Accepts provider spellings: Bedrock ``us.anthropic.claude-3-haiku-20240307-v1:0``,
    Vertex ``claude-3-opus@20240229``, and router prefixes such as ``anthropic/``."""
    m = raw.strip().lower()
    m = re.sub(r"^(?:[a-z-]+/)+", "", m)  # openrouter/litellm prefixes
    m = re.sub(r"^(?:(?:us|eu|apac|global|jp|au)\.)?anthropic\.", "", m)
    m = re.sub(r"-v\d+(?::\d+)?$", "", m)
    m = m.replace("@", "-")
    return _MODELS.get(m)


def model_flags(repo: Repo, assets: list[AIAsset]) -> list[Flag]:
    found: dict[str, tuple[str, str, str | None, str | None]] = {}
    for asset in assets:
        for model in asset.models:
            hit = lookup_model(model)
            if hit:
                found.setdefault(hit[0], hit)
                asset.flags.append(_model_flag(hit, asset.path, "example" in asset.tags))
    for model in repo.ai.models:
        hit = lookup_model(model)
        if hit:
            found.setdefault(hit[0], hit)
    if not found:
        return []
    retired = [f for f in found.values() if f[1] == "retired"]
    names = ", ".join(sorted(found)[:5]) + ("..." if len(found) > 5 else "")
    return [
        Flag(
            id="deprecated-model",
            category="ai-governance",
            severity="high" if retired else "medium",
            message=f"References {'retired' if retired else 'deprecated'} model(s): {names}",
        )
    ]


def _model_flag(
    hit: tuple[str, str, str | None, str | None], path: str, example: bool = False
) -> Flag:
    model_id, status, when, replacement = hit
    msg = f"{model_id} is {status}" + (f" ({when})" if when else "")
    if replacement:
        msg += f"; move to {replacement}"
    return Flag(
        id="deprecated-model",
        category="ai-governance",
        # sample code that names an old model matters less than production code
        severity="low" if example else "high" if status == "retired" else "medium",
        message=msg,
        path=path,
    )


# ------------------------------------------------------------------------------ links


def _norm(ecosystem: str, name: str) -> str:
    name = name.lower()
    return re.sub(r"[-_.]+", "-", name) if ecosystem == "pypi" else name


def _link(repos: list[Repo]) -> None:
    by_id = {r.id.lower(): r for r in repos}
    published: dict[tuple[str, str], str] = {}
    for repo in repos:
        if repo.fork:
            continue  # a fork of a public package would claim every consumer of it
        for pkg in repo.structure.packages:
            if pkg.private is not True:
                published.setdefault((pkg.ecosystem, _norm(pkg.ecosystem, pkg.name)), repo.id)
    go_modules = sorted(
        ((name, rid) for (eco, name), rid in published.items() if eco == "go"),
        key=lambda kv: -len(kv[0]),
    )

    edges: dict[tuple[str, str, str], None] = {}  # ordered set; every route is kept

    def link(src: Repo, target_id: str | None, via: str) -> None:
        if target_id and target_id.lower() != src.id.lower():
            edges.setdefault((src.id, by_id[target_id.lower()].id, via), None)

    for repo in repos:
        for dep in repo.dependencies:
            key = (dep.ecosystem, _norm(dep.ecosystem, dep.name))
            target = published.get(key)
            if not target and dep.ecosystem == "go":
                target = next(
                    (rid for mod, rid in go_modules if key[1].startswith(mod + "/")), None
                )
            if target:
                link(repo, target, f"{dep.ecosystem} {dep.name}")
                continue
            for text in (dep.name, dep.version or ""):
                if m := _GITHUB_REF.search(text):
                    target_id = f"{m.group(1)}/{m.group(2)}".lower()
                    if target_id in by_id:
                        link(repo, target_id, f"{dep.ecosystem} {dep.name}")
                        break
        for ref in repo.references:
            if ref.target in by_id:
                link(repo, ref.target, f"{ref.kind} {ref.target}")

    flagged: set[tuple[str, str]] = set()
    for src_id, dst_id, via in edges:
        src, dst = by_id[src_id.lower()], by_id[dst_id.lower()]
        if len(src.depends_on) < MAX_LINKS:
            src.depends_on.append(RepoLink(repo=dst.id, via=via))
        if len(dst.used_by) < MAX_LINKS:
            dst.used_by.append(RepoLink(repo=src.id, via=via))
        if dst.archived and not src.archived and (src.id, dst.id) not in flagged:
            flagged.add((src.id, dst.id))
            src.flags.append(
                Flag(
                    id="depends-on-archived",
                    category="maintenance",
                    severity="medium",
                    message=f"Depends on archived repo {dst.id} ({via})",
                )
            )
    for repo in repos:
        repo.depends_on.sort(key=lambda link: link.repo.lower())
        repo.used_by.sort(key=lambda link: link.repo.lower())
