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
from collections.abc import Callable, Iterable
from datetime import UTC, date, datetime, timedelta

from ..models import AIAsset, Flag, Repo, RepoLink, Severity
from .ai_risk import launched_package
from .flags import release_cycle
from .manifests import NON_PRODUCT_DIR
from .reference import MODEL_DEPRECATIONS, RUNTIME_EOL

DERIVED_FLAGS = {"eol-runtime", "deprecated-model", "depends-on-archived", "vulnerable-dependency"}
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


# repo id -> (ecosystem, name, version) of transitive dependencies held outside the record
TransitiveRefs = Callable[[str], Iterable[tuple[str, str, str | None]]]


def link_org(
    repos: list[Repo],
    assets: list[AIAsset],
    today: date | None = None,
    transitive: TransitiveRefs | None = None,
) -> dict[str, list[RepoLink]]:
    """Derived flags plus ``depends_on`` / ``used_by`` (each capped at ``MAX_LINKS``
    entries). Returns every repo's complete ``depends_on`` list (for SQLite ``repo_links``).

    ``transitive``: the transitive dependencies of records loaded without them
    (``store.load_previous(direct_only=True)``); they link repos too."""
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
    return _link(repos, by_repo, transitive)


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
    # oldest snapshot first, so an alias ("-latest") ends up pointing at the newest one
    for model_id, (status, when, replacement) in sorted(
        MODEL_DEPRECATIONS.items(), key=lambda kv: re.findall(r"\d{8}", kv[0]) or [""]
    ):
        entry = (model_id, status, when, replacement)
        index[model_id] = entry
        if m := re.fullmatch(r"(.+)-\d{8}", model_id):
            family = m.group(1)
            for alias in (family, f"{family}-latest", f"{family}-0"):
                index[alias] = entry
    # Bedrock's original model ids
    for legacy, canonical in (
        ("claude-v2", "claude-2.0"),
        ("claude-v2:1", "claude-2.1"),
        ("claude-v1", "claude-1.3"),
        ("claude-instant-v1", "claude-instant-1.2"),
    ):
        if canonical in index:
            index[legacy] = index[canonical]
    return index


_MODELS = _model_index()


def lookup_model(raw: str) -> tuple[str, str, str | None, str | None] | None:
    """(canonical id, status, date, replacement) for a retired/deprecated model reference.

    Accepts provider spellings: Bedrock ``us.anthropic.claude-3-haiku-20240307-v1:0``,
    Vertex ``claude-3-opus@20240229``, and router prefixes such as ``anthropic/``."""
    m = raw.strip().lower()
    m = re.sub(r"^(?:[a-z0-9_.-]+/)+", "", m)  # openrouter / litellm / vertex_ai prefixes
    m = re.sub(r"^(?:(?:us|eu|apac|global|jp|au)\.)?anthropic\.", "", m)
    if m in _MODELS:
        return _MODELS[m]  # e.g. claude-v2:1
    m = re.sub(r"(\d{8})-v\d+(?::\d+)?$", r"\1", m)  # Bedrock version suffix after a date
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


def _entity_name(ref: str) -> str:
    """``component:default/billing`` -> ``billing`` (Backstage entity refs)."""
    return ref.rsplit("/", 1)[-1].split(":")[-1].lower()


def _mcp_targets(
    name: str,
    cfg: object,
    publishers: dict[tuple[str, str], list[Repo]],
    providers: dict[str, set[str]],
    consumer: Repo,
) -> list[Repo | str]:
    """Org repos behind an MCP server a repo configures. The launched package decides;
    the server name is only a fallback for configs that give nothing else (a remote URL or
    a third-party package means the server is not one of ours)."""
    cfg = cfg if isinstance(cfg, dict) else {}
    launched = launched_package(str(cfg.get("command") or ""))
    if launched and launched[0] in ("npm", "pypi"):
        ecosystem, spec = launched
        if ecosystem == "npm":
            base = "@" + spec[1:].split("@")[0] if spec.startswith("@") else spec.split("@")[0]
        else:
            base = re.split(r"[=<>!~\[@ ]", spec, maxsplit=1)[0]
        owner = _owner(publishers.get((ecosystem, _norm(ecosystem, base)), []), consumer)
        return [owner] if owner else []
    if launched or cfg.get("url"):
        return []
    owners = providers.get(name.lower(), set())
    if len(owners) != 1:
        return []  # ambiguous names link nothing
    return [next(iter(owners))]


def _norm(ecosystem: str, name: str) -> str:
    name = name.lower()
    return re.sub(r"[-_.]+", "-", name) if ecosystem == "pypi" else name


_SCOPE_RANK = {"runtime": 0, "peer": 0, "optional": 1, "dev": 2, "build": 3, "transitive": 4}
MAX_ROUTES_PER_PAIR = 5  # repos are never dropped; only extra routes to the same repo are


def _publishers(repos: list[Repo]) -> dict[tuple[str, str], list[Repo]]:
    """Who publishes each package. Forks (they would claim every consumer of the upstream
    package) and example/test packages (templates copy them) never count."""
    out: dict[tuple[str, str], list[Repo]] = {}
    for repo in repos:
        if repo.fork:
            continue
        for pkg in repo.structure.packages:
            if pkg.private is True or NON_PRODUCT_DIR.search(f"{pkg.path}/"):
                continue
            key = (pkg.ecosystem, _norm(pkg.ecosystem, pkg.name))
            if repo not in out.setdefault(key, []):
                out[key].append(repo)
    return out


def _owner(candidates: list[Repo], consumer: Repo) -> Repo | None:
    """The one repo a package comes from, or None when it is the consumer's own package
    or ownership is ambiguous (linking the wrong repo is worse than no link)."""
    if consumer in candidates:
        return None  # a workspace member of the consumer itself
    live = [r for r in candidates if not r.archived] or candidates
    return live[0] if len(live) == 1 else None


def _link(
    repos: list[Repo],
    assets_by_repo: dict[str, list[AIAsset]] | None = None,
    transitive: TransitiveRefs | None = None,
) -> dict[str, list[RepoLink]]:
    assets_by_repo = assets_by_repo or {}
    by_id = {r.id.lower(): r for r in repos}
    publishers = _publishers(repos)
    go_modules = {name: key for key in publishers if key[0] == "go" for name in [key[1]]}

    # (src, dst) -> {base via: strongest scope rank}
    routes: dict[tuple[str, str], dict[str, int]] = {}

    def link(src: Repo, target: Repo | str | None, via: str, scope: str = "runtime") -> None:
        dst = by_id.get(target.lower()) if isinstance(target, str) else target
        if dst is None or dst.id.lower() == src.id.lower():
            return
        pair = routes.setdefault((src.id, dst.id), {})
        rank = _SCOPE_RANK.get(scope, 0)
        pair[via] = min(pair.get(via, rank), rank)

    # names teams declared (Backstage metadata.name) and MCP servers repos implement
    declared_names: dict[str, set[str]] = {}
    mcp_providers: dict[str, set[str]] = {}
    api_providers: dict[str, set[str]] = {}
    for repo in repos:
        for name in {repo.declared.name, repo.name}:
            if name:
                declared_names.setdefault(name.lower(), set()).add(repo.id)
        for asset in assets_by_repo.get(repo.id, []):
            # example servers (SDK samples, tutorials) are not something others deploy
            if asset.kind == "mcp-server" and "example" not in asset.tags:
                mcp_providers.setdefault(asset.name.lower(), set()).add(repo.id)
        for api in repo.declared.provides_apis:
            api_providers.setdefault(_entity_name(api), set()).add(repo.id)

    for repo in repos:
        deps = [(d.ecosystem, d.name, d.version, d.scope) for d in repo.dependencies]
        if transitive is not None:
            deps += [
                (eco, name, version, "transitive") for eco, name, version in transitive(repo.id)
            ]
        for ecosystem, name, version, scope in deps:
            key = (ecosystem, _norm(ecosystem, name))
            candidates = publishers.get(key)
            if candidates is None and ecosystem == "go":
                # a package path inside a module: walk its prefixes (github.com/a/b/c -> a/b)
                parts = key[1].split("/")
                for i in range(len(parts) - 1, 0, -1):
                    module = go_modules.get("/".join(parts[:i]))
                    if module:
                        candidates = publishers[module]
                        break
            if candidates:
                link(repo, _owner(candidates, repo), f"{ecosystem} {name}", scope)
                continue
            if ecosystem == "docker" and name.startswith("ghcr.io/"):
                parts = name.split("/")
                if len(parts) >= 3:
                    link(repo, f"{parts[1]}/{parts[2]}", f"image {name}", scope)
                continue
            if ecosystem in ("terraform", "github-actions"):
                continue  # resolved from `references`, which keep the exact file
            for text in (name, version or ""):
                if m := _GITHUB_REF.search(text):
                    target_id = f"{m.group(1)}/{m.group(2)}".lower()
                    if target_id in by_id:
                        link(repo, target_id, f"{ecosystem} {name}", scope)
                        break
        for ref in repo.references:
            if ref.target in by_id:
                link(repo, ref.target, f"{ref.kind} {ref.target}")  # kind says how
        for entity in repo.declared.depends_on:
            owners = declared_names.get(_entity_name(entity), set())
            if len(owners) == 1:
                link(repo, next(iter(owners)), f"declared dependsOn {entity}")
        for api in repo.declared.consumes_apis:
            for target in sorted(api_providers.get(_entity_name(api), ())):
                link(repo, target, f"consumes API {api}")
        for asset in assets_by_repo.get(repo.id, []):
            if asset.kind not in ("mcp-config", "settings"):
                continue
            servers = asset.frontmatter.get("servers")
            for name, cfg in (servers if isinstance(servers, dict) else {}).items():
                for server in _mcp_targets(str(name), cfg, publishers, mcp_providers, repo):
                    link(repo, server, f"MCP server {name}")

    labels = {1: " (optional)", 2: " (dev)", 3: " (build)", 4: " (transitive)"}
    flagged: set[tuple[str, str]] = set()
    # (relevance, link) per repo: the MAX_LINKS most relevant links are kept on the record
    out_links: dict[str, list[tuple[tuple[int, bool, str, str], RepoLink]]] = {}
    in_links: dict[str, list[tuple[tuple[int, bool, str, str], RepoLink]]] = {}
    for (src_id, dst_id), vias in sorted(routes.items()):
        src, dst = by_id[src_id.lower()], by_id[dst_id.lower()]
        ordered = sorted(vias.items(), key=lambda kv: (kv[1], kv[0]))[:MAX_ROUTES_PER_PAIR]
        for via, rank in ordered:
            label = via + labels.get(rank, "")
            # runtime before dev/build/transitive, live repos before archived ones
            out_links.setdefault(src.id, []).append(
                ((rank, dst.archived, dst.id.lower(), label), RepoLink(repo=dst.id, via=label))
            )
            in_links.setdefault(dst.id, []).append(
                ((rank, src.archived, src.id.lower(), label), RepoLink(repo=src.id, via=label))
            )
        if dst.archived and not src.archived and (src.id, dst.id) not in flagged:
            flagged.add((src.id, dst.id))
            src.flags.append(
                Flag(
                    id="depends-on-archived",
                    category="maintenance",
                    severity="medium",
                    message=f"Depends on archived repo {dst.id} ({ordered[0][0]})",
                )
            )
    complete: dict[str, list[RepoLink]] = {}
    for repo in repos:
        outgoing = out_links.get(repo.id, [])
        complete[repo.id] = sorted((ln for _, ln in outgoing), key=lambda ln: ln.repo.lower())
        repo.depends_on = _most_relevant(outgoing)
        repo.used_by = _most_relevant(in_links.get(repo.id, []))
    return complete


def _most_relevant(links: list[tuple[tuple[int, bool, str, str], RepoLink]]) -> list[RepoLink]:
    """At most MAX_LINKS links (strongest first when capped), listed by repo name."""
    if len(links) > MAX_LINKS:
        links = sorted(links, key=lambda x: x[0])[:MAX_LINKS]
    return sorted((ln for _, ln in links), key=lambda ln: ln.repo.lower())
