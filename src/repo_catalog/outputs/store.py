"""JSON outputs. One file per repo (small, diffable in git) plus aggregated files that the
frontend, SQLite builder and MCP server read."""

from __future__ import annotations

import json
import logging
import os
import re
import stat
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from .. import __version__
from ..models import AIAsset, CatalogMeta, Dependency, Repo

log = logging.getLogger(__name__)

REPOS_DIR = "repos"
CATALOG_FILE = "catalog.json"
ASSETS_FILE = "ai-assets.json"
SITE_DIR = "site"  # per-repo / per-asset detail files for the web UI


def _current_umask() -> int:
    mask = os.umask(0o022)  # the only way to read it; restored right away
    os.umask(mask)
    return mask


# read once at import (single-threaded): os.umask is process-wide and not thread-safe
_FILE_MODE = 0o666 & ~_current_umask()


def _slug(repo_id: str) -> str:
    return repo_id.replace("/", "__")


# one encoder for every call (json.dumps with options builds a new one each time)
_ENCODE = json.JSONEncoder(separators=(",", ":")).encode


def dumps(obj: object) -> str:
    """Compact JSON: without ``indent`` the json module uses its C encoder (much faster)."""
    return _ENCODE(obj)


def dumps_lines(obj: object, depth: int = 3, _indent: int = 0) -> str:
    """JSON with one member per line down to ``depth`` levels and compact JSON below, so the
    per-repo files keep readable git diffs (one line per dependency or asset field)
    without paying for the pure-Python pretty printer."""
    if depth <= 0 or not obj or not isinstance(obj, dict | list):
        return dumps(obj)
    pad = "\n" + " " * (_indent + 1)
    if isinstance(obj, dict):
        items = [f"{_ENCODE(k)}: {dumps_lines(v, depth - 1, _indent + 1)}" for k, v in obj.items()]
        return "{" + pad + ("," + pad).join(items) + "\n" + " " * _indent + "}"
    items = [dumps_lines(v, depth - 1, _indent + 1) for v in obj]
    return "[" + pad + ("," + pad).join(items) + "\n" + " " * _indent + "]"


def write_atomic(path: Path, text: str, *, skip_unchanged: bool = True) -> bool:
    """Write via a temp file and rename, so a killed run never leaves a half-written file.

    Files are readable like any other output (``0666 & ~umask``, not mkstemp's 0600). A
    file that already holds exactly ``text`` is left alone, so incremental runs only touch
    what changed. Returns True if the file was written."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = text.encode("utf-8")
    if skip_unchanged:
        try:
            st = path.stat()
            if st.st_size == len(data) and path.read_bytes() == data:
                if stat.S_IMODE(st.st_mode) != _FILE_MODE:
                    os.chmod(path, _FILE_MODE)  # older versions wrote 0600 files
                return False
        except OSError:
            pass
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.chmod(tmp, _FILE_MODE)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return True


class _Stored(BaseModel):
    """A per-repo file (``{"repo": ..., "assets": [...]}``), validated straight from JSON."""

    model_config = ConfigDict(extra="ignore")
    repo: Repo
    assets: list[AIAsset] = []


class _StoredDependencies(BaseModel):
    """Only the dependency list of a per-repo file (everything else is skipped)."""

    class _Deps(BaseModel):
        model_config = ConfigDict(extra="ignore")
        dependencies: list[Dependency] = []

    model_config = ConfigDict(extra="ignore")
    repo: _Deps


class StoredRecords(dict[str, tuple[Repo, list[AIAsset]]]):
    """Records from ``repos/`` by repo id, plus the files they came from and the files that
    failed to load (``rejected``: unreadable or not matching the current schema)."""

    def __init__(self) -> None:
        super().__init__()
        self.paths: dict[str, Path] = {}
        self.rejected: dict[str, str] = {}  # file name -> error
        # direct_only: (ecosystem, name, version) of the dropped transitive deps, packed
        # into one string per repo (a tenth of the memory of Dependency objects)
        self._transitive: dict[str, str] = {}

    def transitive_refs(self, repo_id: str) -> list[tuple[str, str, str | None]]:
        """(ecosystem, name, version) of the transitive dependencies ``load_previous``
        dropped from ``repo_id``'s record (what org-wide linking needs of them)."""
        packed = self._transitive.get(repo_id)
        if not packed:
            return []
        return [
            (eco, name, version or None)
            for eco, name, version in (line.split(_UNIT) for line in packed.split(_RECORD))
        ]


_UNIT, _RECORD = "\x1f", "\x1e"  # ASCII unit / record separators: never in package names
_SEPARATORS = {_UNIT, _RECORD}


def _pack(dep: Dependency) -> str | None:
    fields = (dep.ecosystem, dep.name, dep.version or "")
    return None if _SEPARATORS.intersection("".join(fields)) else _UNIT.join(fields)


def load_previous(out_dir: Path, *, direct_only: bool = False) -> StoredRecords:
    """Load every per-repo record. With ``direct_only`` the locked transitive dependencies
    (most of a large catalog's memory) are validated but not kept: ``full_dependencies``
    reads them back from the file one repo at a time when an output needs them, and
    ``StoredRecords.transitive_refs`` keeps their names."""
    prev = StoredRecords()
    folder = out_dir / REPOS_DIR
    if not folder.is_dir():
        return prev
    for path in sorted(folder.glob("*.json")):
        try:
            record = _Stored.model_validate_json(path.read_bytes())
        except Exception as exc:  # schema drift: just rescan that repo
            prev.rejected[path.name] = str(exc).splitlines()[0][:300]
            log.warning("ignoring unreadable %s (it will be rescanned): %s", path.name, exc)
            continue
        repo = record.repo
        if direct_only:
            refs = dict.fromkeys(
                packed
                for d in repo.dependencies
                if d.scope == "transitive" and (packed := _pack(d)) is not None
            )
            if refs:
                prev._transitive[repo.id] = _RECORD.join(refs)
            strip_transitive(repo)
        prev[repo.id] = (repo, record.assets)
        prev.paths[repo.id] = path
    return prev


def strip_transitive(repo: Repo) -> None:
    """Drop locked transitive dependencies from a record held in memory (see
    ``full_dependencies``); direct dependencies keep their order."""
    if any(d.scope == "transitive" for d in repo.dependencies):
        repo.dependencies = [d for d in repo.dependencies if d.scope != "transitive"]


def repo_path(out_dir: Path, repo_id: str) -> Path:
    return out_dir / REPOS_DIR / f"{_slug(repo_id)}.json"


def full_dependencies(path: Path, repo: Repo) -> list[Dependency]:
    """``repo``'s dependencies with the transitive ones stripped by ``load_previous``
    (``direct_only``) read back from its file, in the stored order. The in-memory direct
    dependencies are kept as they are (build-time changes such as OSV ids survive)."""
    direct = [d for d in repo.dependencies if d.scope != "transitive"]
    if len(direct) != len(repo.dependencies):
        return list(repo.dependencies)  # not stripped: already complete
    try:
        stored = _StoredDependencies.model_validate_json(path.read_bytes()).repo.dependencies
    except FileNotFoundError:
        return direct
    except Exception as exc:
        log.warning("could not re-read dependencies from %s: %s", path.name, exc)
        return direct
    if sum(d.scope != "transitive" for d in stored) != len(direct):
        log.warning("%s changed during the build; its direct dependencies may be stale", path)
        return direct + [d for d in stored if d.scope == "transitive"]
    it = iter(direct)
    return [d if d.scope == "transitive" else next(it) for d in stored]


def write_repo(
    out_dir: Path, repo: Repo, assets: list[AIAsset], *, merge_transitive: bool = False
) -> bool:
    """Write one per-repo record. ``merge_transitive``: ``repo`` was stripped of its
    transitive dependencies (``strip_transitive``); keep the ones already in its file.
    Returns False when the file already had exactly this content."""
    path = repo_path(out_dir, repo.id)
    data = repo.model_dump(mode="json")
    if merge_transitive:
        data["dependencies"] = _merge_stored(path, data["dependencies"])
    payload: dict[str, Any] = {
        "repo": data,
        "assets": [a.model_dump(mode="json") for a in assets],
    }
    return write_atomic(path, dumps_lines(payload) + "\n")


_DEPENDENCY_KEYS = list(Dependency.model_fields)


def _merge_stored(path: Path, direct: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """``direct`` (dumped dependencies of a stripped record) with the transitive ones in
    ``path``, in the stored order. Stored entries are reused as they are (they were
    validated when the record was loaded) unless their shape is not the current one."""
    try:
        stored = json.loads(path.read_bytes())["repo"]["dependencies"]
    except FileNotFoundError:
        return direct
    except Exception as exc:
        log.warning("could not re-read dependencies from %s: %s", path.name, exc)
        return direct
    if not isinstance(stored, list) or not all(isinstance(d, dict) for d in stored):
        return direct

    def current(d: dict[str, Any]) -> dict[str, Any]:
        if list(d) == _DEPENDENCY_KEYS:
            return d
        return Dependency.model_validate(d).model_dump(mode="json")

    if sum(d.get("scope") != "transitive" for d in stored) != len(direct):
        log.warning("%s changed since it was loaded; its direct dependencies may be stale", path)
        return [*direct, *(current(d) for d in stored if d.get("scope") == "transitive")]
    it = iter(direct)
    return [current(d) if d.get("scope") == "transitive" else next(it) for d in stored]


def prune(out_dir: Path, keep: set[str], owners: set[str]) -> list[str]:
    """Remove records of repos under ``owners`` that were not seen in this run (deleted,
    renamed or filtered out). Records of other owners and of local scans are left alone."""
    removed: list[str] = []
    folder = out_dir / REPOS_DIR
    if not owners or not folder.is_dir():
        return removed
    wanted = {_slug(k) for k in keep}
    for path in folder.glob("*.json"):
        owner = path.stem.split("__", 1)[0].lower()
        if owner in owners and path.stem not in wanted:
            path.unlink()
            removed.append(path.stem)
    return removed


def write_aggregates(
    out_dir: Path,
    repos: list[Repo],
    assets: list[AIAsset],
    source: str,
    llm: bool,
    failures: dict[str, str] | None = None,
    used_by_totals: dict[str, int] | None = None,
    duplicate_totals: dict[str, int] | None = None,
) -> CatalogMeta:
    """``used_by_totals`` / ``duplicate_totals``: true counts behind the capped lists."""
    meta = CatalogMeta(
        generated_at=datetime.now(UTC),
        scanner_version=__version__,
        source=source,
        repo_count=len(repos),
        asset_count=len(assets),
        llm_enriched=llm,
        failures=failures or {},
    )
    meta_json = meta.model_dump(mode="json")
    # compact: the C encoder (indent forces the pure-Python one, ~10x slower at scale)
    write_atomic(
        out_dir / CATALOG_FILE,
        dumps({"meta": meta_json, "repos": [_site_repo(r, used_by_totals) for r in repos]}),
    )
    write_atomic(
        out_dir / ASSETS_FILE,
        dumps({"meta": meta_json, "assets": [_site_asset(a, duplicate_totals) for a in assets]}),
    )
    return meta


_ALL = True  # pydantic include-spec shorthand
# catalog.json entry: what the web UI needs to list, search, facet, chart and export repos.
# Mirrored by RepoItem in site/src/types.ts.
_REPO_LIST_FIELDS: dict[str, Any] = {
    **dict.fromkeys(
        (
            *("id", "name", "owner", "url", "description", "homepage", "topics", "visibility"),
            *("archived", "fork", "default_branch", "head_sha", "license", "stars", "pushed_at"),
            *("lifecycle", "capabilities", "summary", "dependency_summary", "ai", "flags"),
            *("reusables", "depends_on", "scanned_at"),
        ),
        _ALL,
    ),
    "declared": {"owner", "system"},
    "stack": {
        **dict.fromkeys(
            (
                *("primary_language", "frameworks", "libraries", "package_managers"),
                *("build_tools", "testing", "linting", "databases", "messaging", "cloud"),
                *("infrastructure", "ci_cd", "observability", "auth", "ai"),
            ),
            _ALL,
        ),
        "languages": {"__all__": {"name", "percent"}},
    },
    "structure": {"repo_type": _ALL, "is_monorepo": _ALL, "packages": {"__all__": {"name"}}},
    "practices": {"score": _ALL, "grade": _ALL, "checks": {"__all__": {"id", "label", "passed"}}},
    "ownership": {"codeowners", "last_commit"},
}
# ai-assets.json entry: no content, frontmatter, bundled files or duplicate ids.
# Mirrored by AssetItem in site/src/types.ts.
_ASSET_LIST_FIELDS = {
    *("id", "kind", "ecosystem", "name", "title", "description", "repo", "path", "url"),
    *("scope", "confidence", "tools", "models", "mcp_servers", "tags", "excerpt", "headings"),
    *("quality_score", "last_modified", "summary", "use_cases", "category", "flags"),
}


def _site_repo(r: Repo, used_by_totals: dict[str, int] | None = None) -> dict[str, object]:
    """One catalog.json entry, kept small so the web UI loads fast at thousands of repos.
    Dependencies become names (direct only); the full record is in site/repos/<slug>.json,
    the per-repo files, SQLite and the SBOMs."""
    data = r.model_dump(mode="json", include=_REPO_LIST_FIELDS)
    direct = [d for d in r.dependencies if d.scope != "transitive"]
    data["dependency_names"] = sorted({d.name for d in direct})
    data["vulnerable_dependencies"] = sorted({d.name for d in direct if d.vulns})
    data["used_by_count"] = max(len(r.used_by), (used_by_totals or {}).get(r.id, 0))
    return data


def _site_asset(a: AIAsset, duplicate_totals: dict[str, int] | None = None) -> dict[str, object]:
    """One ai-assets.json entry; the full asset is in site/assets/<id>.json."""
    data = a.model_dump(mode="json", include=_ASSET_LIST_FIELDS)
    data["duplicate_count"] = max(len(a.duplicates), (duplicate_totals or {}).get(a.id, 0))
    return data


def _detail_repo(r: Repo) -> dict[str, Any]:
    """The full repo record the UI drawer loads (locked transitive deps left out: they are
    counted in dependency_summary and listed in the per-repo files, SQLite and SBOMs)."""
    data = r.model_dump(mode="json", exclude={"dependencies"})
    data["dependencies"] = [
        d.model_dump(mode="json") for d in r.dependencies if d.scope != "transitive"
    ]
    return data


def _file_name(key: str) -> str:
    """Detail file name for a repo slug or asset id (ids are hashes; be safe anyway)."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", key).lstrip(".") or "_"


def _version_drift(repos: list[Repo], limit: int = 15) -> list[dict[str, Any]]:
    """Direct dependencies used by active repos at different major versions."""
    by_dep: dict[tuple[str, str], dict[str, list[str]]] = {}
    for r in repos:
        if r.archived:
            continue
        for d in r.dependencies:
            version = d.resolved or d.version
            if d.scope == "transitive" or not version or d.ecosystem == "github-actions":
                continue
            m = re.search(r"([0-9]+)(?:\.([0-9]+))?", re.sub(r"^[^0-9]*", "", version))
            if not m:
                continue
            major, minor = m.group(1), m.group(2)
            major = f"0.{minor}" if major == "0" and minor is not None else major
            ids = by_dep.setdefault((d.ecosystem, d.name), {}).setdefault(major, [])
            if not ids or ids[-1] != r.id:
                ids.append(r.id)
    rows = []
    for (eco, name), majors in by_dep.items():
        n = len({i for ids in majors.values() for i in ids})
        if len(majors) > 1 and n > 1:
            rows.append((len(majors), n, eco, name, majors))
    rows.sort(key=lambda x: (-x[0], -x[1]))
    return [
        {
            "ecosystem": eco,
            "name": name,
            "repos": n,
            "majors": [
                {"major": k, "count": len(ids), "sample": ids[:20]} for k, ids in majors.items()
            ],
        }
        for _, n, eco, name, majors in rows[:limit]
    ]


def write_site_details(out_dir: Path, repos: list[Repo], assets: list[AIAsset]) -> None:
    """Per-item files the web UI loads on demand (drawer, Insights), next to the slim
    catalog.json / ai-assets.json: site/repos/<slug>.json (``{repo, assets: [refs]}``),
    site/assets/<id>.json and site/insights.json. Unchanged files are not rewritten and
    files of repos and assets no longer in the catalog are removed."""
    site = out_dir / SITE_DIR
    by_repo: dict[str, list[dict[str, str]]] = {}
    for a in assets:
        by_repo.setdefault(a.repo, []).append(
            {"id": a.id, "kind": a.kind, "name": a.name, "path": a.path}
        )
    written: dict[str, set[str]] = {"repos": set(), "assets": set()}
    for r in repos:
        name = f"{_file_name(_slug(r.id))}.json"
        write_atomic(
            site / "repos" / name, dumps({"repo": _detail_repo(r), "assets": by_repo.get(r.id, [])})
        )
        written["repos"].add(name)
    for a in assets:
        name = f"{_file_name(a.id)}.json"
        write_atomic(site / "assets" / name, dumps(a.model_dump(mode="json")))
        written["assets"].add(name)
    for sub, keep in written.items():
        for path in (site / sub).glob("*.json"):
            if path.name not in keep:
                path.unlink()
    write_atomic(site / "insights.json", dumps({"version_drift": _version_drift(repos)}))


def load_aggregates(out_dir: Path) -> tuple[list[Repo], list[AIAsset]]:
    """The built catalog as models (direct dependencies only, build-time fields included),
    in catalog order. catalog.json / ai-assets.json hold slim list entries, so the full
    records are read from the site/ detail files ``write_site_details`` wrote."""
    site = out_dir / SITE_DIR
    repos: list[Repo] = []
    for r in json.loads((out_dir / CATALOG_FILE).read_text())["repos"]:
        path = site / "repos" / f"{_file_name(_slug(r['id']))}.json"
        repos.append(Repo.model_validate(json.loads(path.read_text())["repo"]))
    assets = [
        AIAsset.model_validate_json((site / "assets" / f"{_file_name(a['id'])}.json").read_bytes())
        for a in json.loads((out_dir / ASSETS_FILE).read_text())["assets"]
    ]
    return repos, assets


def write_schemas(schema_dir: Path) -> None:
    schema_dir.mkdir(parents=True, exist_ok=True)
    for name, model in (("repo", Repo), ("ai-asset", AIAsset), ("catalog-meta", CatalogMeta)):
        (schema_dir / f"{name}.schema.json").write_text(
            json.dumps(model.model_json_schema(), indent=2) + "\n"
        )
