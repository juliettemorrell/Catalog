"""Build a queryable SQLite database (with FTS5 full-text search) from the catalog.

Designed for SDLC agents and ad-hoc SQL: normalized tables for "which repos use X",
FTS tables for fuzzy search, and the full JSON record on every row for anything else.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterable, Mapping
from pathlib import Path
from types import TracebackType

from ..models import AIAsset, Repo, RepoLink

SCHEMA = """
PRAGMA journal_mode = OFF;
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE repos (
  id TEXT PRIMARY KEY, name TEXT, owner TEXT, url TEXT, description TEXT, one_liner TEXT,
  purpose TEXT, reuse_notes TEXT, repo_type TEXT, lifecycle TEXT, primary_language TEXT,
  practices_score INTEGER, practices_grade TEXT, archived INTEGER, fork INTEGER,
  visibility TEXT, license TEXT, stars INTEGER, pushed_at TEXT, last_commit TEXT,
  owner_team TEXT, system TEXT, has_ai INTEGER, ai_asset_count INTEGER,
  file_count INTEGER, total_lines INTEGER, json TEXT NOT NULL
);
CREATE TABLE repo_tech (repo_id TEXT, category TEXT, name TEXT);
CREATE TABLE repo_capabilities (repo_id TEXT, capability TEXT);
CREATE TABLE repo_topics (repo_id TEXT, topic TEXT);
CREATE TABLE repo_languages (repo_id TEXT, language TEXT, lines INTEGER, percent REAL);
CREATE TABLE dependencies (repo_id TEXT, name TEXT, version TEXT, ecosystem TEXT,
  scope TEXT, manifest TEXT, resolved TEXT, purl TEXT, vulns TEXT, norm_name TEXT);
CREATE TABLE packages (repo_id TEXT, name TEXT, path TEXT, ecosystem TEXT, version TEXT,
  description TEXT);
CREATE TABLE practice_checks (repo_id TEXT, check_id TEXT, category TEXT, label TEXT,
  passed INTEGER, weight INTEGER, evidence TEXT);
CREATE TABLE ai_assets (
  id TEXT PRIMARY KEY, repo_id TEXT, kind TEXT, ecosystem TEXT, name TEXT, title TEXT,
  description TEXT, summary TEXT, category TEXT, path TEXT, url TEXT, scope TEXT,
  confidence TEXT, quality_score INTEGER, word_count INTEGER, last_modified TEXT,
  last_author TEXT, duplicate_count INTEGER, content TEXT, json TEXT NOT NULL,
  use_cases TEXT, tags TEXT
);
CREATE TABLE asset_tools (asset_id TEXT, tool TEXT);
CREATE TABLE asset_models (asset_id TEXT, model TEXT);
CREATE TABLE asset_tags (asset_id TEXT, tag TEXT);
CREATE TABLE flags (repo_id TEXT, asset_id TEXT, flag_id TEXT, category TEXT,
  severity TEXT, message TEXT, path TEXT, line INTEGER);
CREATE TABLE reusables (repo_id TEXT, kind TEXT, name TEXT, path TEXT, description TEXT,
  details TEXT);
CREATE TABLE repo_links (repo_id TEXT, depends_on TEXT, via TEXT);
CREATE TABLE runtime_versions (repo_id TEXT, runtime TEXT, version TEXT, path TEXT);
CREATE VIRTUAL TABLE repos_fts USING fts5(
  id UNINDEXED, name, description, summary, readme, tech, capabilities, topics,
  tokenize = 'unicode61 remove_diacritics 2');
-- external content: the text is read from ai_assets (no second copy of every asset body)
CREATE VIRTUAL TABLE assets_fts USING fts5(
  id UNINDEXED, name, description, summary, use_cases, content, tags,
  content = 'ai_assets', tokenize = 'unicode61 remove_diacritics 2');
"""

# created after the rows are in (bulk loading into indexed tables is much slower)
INDEXES = """
CREATE INDEX idx_tech ON repo_tech(name COLLATE NOCASE);
CREATE INDEX idx_tech_repo ON repo_tech(repo_id);
CREATE INDEX idx_cap ON repo_capabilities(capability);
CREATE INDEX idx_dep ON dependencies(name COLLATE NOCASE);
CREATE INDEX idx_dep_norm ON dependencies(norm_name);
CREATE INDEX idx_dep_repo ON dependencies(repo_id);
CREATE INDEX idx_dep_purl ON dependencies(purl);
CREATE INDEX idx_asset_kind ON ai_assets(kind, ecosystem);
CREATE INDEX idx_asset_repo ON ai_assets(repo_id);
CREATE INDEX idx_flags ON flags(flag_id, severity);
CREATE INDEX idx_reusable ON reusables(kind);
CREATE INDEX idx_links_src ON repo_links(repo_id);
CREATE INDEX idx_links_dst ON repo_links(depends_on);
CREATE VIEW flag_summary AS
  SELECT flag_id, category, severity, COUNT(*) AS findings,
         COUNT(DISTINCT repo_id) AS repo_count
  FROM flags GROUP BY flag_id, category, severity ORDER BY
  CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, findings DESC;
CREATE VIEW vulnerable_dependencies AS
  SELECT d.repo_id, d.ecosystem, d.name, COALESCE(d.resolved, d.version) AS version, d.scope,
         d.manifest, d.vulns FROM dependencies d WHERE d.vulns IS NOT NULL
  ORDER BY d.repo_id, d.name;
CREATE VIEW tech_usage AS
  SELECT category, name, COUNT(DISTINCT repo_id) AS repo_count
  FROM repo_tech GROUP BY category, name ORDER BY repo_count DESC;
"""

# Aggregates over every (transitive) dependency take seconds on a large org, too slow for
# an interactive query: they are computed once here, as tables. Same names and columns as
# the views they replace, plus norm_name (indexed) to look a package up.
AGGREGATES = """
CREATE TABLE dependency_versions AS
  SELECT ecosystem, name, COUNT(DISTINCT repo_id) AS repo_count,
         COUNT(DISTINCT COALESCE(resolved, version)) AS version_count,
         GROUP_CONCAT(DISTINCT COALESCE(resolved, version)) AS versions,
         MIN(norm_name) AS norm_name
  FROM dependencies WHERE COALESCE(resolved, version) IS NOT NULL AND scope != 'transitive'
  GROUP BY ecosystem, name HAVING COUNT(DISTINCT repo_id) > 1
  ORDER BY version_count DESC, repo_count DESC;
CREATE TABLE dependency_usage AS
  SELECT ecosystem, name, COUNT(DISTINCT repo_id) AS repo_count,
         GROUP_CONCAT(DISTINCT version) AS versions, MIN(norm_name) AS norm_name
  FROM dependencies GROUP BY ecosystem, name ORDER BY repo_count DESC;
CREATE INDEX idx_dep_usage ON dependency_usage(norm_name);
CREATE INDEX idx_dep_versions ON dependency_versions(norm_name);
"""

_TECH_FIELDS = (
    "frameworks",
    "libraries",
    "testing",
    "linting",
    "databases",
    "messaging",
    "cloud",
    "infrastructure",
    "ci_cd",
    "observability",
    "auth",
    "ai",
    "build_tools",
    "package_managers",
)


def norm_name(ecosystem: str, name: str) -> str:
    """Lookup key for a package name: PyPI treats -, _ and . alike (PEP 503), so
    ``typing_extensions`` == ``Typing.Extensions``; other ecosystems just ignore case."""
    name = name.lower()
    return re.sub(r"[-_.]+", "-", name) if ecosystem == "pypi" else name


class CatalogDB:
    """Builds catalog.db one repo and one asset at a time (a large org's dependencies need
    not all be in memory at once). Written to a temp file and moved into place by
    ``finish``, so readers never see a half-built database."""

    def __init__(self, path: Path, meta: Mapping[str, str]) -> None:
        self.path = path
        self.tmp = path.with_suffix(".tmp")
        self.tmp.unlink(missing_ok=True)
        self.con = sqlite3.connect(self.tmp)
        self.con.executescript(SCHEMA)
        self.con.executemany("INSERT INTO meta VALUES (?, ?)", meta.items())

    def add_repo(self, repo: Repo, depends_on: list[RepoLink] | None = None) -> None:
        """``depends_on``: the complete link list when ``repo.depends_on`` is capped."""
        _insert_repo(self.con, repo, repo.depends_on if depends_on is None else depends_on)

    def add_asset(self, asset: AIAsset, duplicate_count: int | None = None) -> None:
        """``duplicate_count``: the total when ``asset.duplicates`` is capped."""
        count = len(asset.duplicates) if duplicate_count is None else duplicate_count
        _insert_asset(self.con, asset, count)

    def finish(self) -> None:
        con = self.con
        try:
            con.executescript(INDEXES)
            con.executescript(AGGREGATES)
            # the index of an external-content table is built from ai_assets in one pass
            # (no VACUUM from here on: it may renumber the rows the index points to, and a
            # freshly built file has nothing to reclaim)
            con.execute("INSERT INTO assets_fts(assets_fts) VALUES ('rebuild')")
            con.commit()
        finally:
            con.close()
        self.tmp.replace(self.path)

    def abort(self) -> None:
        self.con.close()
        self.tmp.unlink(missing_ok=True)

    def __enter__(self) -> CatalogDB:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if exc_type is None:
            self.finish()
        else:
            self.abort()


def build_sqlite(
    path: Path,
    repos: Iterable[Repo],
    assets: Iterable[AIAsset],
    meta: Mapping[str, str],
    *,
    links: Mapping[str, list[RepoLink]] | None = None,
    duplicate_counts: Mapping[str, int] | None = None,
) -> None:
    """``links`` / ``duplicate_counts``: complete link lists and copy counts by id, as
    returned by ``link_org`` and ``mark_duplicates`` (the records hold capped lists)."""
    with CatalogDB(path, meta) as db:
        for r in repos:
            db.add_repo(r, links.get(r.id) if links is not None else None)
        for a in assets:
            db.add_asset(a, duplicate_counts.get(a.id) if duplicate_counts is not None else None)


def _insert_repo(con: sqlite3.Connection, r: Repo, depends_on: list[RepoLink]) -> None:
    s = r.stack
    # the full record minus locked transitive deps (thousands per repo, and all of them
    # are rows in `dependencies`); used_by/depends_on are the capped lists
    direct = [d for d in r.dependencies if d.scope != "transitive"]
    record = (
        r if len(direct) == len(r.dependencies) else r.model_copy(update={"dependencies": direct})
    )
    con.execute(
        "INSERT INTO repos VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            r.id,
            r.name,
            r.owner,
            r.url,
            r.description,
            r.summary.one_liner,
            r.summary.purpose,
            r.summary.reuse_notes,
            r.structure.repo_type,
            r.lifecycle,
            s.primary_language,
            r.practices.score,
            r.practices.grade,
            int(r.archived),
            int(r.fork),
            r.visibility,
            r.license,
            r.stars,
            _iso(r.pushed_at),
            _iso(r.ownership.last_commit),
            r.declared.owner,
            r.declared.system,
            int(r.ai.has_ai),
            r.ai.asset_count,
            r.structure.file_count,
            r.structure.total_lines,
            record.model_dump_json(),
        ),
    )
    tech: list[tuple[str, str, str]] = []
    for f in _TECH_FIELDS:
        tech += [(r.id, f, v) for v in getattr(s, f)]
    tech += [(r.id, "languages", lang.name) for lang in s.languages]
    tech += [(r.id, "runtimes", f"{k} {v}") for k, v in s.runtimes.items()]
    con.executemany("INSERT INTO repo_tech VALUES (?,?,?)", tech)
    con.executemany(
        "INSERT INTO repo_capabilities VALUES (?,?)", [(r.id, c) for c in r.capabilities]
    )
    con.executemany("INSERT INTO repo_topics VALUES (?,?)", [(r.id, t) for t in r.topics])
    con.executemany(
        "INSERT INTO repo_languages VALUES (?,?,?,?)",
        [(r.id, lang.name, lang.lines, lang.percent) for lang in s.languages],
    )
    con.executemany(
        "INSERT INTO dependencies VALUES (?,?,?,?,?,?,?,?,?,?)",
        [
            (
                r.id,
                d.name,
                d.version,
                d.ecosystem,
                d.scope,
                d.manifest,
                d.resolved,
                d.purl,
                " ".join(d.vulns) or None,
                norm_name(d.ecosystem, d.name),
            )
            for d in r.dependencies
        ],
    )
    con.executemany(
        "INSERT INTO packages VALUES (?,?,?,?,?,?)",
        [
            (r.id, p.name, p.path, p.ecosystem, p.version, p.description)
            for p in r.structure.packages
        ],
    )
    con.executemany(
        "INSERT INTO practice_checks VALUES (?,?,?,?,?,?,?)",
        [
            (r.id, c.id, c.category, c.label, int(c.passed), c.weight, c.evidence)
            for c in r.practices.checks
        ],
    )
    con.executemany(
        "INSERT INTO flags VALUES (?,?,?,?,?,?,?,?)",
        [(r.id, None, f.id, f.category, f.severity, f.message, f.path, f.line) for f in r.flags],
    )
    con.executemany(
        "INSERT INTO reusables VALUES (?,?,?,?,?,?)",
        [
            (r.id, x.kind, x.name, x.path, x.description, json.dumps(x.details, sort_keys=True))
            for x in r.reusables
        ],
    )
    con.executemany(
        "INSERT INTO repo_links VALUES (?,?,?)", [(r.id, ln.repo, ln.via) for ln in depends_on]
    )
    con.executemany(
        "INSERT INTO runtime_versions VALUES (?,?,?,?)",
        [(r.id, v.runtime, v.version, v.path) for v in r.stack.runtime_versions],
    )
    con.execute(
        "INSERT INTO repos_fts VALUES (?,?,?,?,?,?,?,?)",
        (
            r.id,
            r.name,
            " ".join(filter(None, [r.description, r.summary.one_liner])),
            " ".join(
                filter(
                    None,
                    [r.summary.purpose, r.summary.reuse_notes, " ".join(r.summary.key_features)],
                )
            ),
            r.summary.readme_excerpt or "",
            " ".join(t[2] for t in tech),
            " ".join(r.capabilities + r.summary.domains),
            " ".join(r.topics),
        ),
    )


def _insert_asset(con: sqlite3.Connection, a: AIAsset, duplicate_count: int) -> None:
    con.execute(
        "INSERT INTO ai_assets VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            a.id,
            a.repo,
            a.kind,
            a.ecosystem,
            a.name,
            a.title,
            a.description,
            a.summary,
            a.category,
            a.path,
            a.url,
            a.scope,
            a.confidence,
            a.quality_score,
            a.word_count,
            _iso(a.last_modified),
            a.last_author,
            duplicate_count,
            a.content,
            a.model_dump_json(exclude={"content"}),
            " ".join(a.use_cases),
            " ".join(a.tags),
        ),
    )
    con.executemany(
        "INSERT INTO flags VALUES (?,?,?,?,?,?,?,?)",
        [(a.repo, a.id, f.id, f.category, f.severity, f.message, f.path, f.line) for f in a.flags],
    )
    con.executemany("INSERT INTO asset_tools VALUES (?,?)", [(a.id, t) for t in a.tools])
    con.executemany("INSERT INTO asset_models VALUES (?,?)", [(a.id, m) for m in a.models])
    con.executemany("INSERT INTO asset_tags VALUES (?,?)", [(a.id, t) for t in a.tags])


def _iso(v: object) -> str | None:
    return v.isoformat() if v is not None and hasattr(v, "isoformat") else None


def dump_meta(meta: object) -> dict[str, str]:
    return {k: str(v) for k, v in json.loads(json.dumps(meta, default=str)).items()}
