"""Read-only query helpers over catalog.db, shared by the CLI and the MCP server."""

from __future__ import annotations

import json
import re
import sqlite3
import time
from typing import Any

from .outputs.sqlite import norm_name

# list sizes in get_repo / repo_relationships answers (agents read them into a context
# window); totals say how many there are and `sql` / `dependency_usage` return the rest
MAX_LIST = 100
MAX_DEPENDENCIES = 200


def fts_query(text: str, mode: str = "AND") -> str:
    """Turn free text into a safe FTS5 expression with prefix matching.

    Tokens are split the same way the FTS tokenizer splits them (``c++`` -> ``c``), and
    one-character pieces are dropped, so the expression never matches more than intended.
    """
    tokens = [t for t in re.split(r"[^\w]+", text.lower()) if len(t) > 1]
    return f" {mode} ".join(f'"{t}"*' for t in dict.fromkeys(tokens[:12]))


def like(text: str) -> str:
    """A substring LIKE pattern for user text: % and _ match themselves (use ESCAPE '\\')."""
    return "%" + re.sub(r"([%_\\])", r"\\\1", text) + "%"


def resolve_repo(con: sqlite3.Connection, repo_id: str) -> str | list[str] | None:
    """``owner/name`` or a bare ``name``. A bare name shared by several owners returns the
    candidates instead of an arbitrary one."""
    exact = con.execute("SELECT id FROM repos WHERE id = ? COLLATE NOCASE", (repo_id,)).fetchone()
    if exact:
        return str(exact[0])
    rows = [
        str(r[0])
        for r in con.execute(
            "SELECT id FROM repos WHERE name = ? COLLATE NOCASE ORDER BY id", (repo_id,)
        )
    ]
    if len(rows) > 1:
        return rows
    return rows[0] if rows else None


def _ambiguous(candidates: list[str]) -> dict[str, Any]:
    return {"error": "ambiguous repo name; use owner/name", "candidates": candidates}


def _rows(cur: sqlite3.Cursor) -> list[dict[str, Any]]:
    return [dict(r) for r in cur.fetchall()]


def _clamp(limit: int, hi: int = 100) -> int:
    return max(1, min(int(limit), hi))


def _search(
    con: sqlite3.Connection,
    *,
    query: str,
    fts: str,
    weights: str,
    cols: str,
    table: str,
    where: list[str],
    params: list[Any],
    order: str,
    like_cols: tuple[str, ...],
    limit: int,
) -> list[dict[str, Any]]:
    """FTS5 (AND, then OR) with a LIKE fallback for queries FTS cannot express."""
    cond = " AND ".join(where)
    query = query.strip()
    if not query:
        return _rows(
            con.execute(
                f"SELECT {cols} FROM {table} WHERE {cond} ORDER BY {order} LIMIT ?",
                [*params, limit],
            )
        )
    for mode in ("AND", "OR"):
        expr = fts_query(query, mode)
        if not expr:
            break
        rows = _rows(
            con.execute(
                f"SELECT {cols}, bm25({fts}, {weights}) AS rank FROM {fts} "
                f"JOIN {table} ON {table.split()[-1]}.id = {fts}.id "
                f"WHERE {fts} MATCH ? AND {cond} ORDER BY rank LIMIT ?",
                [expr, *params, limit],
            )
        )
        if rows:
            return rows
    like = " OR ".join(f"{c} LIKE ? ESCAPE '\\'" for c in like_cols)
    needle = "%" + re.sub(r"([%_\\])", r"\\\1", query) + "%"
    return _rows(
        con.execute(
            f"SELECT {cols} FROM {table} WHERE {cond} AND ({like}) ORDER BY {order} LIMIT ?",
            [*params, *([needle] * len(like_cols)), limit],
        )
    )


def search_repos(
    con: sqlite3.Connection,
    query: str = "",
    *,
    language: str | None = None,
    technology: str | None = None,
    capability: str | None = None,
    repo_type: str | None = None,
    has_ai: bool | None = None,
    include_archived: bool = True,
    limit: int = 20,
) -> list[dict[str, Any]]:
    where: list[str] = ["1=1"]
    params: list[Any] = []
    if language:
        where.append("r.primary_language = ? COLLATE NOCASE")
        params.append(language)
    if technology:
        where.append(
            "r.id IN (SELECT repo_id FROM repo_tech WHERE name LIKE ? ESCAPE '\\' "
            "COLLATE NOCASE UNION SELECT repo_id FROM dependencies WHERE name LIKE ? "
            "ESCAPE '\\' COLLATE NOCASE)"
        )
        params += [like(technology), like(technology)]
    if capability:
        where.append(
            "r.id IN (SELECT repo_id FROM repo_capabilities WHERE capability LIKE ? ESCAPE '\\')"
        )
        params.append(like(capability))
    if repo_type:
        where.append("r.repo_type = ?")
        params.append(repo_type)
    if has_ai is not None:
        where.append("r.has_ai = ?")
        params.append(int(has_ai))
    if not include_archived:
        where.append("r.archived = 0")
    return _search(
        con,
        query=query,
        fts="repos_fts",
        weights="0, 8, 4, 3, 1, 3, 4, 3",
        cols=(
            "r.id, r.url, r.one_liner, r.purpose, r.repo_type, r.lifecycle, "
            "r.primary_language, r.practices_score, r.practices_grade, r.ai_asset_count, "
            "r.pushed_at"
        ),
        table="repos r",
        where=where,
        params=params,
        order="r.practices_score DESC, r.pushed_at DESC",
        like_cols=("r.id", "r.description", "r.one_liner"),
        limit=_clamp(limit),
    )


def search_assets(
    con: sqlite3.Connection,
    query: str = "",
    *,
    kind: str | None = None,
    ecosystem: str | None = None,
    repo: str | None = None,
    min_quality: int = 0,
    limit: int = 20,
) -> list[dict[str, Any]]:
    where: list[str] = ["a.quality_score >= ?"]
    params: list[Any] = [min_quality]
    for col, val in (("a.kind", kind), ("a.ecosystem", ecosystem), ("a.repo_id", repo)):
        if val:
            where.append(f"{col} = ?")
            params.append(val)
    return _search(
        con,
        query=query,
        fts="assets_fts",
        weights="0, 8, 4, 4, 4, 1, 3",
        cols=(
            "a.id, a.kind, a.ecosystem, a.name, a.description, a.summary, a.category, "
            "a.repo_id AS repo, a.path, a.url, a.quality_score, a.duplicate_count"
        ),
        table="ai_assets a",
        where=where,
        params=params,
        order="a.quality_score DESC, a.name",
        like_cols=("a.name", "a.description", "a.path"),
        limit=_clamp(limit),
    )


def find_building_blocks(
    con: sqlite3.Connection, query: str = "", *, kind: str | None = None, limit: int = 20
) -> list[dict[str, Any]]:
    """Reusable actions, workflows, Terraform modules, Helm charts, templates and APIs.

    Every word must appear in the name, description, repo, path or details."""
    where, params = ["x.repo_id = r.id"], []
    if kind:
        where.append("x.kind = ?")
        params.append(kind)
    for word in [w for w in re.split(r"\s+", query.lower()) if w][:8]:
        where.append(
            "LOWER(x.name || ' ' || COALESCE(x.description, '') || ' ' || x.repo_id || ' ' || "
            "x.path || ' ' || x.details) LIKE ? ESCAPE '\\'"
        )
        params.append("%" + re.sub(r"([%_\\])", r"\\\1", word) + "%")
    rows = _rows(
        con.execute(
            "SELECT x.kind, x.name, x.repo_id AS repo, x.path, x.description, x.details, "
            "r.url || '/tree/HEAD/' || x.path AS url, "
            "r.lifecycle, r.practices_grade FROM reusables x, repos r WHERE "
            + " AND ".join(where)
            + " ORDER BY r.archived, r.practices_score DESC, x.kind, x.name LIMIT ?",
            [*params, _clamp(limit)],
        )
    )
    for row in rows:
        row["details"] = json.loads(row["details"] or "{}")
    return rows


def list_flags(
    con: sqlite3.Connection,
    *,
    severity: str | None = None,
    category: str | None = None,
    flag_id: str | None = None,
    repo: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Risk and maintenance findings, most severe first."""
    where, params = ["1=1"], []
    for col, val in (("severity", severity), ("category", category), ("flag_id", flag_id)):
        if val:
            where.append(f"f.{col} = ?")
            params.append(val)
    if repo:
        where.append(
            "(f.repo_id = ? COLLATE NOCASE OR f.repo_id LIKE ? ESCAPE '\\' COLLATE NOCASE)"
        )
        params += [repo, "%/" + like(repo)[1:-1]]
    return _rows(
        con.execute(
            "SELECT f.repo_id AS repo, f.asset_id, f.flag_id, f.category, f.severity, "
            "f.message, f.path, f.line FROM flags f WHERE "
            + " AND ".join(where)
            + " ORDER BY CASE f.severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, "
            "f.repo_id, f.flag_id LIMIT ?",
            [*params, _clamp(limit, 1000)],
        )
    )


# runtime links first, then optional, dev, build and transitive ones (the via suffix)
_LINK_ORDER = (
    "CASE WHEN via LIKE '% (transitive)' THEN 4 WHEN via LIKE '% (build)' THEN 3 "
    "WHEN via LIKE '% (dev)' THEN 2 WHEN via LIKE '% (optional)' THEN 1 ELSE 0 END, rowid"
)


def repo_relationships(
    con: sqlite3.Connection, repo_id: str, *, limit: int = MAX_LIST
) -> dict[str, Any] | None:
    """Which org repos this one depends on, and which depend on it (blast radius). Each
    list holds at most ``limit`` links, runtime ones first; ``*_total`` counts them all."""
    found = resolve_repo(con, repo_id)
    if isinstance(found, list):
        return _ambiguous(found)
    if found is None:
        return None
    rid = found
    limit = _clamp(limit, 1000)
    out: dict[str, Any] = {"repo": rid}
    for key, col, other in (
        ("depends_on", "repo_id", "depends_on"),
        ("used_by", "depends_on", "repo_id"),
    ):
        out[key] = _rows(
            con.execute(
                f"SELECT {other} AS repo, via FROM repo_links WHERE {col} = ? "
                f"ORDER BY {_LINK_ORDER} LIMIT ?",
                (rid, limit),
            )
        )
        total = con.execute(f"SELECT COUNT(*) FROM repo_links WHERE {col} = ?", (rid,)).fetchone()
        out[f"{key}_total"] = total[0]
    if out["depends_on_total"] > limit or out["used_by_total"] > limit:
        out["note"] = (
            f'Lists are capped at {limit} links. All of them: sql "SELECT repo_id, depends_on, '
            f"via FROM repo_links WHERE depends_on = '{rid}'\" (used_by) or WHERE repo_id = "
            "... (depends_on)."
        )
    return out


def get_repo(
    con: sqlite3.Connection,
    repo_id: str,
    *,
    include_transitive: bool = False,
    max_items: int | None = MAX_LIST,
) -> dict[str, Any] | None:
    """Full record, sized for an agent's context. Locked transitive dependencies (often
    thousands) are left out unless asked for (`dependency_summary` counts them and
    `dependency_usage` queries them); direct dependencies are capped at MAX_DEPENDENCIES
    and other long lists (used_by, depends_on, flags...) at ``max_items``, with the full
    lengths in `truncated`. ``max_items=None`` returns everything."""
    found = resolve_repo(con, repo_id)
    if isinstance(found, list):
        return _ambiguous(found)
    row = con.execute("SELECT json FROM repos WHERE id = ?", (found,)).fetchone() if found else None
    if not row:
        return None
    rid = str(found)
    data: dict[str, Any] = json.loads(row[0])
    # the json column holds direct dependencies; every row (transitive too) is in the table
    data["dependencies"] = [d for d in data["dependencies"] if d["scope"] != "transitive"]
    if include_transitive:
        data["dependencies"] = [
            {
                "name": d["name"],
                "version": d["version"],
                "ecosystem": d["ecosystem"],
                "scope": d["scope"],
                "manifest": d["manifest"],
                "resolved": d["resolved"],
                "purl": d["purl"],
                "vulns": d["vulns"].split() if d["vulns"] else [],
            }
            for d in _rows(
                con.execute("SELECT * FROM dependencies WHERE repo_id = ? ORDER BY rowid", (rid,))
            )
        ]
    total_used_by = con.execute(
        "SELECT COUNT(*) FROM repo_links WHERE depends_on = ?", (rid,)
    ).fetchone()[0]
    total_depends_on = con.execute(
        "SELECT COUNT(*) FROM repo_links WHERE repo_id = ?", (rid,)
    ).fetchone()[0]
    totals = {
        "used_by": max(total_used_by, len(data.get("used_by", []))),
        "depends_on": max(total_depends_on, len(data.get("depends_on", []))),
    }
    if max_items is None:
        return data
    truncated: dict[str, dict[str, int]] = {}
    for key, value in list(data.items()):
        cap = MAX_DEPENDENCIES if key == "dependencies" else max_items
        total = totals.get(key, len(value) if isinstance(value, list) else 0)
        if isinstance(value, list) and total > cap:
            data[key] = value[:cap]
            truncated[key] = {"shown": len(data[key]), "total": total}
        elif key in totals and total > len(value):  # the record itself holds a capped list
            truncated[key] = {"shown": len(value), "total": total}
    if truncated:
        data["truncated"] = truncated
        data["truncated_note"] = (
            "Long lists are cut to keep this answer small. The rest: dependency_usage or sql "
            f"\"SELECT * FROM dependencies WHERE repo_id = '{rid}'\"; repo_relationships or "
            "the repo_links table for used_by/depends_on; list_flags(repo=...) for flags."
        )
    return data


def dependency_usage(
    con: sqlite3.Connection,
    name: str,
    *,
    ecosystem: str | None = None,
    version_prefix: str | None = None,
    include_transitive: bool = True,
    limit: int = 200,
) -> list[dict[str, Any]]:
    """Every repo that ships a package (exact name, case-insensitive), with the declared and
    locked version, whether it is direct or transitive, where, and known advisories."""
    # norm_name is indexed: lower case, and PEP 503 for PyPI (typing_extensions ==
    # typing-extensions); other ecosystems keep - _ . distinct
    lower, pep503 = norm_name("", name), norm_name("pypi", name)
    where = [
        "d.norm_name IN (?, ?)",
        "d.norm_name = CASE d.ecosystem WHEN 'pypi' THEN ? ELSE ? END",
    ]
    params: list[Any] = [lower, pep503, pep503, lower]
    if ecosystem:
        where.append("d.ecosystem = ?")
        params.append(ecosystem)
    if version_prefix:
        where.append("COALESCE(d.resolved, d.version) LIKE ? ESCAPE '\\'")
        params.append(re.sub(r"([%_\\])", r"\\\1", version_prefix) + "%")
    if not include_transitive:
        where.append("d.scope != 'transitive'")
    return _rows(
        con.execute(
            "SELECT d.repo_id AS repo, d.ecosystem, d.name, d.version AS declared, d.resolved, "
            "d.scope, d.manifest, d.purl, d.vulns, r.lifecycle FROM dependencies d "
            "JOIN repos r ON r.id = d.repo_id WHERE "
            + " AND ".join(where)
            + " ORDER BY r.archived, d.repo_id, d.scope LIMIT ?",
            [*params, _clamp(limit, 2000)],
        )
    )


def get_asset(con: sqlite3.Connection, asset_id: str) -> dict[str, Any] | None:
    row = con.execute("SELECT json, content FROM ai_assets WHERE id = ?", (asset_id,)).fetchone()
    if not row:
        return None
    data: dict[str, Any] = json.loads(row[0])
    data["content"] = row[1]
    return data


def technology_usage(
    con: sqlite3.Connection, category: str | None = None, limit: int = 50
) -> list[dict[str, Any]]:
    limit = _clamp(limit, 500)
    if category:
        return _rows(
            con.execute("SELECT * FROM tech_usage WHERE category = ? LIMIT ?", (category, limit))
        )
    return _rows(con.execute("SELECT * FROM tech_usage LIMIT ?", (limit,)))


def repos_using(con: sqlite3.Connection, name: str) -> list[dict[str, Any]]:
    return _rows(
        con.execute(
            "SELECT DISTINCT r.id, r.url, r.one_liner, t.category, t.name AS matched "
            "FROM repo_tech t JOIN repos r ON r.id = t.repo_id "
            "WHERE t.name LIKE ? ESCAPE '\\' COLLATE NOCASE "
            "UNION SELECT DISTINCT r.id, r.url, r.one_liner, "
            "CASE d.scope WHEN 'transitive' THEN 'transitive dependency' ELSE 'dependency' END, "
            "d.name || ' ' || COALESCE(d.resolved, d.version, '') "
            "FROM dependencies d JOIN repos r ON r.id = d.repo_id "
            "WHERE d.name LIKE ? ESCAPE '\\' COLLATE NOCASE ORDER BY 1 LIMIT 500",
            (like(name), like(name)),
        )
    )


_FORBIDDEN_SQL = re.compile(r"--|/\*|\b(attach|detach|pragma|vacuum|load_extension)\b", re.I)


def read_only_sql(
    con: sqlite3.Connection, sql: str, limit: int = 200, timeout_s: float = 5.0
) -> list[dict[str, Any]]:
    """Run one SELECT/WITH statement with a row limit and a time limit.

    The connection should also be opened read-only (``mode=ro``); this adds guards against
    escaping the LIMIT wrapper (comments), multiple statements and runaway queries.
    """
    body = sql.strip().rstrip(";").strip()
    if not re.match(r"^(SELECT|WITH)\b", body, re.I):
        raise ValueError("Only a single SELECT or WITH query is allowed.")
    if _FORBIDDEN_SQL.search(body):
        raise ValueError("Comments, ATTACH, PRAGMA and similar statements are not allowed.")
    if not sqlite3.complete_statement(body + ";") or _has_second_statement(body):
        raise ValueError("Only one statement is allowed.")
    limit = max(1, min(int(limit), 10_000))
    deadline = time.monotonic() + timeout_s
    con.set_progress_handler(lambda: int(time.monotonic() > deadline), 10_000)
    try:
        return _rows(con.execute(f"SELECT * FROM ({body}) LIMIT {limit}"))
    except sqlite3.OperationalError as exc:
        if "interrupted" in str(exc):
            raise ValueError(f"Query exceeded {timeout_s:g}s; add filters or a LIMIT.") from None
        raise
    finally:
        con.set_progress_handler(None, 0)


def _has_second_statement(body: str) -> bool:
    """True if a ';' outside string literals splits the text into several statements."""
    quote: str | None = None
    for ch in body:
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"`[":
            quote = "]" if ch == "[" else ch
        elif ch == ";":
            return True
    return False
