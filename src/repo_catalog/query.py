"""Read-only query helpers over catalog.db, shared by the CLI and the MCP server."""

from __future__ import annotations

import json
import re
import sqlite3
import time
from typing import Any


def fts_query(text: str, mode: str = "AND") -> str:
    """Turn free text into a safe FTS5 expression with prefix matching.

    Tokens are split the same way the FTS tokenizer splits them (``c++`` -> ``c``), and
    one-character pieces are dropped, so the expression never matches more than intended.
    """
    tokens = [t for t in re.split(r"[^\w]+", text.lower()) if len(t) > 1]
    return f" {mode} ".join(f'"{t}"*' for t in dict.fromkeys(tokens[:12]))


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
            "r.id IN (SELECT repo_id FROM repo_tech WHERE name LIKE ? COLLATE NOCASE "
            "UNION SELECT repo_id FROM dependencies WHERE name LIKE ? COLLATE NOCASE)"
        )
        params += [f"%{technology}%", f"%{technology}%"]
    if capability:
        where.append("r.id IN (SELECT repo_id FROM repo_capabilities WHERE capability LIKE ?)")
        params.append(f"%{capability}%")
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
        weights="0, 8, 4, 4, 1, 3",
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
        where.append("(f.repo_id = ? COLLATE NOCASE OR f.repo_id LIKE ? COLLATE NOCASE)")
        params += [repo, f"%/{repo}"]
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


def repo_relationships(con: sqlite3.Connection, repo_id: str) -> dict[str, Any] | None:
    """Which org repos this one depends on, and which depend on it (blast radius)."""
    row = con.execute(
        "SELECT id FROM repos WHERE id = ? COLLATE NOCASE OR name = ? COLLATE NOCASE",
        (repo_id, repo_id),
    ).fetchone()
    if not row:
        return None
    rid = row[0]
    return {
        "repo": rid,
        "depends_on": _rows(
            con.execute("SELECT depends_on AS repo, via FROM repo_links WHERE repo_id = ?", (rid,))
        ),
        "used_by": _rows(
            con.execute("SELECT repo_id AS repo, via FROM repo_links WHERE depends_on = ?", (rid,))
        ),
    }


def get_repo(
    con: sqlite3.Connection, repo_id: str, *, include_transitive: bool = False
) -> dict[str, Any] | None:
    """Full record. Locked transitive dependencies (often thousands) are left out unless
    asked for; `dependency_summary` has their count and `dependency_usage` queries them."""
    row = con.execute(
        "SELECT json FROM repos WHERE id = ? COLLATE NOCASE OR name = ? COLLATE NOCASE",
        (repo_id, repo_id),
    ).fetchone()
    if not row:
        return None
    data: dict[str, Any] = json.loads(row[0])
    if not include_transitive:
        data["dependencies"] = [d for d in data["dependencies"] if d["scope"] != "transitive"]
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
    where, params = ["d.name = ? COLLATE NOCASE"], [name]
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
            "FROM repo_tech t JOIN repos r ON r.id = t.repo_id WHERE t.name LIKE ? COLLATE NOCASE "
            "UNION SELECT DISTINCT r.id, r.url, r.one_liner, "
            "CASE d.scope WHEN 'transitive' THEN 'transitive dependency' ELSE 'dependency' END, "
            "d.name || ' ' || COALESCE(d.resolved, d.version, '') "
            "FROM dependencies d JOIN repos r ON r.id = d.repo_id "
            "WHERE d.name LIKE ? COLLATE NOCASE ORDER BY 1 LIMIT 500",
            (f"%{name}%", f"%{name}%"),
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
