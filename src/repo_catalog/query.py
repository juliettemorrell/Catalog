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


def get_repo(con: sqlite3.Connection, repo_id: str) -> dict[str, Any] | None:
    row = con.execute(
        "SELECT json FROM repos WHERE id = ? COLLATE NOCASE OR name = ? COLLATE NOCASE",
        (repo_id, repo_id),
    ).fetchone()
    return json.loads(row[0]) if row else None


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
            "UNION SELECT DISTINCT r.id, r.url, r.one_liner, 'dependency', d.name || ' ' || "
            "COALESCE(d.version, '') FROM dependencies d JOIN repos r ON r.id = d.repo_id "
            "WHERE d.name LIKE ? COLLATE NOCASE ORDER BY 1",
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
