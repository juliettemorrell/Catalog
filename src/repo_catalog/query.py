"""Read-only query helpers over catalog.db, shared by the CLI and the MCP server."""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any


def fts_query(text: str, mode: str = "AND") -> str:
    """Turn free text into a safe FTS5 expression with prefix matching."""
    tokens = [t for t in re.findall(r"[\w][\w.+#-]*", text.lower()) if len(t) > 1]
    return f" {mode} ".join(f'"{t}"*' for t in tokens[:12])


def _rows(cur: sqlite3.Cursor) -> list[dict[str, Any]]:
    return [dict(r) for r in cur.fetchall()]


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
    cols = (
        "r.id, r.url, r.one_liner, r.purpose, r.repo_type, r.lifecycle, r.primary_language, "
        "r.practices_score, r.practices_grade, r.ai_asset_count, r.pushed_at"
    )
    for mode in ("AND", "OR"):
        expr = fts_query(query, mode) if query else ""
        if expr:
            sql = (
                f"SELECT {cols}, bm25(repos_fts, 0, 8, 4, 3, 1, 3, 4, 3) AS rank "
                f"FROM repos_fts JOIN repos r ON r.id = repos_fts.id "
                f"WHERE repos_fts MATCH ? AND {' AND '.join(where)} ORDER BY rank LIMIT ?"
            )
            rows = _rows(con.execute(sql, [expr, *params, limit]))
        else:
            sql = (
                f"SELECT {cols} FROM repos r WHERE {' AND '.join(where)} "
                f"ORDER BY r.practices_score DESC, r.pushed_at DESC LIMIT ?"
            )
            rows = _rows(con.execute(sql, [*params, limit]))
        if rows or not expr:
            return rows
    return []


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
    cols = (
        "a.id, a.kind, a.ecosystem, a.name, a.description, a.summary, a.category, "
        "a.repo_id AS repo, a.path, a.url, a.quality_score, a.duplicate_count"
    )
    for mode in ("AND", "OR"):
        expr = fts_query(query, mode) if query else ""
        if expr:
            sql = (
                f"SELECT {cols}, bm25(assets_fts, 0, 8, 4, 4, 1, 3) AS rank "
                f"FROM assets_fts JOIN ai_assets a ON a.id = assets_fts.id "
                f"WHERE assets_fts MATCH ? AND {' AND '.join(where)} ORDER BY rank LIMIT ?"
            )
            rows = _rows(con.execute(sql, [expr, *params, limit]))
        else:
            sql = (
                f"SELECT {cols} FROM ai_assets a WHERE {' AND '.join(where)} "
                f"ORDER BY a.quality_score DESC LIMIT ?"
            )
            rows = _rows(con.execute(sql, [*params, limit]))
        if rows or not expr:
            return rows
    return []


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


def read_only_sql(con: sqlite3.Connection, sql: str, limit: int = 200) -> list[dict[str, Any]]:
    if not re.match(r"^\s*(SELECT|WITH)\b", sql, re.I) or ";" in sql.strip().rstrip(";"):
        raise ValueError("Only a single SELECT/WITH statement is allowed.")
    return _rows(con.execute(f"SELECT * FROM ({sql.strip().rstrip(';')}) LIMIT {int(limit)}"))
