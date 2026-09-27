"""Scale regressions: bounded lists, streaming builds, cheap incremental writes, exit codes."""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import stat
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from repo_catalog import cli, query
from repo_catalog.analyzers.org import MAX_LINKS, link_org
from repo_catalog.github import RepoRef
from repo_catalog.models import AIAsset, Dependency, Package, Repo, Structure
from repo_catalog.outputs import exports, store
from repo_catalog.outputs.sqlite import build_sqlite
from repo_catalog.scanner import MAX_DUPLICATES, mark_duplicates
from repo_catalog.vulns import OsvFindings


def _repo(rid: str, deps: list[Dependency] | None = None, **kw: Any) -> Repo:
    owner, name = rid.split("/")
    return Repo(
        id=rid,
        name=name,
        owner=owner,
        url=f"https://github.com/{rid}",
        dependencies=deps or [],
        scanned_at=datetime(2026, 9, 1, tzinfo=UTC),
        scanner_version="test",
        **kw,
    )


def _dep(name: str, scope: str = "runtime", eco: str = "npm", **kw: Any) -> Dependency:
    manifest = "package-lock.json" if scope == "transitive" else "package.json"
    return Dependency(name=name, ecosystem=eco, scope=scope, manifest=manifest, **kw)  # type: ignore[arg-type]


def _lib(rid: str, package: str, eco: str = "npm") -> Repo:
    return _repo(rid, structure=Structure(packages=[Package(name=package, path="", ecosystem=eco)]))


def _asset(i: int, sha: str = "same") -> AIAsset:
    return AIAsset(
        id=f"a{i:04d}",
        kind="skill",
        ecosystem="agent-skills",
        name="standards",
        repo=f"acme/r{i:04d}",
        path="SKILL.md",
        url="https://example.invalid",
        detector="test",
        content="copied everywhere " * 10,
        content_sha=sha,
        word_count=20,
    )


# ------------------------------------------------------------------ bounded lists


def test_duplicates_are_capped_and_counted() -> None:
    assets = [_asset(i) for i in range(300)] + [_asset(999, sha="unique")]
    totals = mark_duplicates(assets)
    first = [a.id for a in assets[: MAX_DUPLICATES + 1]]
    for a in assets[:300]:
        assert len(a.duplicates) == MAX_DUPLICATES and a.id not in a.duplicates
        assert a.duplicates == [i for i in first if i != a.id][:MAX_DUPLICATES]  # stable
        assert totals[a.id] == 299
    assert assets[-1].duplicates == [] and totals[assets[-1].id] == 0


def test_used_by_is_capped_to_the_most_relevant_links() -> None:
    lib = _lib("acme/core", "@acme/core")
    runtime = [_repo(f"acme/r{i:03d}", [_dep("@acme/core")]) for i in range(MAX_LINKS - 10)]
    dev = [_repo(f"acme/d{i:03d}", [_dep("@acme/core", "dev")]) for i in range(40)]
    repos = [lib, *runtime, *dev]
    complete = link_org(repos, [])
    assert len(lib.used_by) == MAX_LINKS
    kept = {ln.repo for ln in lib.used_by}
    assert {r.id for r in runtime} <= kept  # runtime users win over dev ones
    assert kept - {r.id for r in runtime} == {f"acme/d{i:03d}" for i in range(10)}
    assert [ln.repo for ln in lib.used_by] == sorted(kept)  # listed by name
    # the complete lists (for SQLite repo_links) keep every link
    assert sum(len(v) for v in complete.values()) == len(runtime) + len(dev)


def test_transitive_links_survive_loading_without_transitive_deps(tmp_path: Path) -> None:
    out = tmp_path / "data"
    lib = _lib("acme/lib", "acme-lib", eco="pypi")
    app = _repo("acme/app", [_dep("flask", eco="pypi"), _dep("Acme_Lib", "transitive", "pypi")])
    for r in (lib, app):
        store.write_repo(out, r, [])
    assert cli.main(["build", "--out", str(out)]) == 0
    con = sqlite3.connect(out / "catalog.db")
    con.row_factory = sqlite3.Row
    rel = query.repo_relationships(con, "acme/lib")
    assert rel and rel["used_by"] == [{"repo": "acme/app", "via": "pypi Acme_Lib (transitive)"}]
    assert rel["used_by_total"] == 1


def test_mcp_answers_are_capped_with_totals(tmp_path: Path) -> None:
    lib = _lib("acme/core", "@acme/core")
    users = [_repo(f"acme/u{i:03d}", [_dep("@acme/core")]) for i in range(150)]
    big = _repo("acme/big", [_dep(f"p{i}") for i in range(400)] + [_dep("t", "transitive")])
    repos = [lib, *users, big]
    links = link_org(repos, [])
    db = tmp_path / "c.db"
    build_sqlite(db, repos, [], {}, links=links)
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    rel = query.repo_relationships(con, "acme/core")
    assert rel and len(rel["used_by"]) == query.MAX_LIST and rel["used_by_total"] == 150
    assert "note" in rel
    data = query.get_repo(con, "acme/core")
    assert data and len(data["used_by"]) == query.MAX_LIST
    assert data["truncated"]["used_by"] == {"shown": query.MAX_LIST, "total": 150}
    data = query.get_repo(con, "acme/big")
    assert data and len(data["dependencies"]) == query.MAX_DEPENDENCIES
    assert data["truncated"]["dependencies"]["total"] == 400
    assert "dependency_usage" in data["truncated_note"]
    full = query.get_repo(con, "acme/big", include_transitive=True, max_items=None)
    assert full and full["dependencies"] == [d.model_dump(mode="json") for d in big.dependencies]


# ------------------------------------------------------------------ SQLite


def test_dependency_usage_uses_the_normalized_name_index(tmp_path: Path) -> None:
    repos = [
        _repo("acme/a", [_dep("typing_extensions", eco="pypi", version="4.1")]),
        _repo("acme/b", [_dep("Typing.Extensions", "transitive", "pypi", resolved="4.2")]),
        _repo("acme/c", [_dep("typing-extensions", eco="npm")]),  # other ecosystems: exact
        _repo("acme/d", [_dep("TYPING_EXTENSIONS", eco="npm")]),
    ]
    db = tmp_path / "c.db"
    build_sqlite(db, repos, [], {})
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    hits = query.dependency_usage(con, "typing-extensions")
    assert {(h["repo"], h["ecosystem"]) for h in hits} == {
        ("acme/a", "pypi"),
        ("acme/b", "pypi"),
        ("acme/c", "npm"),
    }
    assert {h["repo"] for h in query.dependency_usage(con, "typing_extensions")} == {
        "acme/a",
        "acme/b",
        "acme/d",
    }
    plan = " ".join(
        str(tuple(r))
        for r in con.execute(
            "EXPLAIN QUERY PLAN SELECT * FROM dependencies d WHERE d.norm_name IN (?, ?)",
            ("a", "b"),
        )
    )
    assert "idx_dep_norm" in plan
    usage = con.execute(
        "SELECT repo_count FROM dependency_usage WHERE norm_name = 'typing-extensions' "
        "AND ecosystem = 'pypi'"
    ).fetchall()
    assert sorted(r[0] for r in usage) == [1, 1]  # still grouped by the exact name


def test_sqlite_keeps_transitive_rows_but_not_in_the_json_column(tmp_path: Path) -> None:
    deps = [_dep("express"), _dep("ms", "transitive", resolved="2.1.3"), _dep("debug")]
    repo = _repo("acme/web", deps)
    asset = _asset(1).model_copy(update={"repo": "acme/web", "tags": ["style"]})
    db = tmp_path / "c.db"
    build_sqlite(db, [repo], [asset], {})
    con = sqlite3.connect(db)
    stored = json.loads(con.execute("SELECT json FROM repos").fetchone()[0])
    assert [d["name"] for d in stored["dependencies"]] == ["express", "debug"]
    assert con.execute("SELECT COUNT(*) FROM dependencies").fetchone()[0] == 3
    # external-content full-text index still finds and joins assets
    con.row_factory = sqlite3.Row
    assert query.search_assets(con, "copied style")[0]["id"] == asset.id


# ------------------------------------------------------------------ files


def test_outputs_are_world_readable_and_unchanged_files_are_not_rewritten(
    tmp_path: Path,
) -> None:
    out = tmp_path / "data"
    repo = _repo("acme/web", [_dep("express"), _dep("ms", "transitive")])
    assert store.write_repo(out, repo, [_asset(1)])
    path = store.repo_path(out, repo.id)
    umask = os.umask(0o022)
    os.umask(umask)
    assert stat.S_IMODE(path.stat().st_mode) == 0o666 & ~umask
    before = path.stat()
    assert not store.write_repo(out, repo, [_asset(1)])  # same content: left alone
    after = path.stat()
    assert (after.st_ino, after.st_mtime_ns) == (before.st_ino, before.st_mtime_ns)
    os.chmod(path, 0o600)  # written by an older version
    assert not store.write_repo(out, repo, [_asset(1)])
    assert stat.S_IMODE(path.stat().st_mode) == 0o666 & ~umask
    # the file stays line-oriented for git diffs and round-trips losslessly
    text = path.read_text()
    assert '\n  "dependencies": [\n   {"name":"express"' in text
    assert store.load_previous(out)[repo.id][0] == repo

    writer = exports.SbomWriter(out / "sbom")
    assert writer.write(repo) and not writer.write(repo)


def test_transitive_deps_stay_on_disk_and_are_merged_back(tmp_path: Path) -> None:
    out = tmp_path / "data"
    deps = [_dep("a"), _dep("t1", "transitive"), _dep("b", "dev"), _dep("t2", "transitive")]
    repo = _repo("acme/web", deps)
    store.write_repo(out, repo, [])
    prev = store.load_previous(out, direct_only=True)
    light = prev[repo.id][0]
    assert [d.name for d in light.dependencies] == ["a", "b"]
    assert prev.transitive_refs(repo.id) == [("npm", "t1", None), ("npm", "t2", None)]
    full = store.full_dependencies(prev.paths[repo.id], light)
    assert full == deps and full[0] is light.dependencies[0]
    light.description = "changed"
    assert store.write_repo(out, light, [], merge_transitive=True)
    again = store.load_previous(out)[repo.id][0]
    assert again.dependencies == deps and again.description == "changed"


# ------------------------------------------------------------------ build / scan


def test_build_streams_osv_ids_onto_transitive_deps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "data"
    dep = _dep("minimist", "transitive", resolved="1.2.5")
    store.write_repo(out, _repo("acme/web", [_dep("express", resolved="4.18.2"), dep]), [])
    findings = OsvFindings(
        found={("npm", "minimist", "1.2.5"): ["GHSA-xvch"]},
        advisories={"GHSA-xvch": {"id": "GHSA-xvch"}},
        ok=True,
    )

    def lookup(keys: Any, cache_dir: Path) -> OsvFindings:
        assert ("npm", "minimist", "1.2.5") in set(keys)
        return findings

    monkeypatch.setattr(cli, "lookup_vulnerabilities", lookup)
    assert cli.main(["build", "--out", str(out), "--osv"]) == 0
    con = sqlite3.connect(out / "catalog.db")
    assert con.execute(
        "SELECT name, vulns FROM dependencies WHERE vulns IS NOT NULL"
    ).fetchall() == [("minimist", "GHSA-xvch")]
    assert (
        con.execute(
            "SELECT COUNT(*) FROM flags WHERE flag_id = 'vulnerable-dependency'"
        ).fetchone()[0]
        == 1
    )
    sbom = json.loads((out / "sbom" / "acme__web.cdx.json").read_text())
    assert sbom["vulnerabilities"][0]["id"] == "GHSA-xvch"
    catalog = json.loads((out / "catalog.json").read_text())
    assert catalog["repos"][0]["dependency_summary"]["vulnerable"] == 1


def test_rejected_records_warn_and_exit_2(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    make_repo: Callable[..., tuple[RepoRef, Path]],
) -> None:
    out = tmp_path / "data"
    store.write_repo(out, _repo("acme/ok"), [])
    (out / "repos" / "acme__broken.json").write_text('{"repo": {"id": "acme/broken"}}')
    with caplog.at_level(logging.WARNING):
        assert cli.main(["build", "--out", str(out)]) == 2
    assert any(
        "could not be loaded" in r.message and r.levelno == logging.WARNING for r in caplog.records
    )
    assert json.loads((out / "catalog.json").read_text())["meta"]["repo_count"] == 1

    _, root = make_repo({"README.md": "# demo\n"}, name="demo")
    args = ["scan", "--local", str(root), "--out", str(out), "--workdir", str(tmp_path / "w")]
    assert cli.main(args) == 2  # the scan itself worked; a stored record did not load
    (out / "repos" / "acme__broken.json").unlink()
    assert cli.main(args) == 0


def test_site_counts_report_totals_behind_capped_lists(tmp_path: Path) -> None:
    lib = _lib("acme/core", "@acme/core")
    users = [_repo(f"acme/r{i:03d}", [_dep("@acme/core")]) for i in range(MAX_LINKS + 50)]
    repos = [lib, *users]
    assets = [_asset(i) for i in range(MAX_DUPLICATES + 30)]
    dup_totals = mark_duplicates(assets)
    links = link_org(repos, assets)
    used_by: dict[str, int] = {}
    for targets in links.values():
        for link in targets:
            used_by[link.repo] = used_by.get(link.repo, 0) + 1
    store.write_aggregates(tmp_path, repos, assets, "test", False, {}, used_by, dup_totals)
    catalog = json.loads((tmp_path / store.CATALOG_FILE).read_text())
    core = next(r for r in catalog["repos"] if r["id"] == "acme/core")
    assert len(lib.used_by) == MAX_LINKS and core["used_by_count"] == MAX_LINKS + 50
    listed = json.loads((tmp_path / store.ASSETS_FILE).read_text())["assets"]
    assert {a["duplicate_count"] for a in listed} == {MAX_DUPLICATES + 29}
