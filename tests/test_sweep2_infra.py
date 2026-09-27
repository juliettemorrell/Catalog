"""Nightly-run robustness: partial GitHub answers, killed runs, damaged clones, exit codes."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import httpx
import pytest

from repo_catalog import cli, git, github, scanner
from repo_catalog.outputs import store


def _sh(*args: str, cwd: Path | None = None) -> str:
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def _remote(base: Path, name: str, files: dict[str, str]) -> tuple[Path, str]:
    bare, work = base / f"{name}.git", base / f"_w_{name}"
    _sh("git", "init", "-q", "--bare", "-b", "main", str(bare))
    _sh("git", "init", "-q", "-b", "main", str(work))
    for rel, text in files.items():
        (work / rel).parent.mkdir(parents=True, exist_ok=True)
        (work / rel).write_text(text)
    _sh("git", "add", "-A", cwd=work)
    _sh("git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "c", cwd=work)
    _sh("git", "remote", "add", "origin", str(bare), cwd=work)
    _sh("git", "push", "-q", "origin", "main", cwd=work)
    return bare, _sh("git", "rev-parse", "HEAD", cwd=work)


def _node(name: str, bare: Path, sha: str, **kw: Any) -> dict[str, Any]:
    return {
        "nameWithOwner": f"acme/{name}",
        "url": str(bare)[:-4],
        "description": None,
        "visibility": "PRIVATE",
        "isArchived": kw.get("archived", False),
        "isFork": False,
        "isTemplate": False,
        "owner": {"login": "acme"},
        "repositoryTopics": {"nodes": []},
        "defaultBranchRef": {"name": kw.get("branch", "main"), "target": {"oid": sha}},
        "languages": {"edges": []},
    }


def _mock(monkeypatch: pytest.MonkeyPatch, pages: list[Any], props: Any = None) -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/graphql":
            cursor = json.loads(req.content)["variables"].get("cursor")
            i = int(cursor or 0)
            page = pages[i]
            if isinstance(page, httpx.Response):
                return page
            nodes, errors = page if isinstance(page, tuple) else (page, None)
            body: dict[str, Any] = {
                "data": {
                    "repositoryOwner": {
                        "login": "acme",
                        "repositories": {
                            "pageInfo": {
                                "hasNextPage": i + 1 < len(pages),
                                "endCursor": str(i + 1),
                            },
                            "nodes": nodes,
                        },
                    }
                }
            }
            if errors:
                body["errors"] = errors
            return httpx.Response(200, json=body)
        if req.url.path.endswith("/properties/values"):
            return (
                props
                if isinstance(props, httpx.Response)
                else httpx.Response(200, json=props or [])
            )
        return httpx.Response(404, json={})

    orig = github.GitHubClient

    class Client(orig):  # type: ignore[misc, valid-type]
        def __init__(self, token: str | None, **kw: Any) -> None:
            kw["transport"] = httpx.MockTransport(handler)
            kw["max_retries"] = 0
            super().__init__(token, **kw)

    monkeypatch.setattr(cli, "GitHubClient", Client)
    monkeypatch.setattr(github.time, "sleep", lambda _s: None)


def _scan(out: Path, wd: Path, *extra: str) -> int:
    return cli.main(
        ["scan", "--org", "acme", "--token", "t", "--out", str(out), "--workdir", str(wd), *extra]
    )


def test_partial_graphql_listing_never_prunes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    a, sa = _remote(tmp_path, "a", {"README.md": "# A\n\nService A.\n"})
    b, sb = _remote(tmp_path, "b", {"README.md": "# B\n\nService B.\n"})
    out, wd = tmp_path / "out", tmp_path / "wd"
    _mock(monkeypatch, [[_node("a", a, sa), _node("b", b, sb)]])
    assert _scan(out, wd) == 0
    saml = [{"message": "Resource protected by organization SAML enforcement"}]
    _mock(monkeypatch, [([_node("a", a, sa), None], saml)])
    assert _scan(out, wd) == 0
    assert sorted(p.name for p in (out / "repos").glob("*.json")) == [
        "acme__a.json",
        "acme__b.json",
    ]


def test_graphql_rate_limited_is_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    replies = iter(
        [
            httpx.Response(
                200, json={"errors": [{"type": "RATE_LIMITED", "message": "slow down"}]}
            ),
            httpx.Response(200, json={"data": {"repository": None}}),
        ]
    )
    waits: list[float] = []
    monkeypatch.setattr(github.time, "sleep", waits.append)
    gh = github.GitHubClient("t", transport=httpx.MockTransport(lambda _r: next(replies)))
    data, complete = gh.graphql("query", {})
    assert data == {"repository": None} and complete and len(waits) == 1


def test_custom_properties_failure_keeps_previous_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    a, sa = _remote(tmp_path, "a", {"README.md": "# A\n\nService A.\n"})
    out, wd = tmp_path / "out", tmp_path / "wd"
    rows = [
        {
            "repository_full_name": "acme/a",
            "properties": [{"property_name": "team", "value": "payments"}],
        }
    ]
    _mock(monkeypatch, [[_node("a", a, sa)]], rows)
    assert _scan(out, wd) == 0
    _mock(monkeypatch, [[_node("a", a, sa)]], httpx.Response(502, text="bad gateway"))
    assert _scan(out, wd) == 0
    repo = json.loads((out / "repos/acme__a.json").read_text())["repo"]
    assert repo["declared"]["custom_properties"] == {"team": "payments"}
    gh = github.GitHubClient("t", transport=httpx.MockTransport(lambda _r: httpx.Response(404)))
    assert gh.org_custom_properties("someuser") == {}


def test_partial_failure_exit_code_and_meta(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    a, sa = _remote(tmp_path, "a", {"README.md": "# A\n\nService A.\n"})
    out, wd = tmp_path / "out", tmp_path / "wd"
    missing = _node("c", tmp_path / "c.git", "0" * 40)
    _mock(monkeypatch, [[_node("a", a, sa), missing]])
    assert _scan(out, wd) == 2
    meta = json.loads((out / "catalog.json").read_text())["meta"]
    assert list(meta["failures"]) == ["acme/c"]
    assert str(wd.resolve()) not in json.dumps(meta)


def test_reused_record_refreshes_branch_and_archived_flags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    a, sa = _remote(tmp_path, "a", {"README.md": "# A\n\nService A.\n"})
    out, wd = tmp_path / "out", tmp_path / "wd"
    _mock(monkeypatch, [[_node("a", a, sa)]])
    assert _scan(out, wd) == 0
    before = json.loads((out / "repos/acme__a.json").read_text())["repo"]
    assert any(f["id"] == "no-owner" for f in before["flags"])
    _mock(monkeypatch, [[_node("a", a, sa, archived=True)]])
    assert _scan(out, wd) == 0
    after = json.loads((out / "repos/acme__a.json").read_text())["repo"]
    assert after["archived"] and after["lifecycle"] == "archived"
    assert after["scanned_at"] != before["scanned_at"]  # rescanned, so flags match


def test_sync_recovers_from_stale_lock(tmp_path: Path) -> None:
    bare, sha = _remote(tmp_path, "a", {"README.md": "x"})
    dest = tmp_path / "wd/acme/a"
    assert git.sync(str(bare), dest, branch="main") == sha
    (dest / ".git/index.lock").write_text("")
    assert git.sync(str(bare), dest, branch="main") == sha
    assert not (dest / ".git/index.lock").exists()


def test_atomic_writes_leave_no_partial_files(tmp_path: Path) -> None:
    target = tmp_path / "x.json"
    store.write_atomic(target, '{"a": 1}')
    assert json.loads(target.read_text()) == {"a": 1}
    assert [p.name for p in tmp_path.iterdir()] == ["x.json"]


def test_scan_all_saves_each_repo_as_it_finishes(tmp_path: Path) -> None:
    a, _ = _remote(tmp_path, "a", {"README.md": "# A\n\nService A.\n"})
    ref = github.RepoRef("acme/a", str(a), "https://github.com/acme/a", default_branch="main")
    saved: list[str] = []
    opts = scanner.ScanOptions(workdir=tmp_path / "wd")
    report = scanner.scan_all([ref], opts, {}, on_result=lambda r: saved.append(r.repo.id))
    assert saved == ["acme/a"] and not report.failures


def test_local_finds_nested_layout_and_unique_ids(tmp_path: Path) -> None:
    for team in ("team1", "team2"):
        root = tmp_path / team / "api"
        _sh("git", "init", "-q", "-b", "main", str(root))
        (root / "README.md").write_text(f"# {team}\n")
        _sh("git", "add", "-A", cwd=root)
        _sh("git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "c", cwd=root)
    refs = cli._local_refs([tmp_path])  # repos two levels down
    ids = sorted(r.full_name for r, _ in refs)
    assert len(ids) == 2 and ids[0] != ids[1] and all(i.startswith("local/") for i in ids)
    empty = tmp_path / "empty"
    empty.mkdir()
    assert cli.main(["scan", "--local", str(empty), "--out", str(tmp_path / "o")]) == 1


def test_prune_removes_clones_of_deleted_repos(tmp_path: Path) -> None:
    clone = tmp_path / "wd/acme/gone"
    (clone / ".git").mkdir(parents=True)
    cli._prune_clones(tmp_path / "wd", ["acme__gone", "acme__..", "x"])
    assert not clone.exists() and (tmp_path / "wd/acme").exists()
