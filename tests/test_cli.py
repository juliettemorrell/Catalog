"""End-to-end tests of the command line: the entry point teams actually run."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from repo_catalog.cli import main


def _git_repo(root: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    env = ["-c", "user.name=T", "-c", "user.email=t@example.com"]
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=root, check=True)
    subprocess.run(["git", *env, "add", "-A"], cwd=root, check=True)
    subprocess.run(["git", *env, "commit", "-q", "-m", "init"], cwd=root, check=True)


@pytest.fixture
def clones(tmp_path: Path) -> Path:
    base = tmp_path / "clones"
    _git_repo(
        base / "ui",
        {
            "package.json": json.dumps({"name": "@acme/ui", "version": "1.0.0"}),
            "README.md": "# UI\n\nShared React components for every Acme web app.\n",
            "action.yml": "name: Setup UI\ndescription: Installs the UI kit\nruns:\n  using: composite\n  steps: []\n",
        },
    )
    _git_repo(
        base / "web",
        {
            "package.json": json.dumps(
                {"name": "web", "dependencies": {"@acme/ui": "^1.0.0", "express": "4.19.2"}}
            ),
            "README.md": "# Web\n\nCustomer portal that takes payments with Stripe.\n",
            ".claude/skills/review/SKILL.md": "---\nname: review\ndescription: Reviews pull requests for security issues\n---\nCheck auth, input validation and secrets.\n",
            "Dockerfile": "FROM node:latest\nCMD node server.js\n",
        },
    )
    return base


def test_scan_build_and_every_query_command(
    clones: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "data"
    assert main(["scan", "--local", str(clones), "--out", str(out)]) == 0
    for name in (
        "catalog.json",
        "ai-assets.json",
        "catalog.db",
        "backstage-entities.yaml",
        "ai-bom.cdx.json",
    ):
        assert (out / name).is_file(), name
    assert sorted(p.name for p in (out / "sbom").iterdir()) == [
        "local__ui.cdx.json",
        "local__web.cdx.json",
    ]
    catalog = json.loads((out / "catalog.json").read_text())
    web = next(r for r in catalog["repos"] if r["name"] == "web")
    assert [ln["repo"] for ln in web["depends_on"]] == ["local/ui"]
    assert any(f["id"] == "docker-unpinned-base" for f in web["flags"])
    capsys.readouterr()

    def run(*argv: str) -> object:
        assert main([*argv, "--out", str(out)]) == 0
        return json.loads(capsys.readouterr().out)

    assert run("search", "payments")[0]["id"] == "local/web"  # type: ignore[index]
    assert run("search", "security review", "--assets")[0]["name"] == "review"  # type: ignore[index]
    assert run("blocks", "setup")[0]["name"] == "Setup UI"  # type: ignore[index]
    assert run("deps", "express")[0]["resolved"] == "4.19.2"  # type: ignore[index]
    assert run("flags", "--severity", "medium", "--repo", "web")  # the unpinned base image
    assert run("sql", "SELECT COUNT(*) AS n FROM repos") == [{"n": 2}]

    # rebuild from stored scans is deterministic apart from timestamps
    before = json.loads((out / "catalog.json").read_text())["repos"]
    assert main(["build", "--out", str(out)]) == 0
    after = json.loads((out / "catalog.json").read_text())["repos"]
    assert [r["depends_on"] for r in before] == [r["depends_on"] for r in after]
    assert [r["flags"] for r in before] == [r["flags"] for r in after]


def test_second_scan_reuses_unchanged_repos(
    clones: Path, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    out = tmp_path / "data"
    assert main(["scan", "--local", str(clones), "--out", str(out)]) == 0
    stored = sorted(p.name for p in (out / "repos").iterdir())
    assert main(["scan", "--local", str(clones), "--out", str(out)]) == 0
    assert sorted(p.name for p in (out / "repos").iterdir()) == stored


def test_cli_errors_are_clean_messages(tmp_path: Path) -> None:
    for argv, message in (
        (["scan"], "Nothing to scan"),
        (["scan", "--local", str(tmp_path / "missing")], "not a directory"),
        (["scan", "--local", str(tmp_path), "--match", "("], "not a valid regular expression"),
        (["build", "--out", str(tmp_path / "none")], "run `repo-catalog scan` first"),
        (["sql", "DELETE FROM repos", "--out", str(tmp_path / "none")], "not found"),
    ):
        with pytest.raises(SystemExit) as exc:
            main(argv)
        assert message in str(exc.value), (argv, exc.value)
