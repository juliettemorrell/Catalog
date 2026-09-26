from __future__ import annotations

import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

from repo_catalog.github import RepoRef


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


@pytest.fixture
def make_repo(tmp_path: Path) -> Callable[..., tuple[RepoRef, Path]]:
    """Create a committed git repo from a {path: content} mapping."""

    def _make(files: dict[str, str], name: str = "demo") -> tuple[RepoRef, Path]:
        root = tmp_path / name
        for rel, content in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        _git(root, "init", "-q", "-b", "main")
        _git(root, "-c", "user.name=Test Author", "-c", "user.email=t@example.com", "add", "-A")
        _git(
            root,
            "-c",
            "user.name=Test Author",
            "-c",
            "user.email=t@example.com",
            "commit",
            "-q",
            "-m",
            "init",
        )
        ref = RepoRef(
            full_name=f"acme/{name}",
            clone_url=str(root),
            html_url=f"https://github.com/acme/{name}",
            default_branch="main",
            head_sha="abc123",
            meta={"description": f"{name} description", "topics": ["demo"]},
        )
        return ref, root

    return _make
