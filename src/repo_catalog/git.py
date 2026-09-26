"""Thin wrappers around the git CLI for cloning and provenance lookups."""

from __future__ import annotations

import base64
import logging
import os
import subprocess
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

log = logging.getLogger(__name__)


class GitError(RuntimeError):
    pass


def _run(args: list[str], cwd: Path | None = None, timeout: int = 900) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )
    if proc.returncode != 0:
        raise GitError(f"git {' '.join(args[:2])} failed: {proc.stderr.strip()[:500]}")
    return proc.stdout


def _auth_args(token: str | None, url: str) -> list[str]:
    """Pass the token as an HTTP header so it never lands in .git/config or process URLs."""
    if not token or not url.startswith("https://github.com/"):
        return []
    basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    return ["-c", f"http.https://github.com/.extraheader=AUTHORIZATION: basic {basic}"]


def sync(
    url: str,
    dest: Path,
    *,
    branch: str | None = None,
    token: str | None = None,
    shallow: bool = False,
) -> str:
    """Clone or fast-forward ``dest`` to the tip of ``branch``. Returns the HEAD SHA.

    Default is a blobless clone: full commit history (for provenance) while file
    contents are only downloaded for the checked-out tree.
    """
    auth = _auth_args(token, url)
    depth = ["--depth", "1"] if shallow else ["--filter=blob:none"]
    if (dest / ".git").is_dir():
        ref = branch or "HEAD"
        _run([*auth, "fetch", "--no-tags", "--force", *depth, "origin", ref], cwd=dest)
        _run(["reset", "--hard", "--quiet", "FETCH_HEAD"], cwd=dest)
        _run(["clean", "-fdxq"], cwd=dest)
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        branch_args = ["--branch", branch] if branch else []
        _run(
            [
                *auth,
                "clone",
                "--quiet",
                "--no-tags",
                "--single-branch",
                *depth,
                *branch_args,
                url,
                str(dest),
            ]
        )
    return head_sha(dest)


def head_sha(repo: Path) -> str:
    return _run(["rev-parse", "HEAD"], cwd=repo).strip()


def remote_head(url: str, token: str | None = None, branch: str | None = None) -> str | None:
    """Tip SHA of the remote branch without cloning (used for incremental scans)."""
    try:
        out = _run([*_auth_args(token, url), "ls-remote", url, branch or "HEAD"], timeout=60)
    except (GitError, subprocess.TimeoutExpired):
        return None
    line = out.strip().splitlines()[0] if out.strip() else ""
    return line.split("\t", 1)[0] or None


@dataclass
class FileHistory:
    last_modified: datetime | None
    last_author: str | None
    commit_count: int


@dataclass
class RepoHistory:
    commit_count: int
    first_commit: datetime | None
    last_commit: datetime | None
    contributors: list[tuple[str, int]]


def repo_history(repo: Path, top: int = 10) -> RepoHistory | None:
    try:
        out = _run(["log", "--no-merges", "--format=%aN%x09%aI", "HEAD"], cwd=repo, timeout=300)
    except (GitError, subprocess.TimeoutExpired) as exc:
        log.info("history unavailable for %s: %s", repo, exc)
        return None
    authors: Counter[str] = Counter()
    dates: list[str] = []
    for line in out.splitlines():
        name, _, date = line.partition("\t")
        authors[name] += 1
        dates.append(date)
    if not dates:
        return RepoHistory(0, None, None, [])
    return RepoHistory(
        commit_count=len(dates),
        first_commit=datetime.fromisoformat(dates[-1]),
        last_commit=datetime.fromisoformat(dates[0]),
        contributors=authors.most_common(top),
    )


def file_history(repo: Path, rel_path: str) -> FileHistory | None:
    try:
        out = _run(["log", "--format=%aN%x09%aI", "HEAD", "--", rel_path], cwd=repo, timeout=120)
    except (GitError, subprocess.TimeoutExpired):
        return None
    lines = [ln for ln in out.splitlines() if ln]
    if not lines:
        return None
    author, _, date = lines[0].partition("\t")
    return FileHistory(datetime.fromisoformat(date), author, len(lines))
