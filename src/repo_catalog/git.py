"""Thin wrappers around the git CLI for cloning and provenance lookups.

Security notes:
- The GitHub token is passed through ``GIT_CONFIG_*`` environment variables, never on the
  command line, so it cannot appear in ``ps`` output, error messages or catalog data.
- Every command runs with ``GIT_CEILING_DIRECTORIES`` so a damaged clone can never make
  git fall back to (and reset!) a repository higher up the tree.
"""

from __future__ import annotations

import base64
import logging
import os
import re
import shutil
import subprocess
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

log = logging.getLogger(__name__)


class GitError(RuntimeError):
    pass


_BASIC = re.compile(r"(?i)(authorization:\s*(?:basic|bearer)\s+)\S+")
_URL_CRED = re.compile(r"(https?://)[^/@\s]+@")


def _scrub(text: str) -> str:
    return _URL_CRED.sub(r"\1***@", _BASIC.sub(r"\1***", text))


def _auth_env(token: str | None, url: str) -> dict[str, str]:
    """Extra-header config for github.com, appended after any GIT_CONFIG_* already set
    (e.g. by a corporate proxy) instead of replacing them."""
    if not token or not url.startswith("https://github.com/"):
        return {}
    basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    n = int(os.environ.get("GIT_CONFIG_COUNT", "0") or 0)
    return {
        "GIT_CONFIG_COUNT": str(n + 1),
        f"GIT_CONFIG_KEY_{n}": "http.https://github.com/.extraheader",
        f"GIT_CONFIG_VALUE_{n}": f"AUTHORIZATION: basic {basic}",
    }


def _run(
    args: list[str],
    cwd: Path | None = None,
    timeout: int = 900,
    env: dict[str, str] | None = None,
) -> str:
    sub = next((a for a in args if not a.startswith("-")), "git")
    full_env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", **(env or {})}
    if cwd is not None:
        full_env["GIT_CEILING_DIRECTORIES"] = str(Path(cwd).resolve().parent)
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=full_env,
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        raise GitError(f"git {sub} timed out after {timeout}s") from None
    if proc.returncode != 0:
        raise GitError(f"git {sub} failed: {_scrub(proc.stderr.strip())[:500]}")
    return proc.stdout


def _is_own_repo(dest: Path) -> bool:
    """True only when ``dest`` itself is a healthy work tree (not a parent repo)."""
    if not (dest / ".git").exists():
        return False
    try:
        top = _run(["rev-parse", "--show-toplevel"], cwd=dest, timeout=60).strip()
    except GitError:
        return False
    return Path(top).resolve() == dest.resolve()


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
    env = _auth_env(token, url)
    depth = ["--depth", "1"] if shallow else ["--filter=blob:none"]
    if dest.exists() and not _is_own_repo(dest):
        log.warning("discarding unusable clone at %s", dest)
        shutil.rmtree(dest)
    if dest.exists():
        if (
            not shallow
            and _run(["rev-parse", "--is-shallow-repository"], cwd=dest).strip() == "true"
        ):
            depth = ["--unshallow", "--filter=blob:none"]
        ref = f"refs/heads/{branch}" if branch else "HEAD"
        _run(["fetch", "--no-tags", "--force", *depth, "origin", ref], cwd=dest, env=env)
        _run(["reset", "--hard", "--quiet", "FETCH_HEAD"], cwd=dest)
        _run(["clean", "-fdxq"], cwd=dest)
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        branch_args = ["--branch", branch] if branch else []
        _run(
            [
                "clone",
                "--quiet",
                "--no-tags",
                "--single-branch",
                *depth,
                *branch_args,
                "--",
                url,
                str(dest),
            ],
            env=env,
        )
    return head_sha(dest)


def head_sha(repo: Path) -> str:
    return _run(["rev-parse", "HEAD"], cwd=repo).strip()


def remote_head(url: str, token: str | None = None, branch: str | None = None) -> str | None:
    """Tip SHA of the remote branch without cloning (used for incremental scans)."""
    ref = f"refs/heads/{branch}" if branch else "HEAD"
    try:
        out = _run(["ls-remote", "--", url, ref], timeout=60, env=_auth_env(token, url))
    except GitError:
        return None
    for line in out.splitlines():
        sha, _, name = line.partition("\t")
        if name == ref:
            return sha
    return None


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


def is_shallow(repo: Path) -> bool:
    try:
        return _run(["rev-parse", "--is-shallow-repository"], cwd=repo).strip() == "true"
    except GitError:
        return True


def repo_history(repo: Path, top: int = 10) -> RepoHistory | None:
    try:
        out = _run(["log", "--no-merges", "--format=%aN%x09%aI", "HEAD"], cwd=repo, timeout=300)
    except GitError as exc:
        log.info("history unavailable for %s: %s", repo, exc)
        return None
    authors: Counter[str] = Counter()
    dates: list[str] = []
    for line in out.splitlines():
        name, _, date = line.partition("\t")
        if not date:
            continue
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


_MARK = "\x1e"  # record separator: cannot appear in author names or paths


def files_history(repo: Path, paths: list[str]) -> dict[str, FileHistory]:
    """Last author/date and commit count for many files in a single ``git log`` pass."""
    wanted = set(paths)
    if not wanted:
        return {}
    try:
        out = _run(
            [
                "-c",
                "core.quotepath=off",
                "log",
                f"--format={_MARK}%aN%x09%aI",
                "--name-only",
                "--no-renames",
                "HEAD",
                "--",
                *sorted(wanted),
            ],
            cwd=repo,
            timeout=600,
        )
    except GitError as exc:
        log.info("file history unavailable for %s: %s", repo, exc)
        return {}
    result: dict[str, FileHistory] = {}
    author: str | None = None
    date: datetime | None = None
    for line in out.split("\n"):  # not splitlines(): it also splits on \x1e
        if line.startswith(_MARK):
            name, _, iso = line[1:].partition("\t")
            author, date = name, datetime.fromisoformat(iso) if iso else None
        elif line in wanted:
            hist = result.get(line)
            if hist is None:
                result[line] = FileHistory(date, author, 1)
            else:
                hist.commit_count += 1
    return result


def file_history(repo: Path, rel_path: str) -> FileHistory | None:
    return files_history(repo, [rel_path]).get(rel_path)
