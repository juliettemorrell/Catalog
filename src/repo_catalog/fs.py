"""List a checkout once and give analyzers a cheap, cached, *safe* view of its files.

- In a git work tree the file list comes from ``git ls-files``: exactly what is committed,
  honouring .gitignore, so untracked build output never pollutes the catalog while real
  folders that happen to be called ``build/`` or ``env/`` are kept.
- Outside git (plain folders) it walks the tree and skips well-known junk directories.
- Symlinks and non-regular files are never listed, and ``read()`` refuses anything that is
  not a listed regular file inside the root, so a committed symlink cannot make the
  scanner read (or block on) files outside the repository.
"""

from __future__ import annotations

import bisect
import os
import re
import stat
import subprocess
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path

# Vendored dependencies and tool caches: never the org's own code, even when committed.
VENDORED_DIRS = frozenset(
    {
        "node_modules",
        "bower_components",
        "jspm_packages",
        "vendor",
        "third_party",
        "site-packages",
        "__pycache__",
        "venv",
        ".venv",
        "Pods",
    }
)
HIDDEN_JUNK = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".idea",
        ".tox",
        ".nox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".cache",
        ".next",
        ".nuxt",
        ".svelte-kit",
        ".output",
        ".turbo",
        ".terraform",
        ".gradle",
        ".serverless",
        ".aws-sam",
        ".parcel-cache",
        ".dart_tool",
        ".docusaurus",
        ".yarn",
        ".pnpm-store",
        ".eggs",
        ".vercel",
        ".netlify",
        ".expo",
        ".angular",
        ".history",
        ".sass-cache",
        ".nyc_output",
        ".hypothesis",
        ".ipynb_checkpoints",
        ".vscode-test",
        ".coverage",
    }
)
# Only skipped when walking a plain folder (untracked build output lives here).
UNTRACKED_JUNK = frozenset(
    {
        "dist",
        "build",
        "out",
        "target",
        "coverage",
        "htmlcov",
        "env",
        "cdk.out",
        "storybook-static",
        "DerivedData",
    }
)

MAX_READ_BYTES = 1_000_000


class FileEntry:
    """A regular file in the repo. Derived fields are computed once (hot path)."""

    __slots__ = ("depth", "name", "parts", "path", "size", "suffix")

    def __init__(self, path: str, size: int):
        self.path = path  # posix, relative to repo root
        self.size = size
        self.parts = tuple(path.split("/"))
        self.name = self.parts[-1]
        dot = self.name.rfind(".")
        self.suffix = self.name[dot:].lower() if dot > 0 else ""
        self.depth = len(self.parts) - 1

    def __repr__(self) -> str:
        return f"FileEntry({self.path!r}, {self.size})"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, FileEntry) and other.path == self.path

    def __hash__(self) -> int:
        return hash(self.path)


def _skip_dir(name: str, tracked: bool) -> bool:
    return name in VENDORED_DIRS or name in HIDDEN_JUNK or (not tracked and name in UNTRACKED_JUNK)


@dataclass
class RepoFiles:
    root: Path
    files: list[FileEntry]
    truncated: bool = False
    _text_cache: dict[tuple[str, int], str | None] = field(default_factory=dict, repr=False)

    @classmethod
    def scan(cls, root: Path, max_files: int = 100_000) -> RepoFiles:
        root = root.resolve()
        tracked = _git_ls_files(root)
        candidates = tracked if tracked is not None else _walk(root)
        entries: list[FileEntry] = []
        truncated = False
        for rel in candidates:
            parts = rel.split("/")
            if any(_skip_dir(p, tracked is not None) for p in parts[:-1]):
                continue
            full = root / rel
            try:
                st = os.lstat(full)
                if stat.S_ISLNK(st.st_mode):
                    # e.g. CLAUDE.md -> AGENTS.md: follow only links that stay inside the repo
                    real = full.resolve(strict=True)
                    if not real.is_relative_to(root):
                        continue
                    st = os.stat(real)
            except (OSError, RuntimeError):
                continue  # dangling/looping links, deleted/sparse/submodule entries
            if not stat.S_ISREG(st.st_mode):
                continue  # sockets, devices, fifos, submodules, directories
            entries.append(FileEntry(rel, st.st_size))
            if len(entries) >= max_files:
                truncated = True
                break
        entries.sort(key=lambda e: e.path)
        return cls(root=root, files=entries, truncated=truncated)

    # -- indexes --------------------------------------------------------------------------

    @cached_property
    def paths(self) -> set[str]:
        return {f.path for f in self.files}

    @cached_property
    def by_name(self) -> dict[str, list[FileEntry]]:
        index: dict[str, list[FileEntry]] = {}
        for f in self.files:
            index.setdefault(f.name.lower(), []).append(f)
        return index

    @cached_property
    def by_suffix(self) -> dict[str, list[FileEntry]]:
        index: dict[str, list[FileEntry]] = {}
        for f in self.files:
            index.setdefault(f.suffix, []).append(f)
        return index

    @cached_property
    def _order(self) -> dict[str, int]:
        return {f.path: i for i, f in enumerate(self.files)}

    @cached_property
    def _sorted_paths(self) -> list[str]:
        return [f.path for f in self.files]

    # -- queries --------------------------------------------------------------------------

    def exists(self, path: str) -> bool:
        return path in self.paths

    def named(self, *names: str) -> list[FileEntry]:
        out: list[FileEntry] = []
        for n in names:
            out.extend(self.by_name.get(n.lower(), []))
        return out

    def under(self, folder: str) -> list[FileEntry]:
        """All files below ``folder`` (a repo-relative directory, '' for the root)."""
        if not folder:
            return list(self.files)
        prefix = folder.rstrip("/") + "/"
        i = bisect.bisect_left(self._sorted_paths, prefix)
        out = []
        while i < len(self.files) and self.files[i].path.startswith(prefix):
            out.append(self.files[i])
            i += 1
        return out

    def glob(self, *patterns: str) -> list[FileEntry]:
        hits: dict[str, FileEntry] = {}
        for pattern in patterns:
            rx = _glob_to_regex(pattern)
            for f in self._candidates(pattern):
                if f.path not in hits and rx.match(f.path):
                    hits[f.path] = f
        order = self._order
        return sorted(hits.values(), key=lambda f: order[f.path])

    def _candidates(self, pattern: str) -> Iterable[FileEntry]:
        """Narrow the search using the name/suffix indexes when the last segment allows."""
        last = pattern.rsplit("/", 1)[-1]
        if not any(c in last for c in "*?[{"):
            return self.by_name.get(last.lower(), [])
        m = re.fullmatch(r"\*(\.[\w-]+)", last)
        if m:
            return self.by_suffix.get(m.group(1).lower(), [])
        m = re.fullmatch(r"\*\.\{([\w,-]+)\}", last)
        if m:
            return [
                f
                for ext in m.group(1).split(",")
                for f in self.by_suffix.get("." + ext.lower(), [])
            ]
        return self.files

    def first(self, *patterns: str) -> FileEntry | None:
        """Shallowest match, preferring earlier patterns at the same depth."""
        best: tuple[int, int, str] | None = None
        found: FileEntry | None = None
        for rank, pattern in enumerate(patterns):
            for f in self.glob(pattern):
                key = (f.depth, rank, f.path)
                if best is None or key < best:
                    best, found = key, f
        return found

    def read(self, path: str, limit: int = MAX_READ_BYTES) -> str | None:
        """Decoded text of a listed regular file, or None (binary, unlisted, unreadable)."""
        key = (path, limit)
        if key in self._text_cache:
            return self._text_cache[key]
        text: str | None = None
        if path in self.paths:
            full = self.root / path
            try:
                real = full.resolve(strict=True)
                # re-checked at read time: never follow a path out of the repository and
                # never open anything but a regular file (a FIFO or device would block)
                if real.is_relative_to(self.root) and stat.S_ISREG(os.stat(real).st_mode):
                    with open(real, "rb") as fh:
                        raw = fh.read(limit)
                    text = decode(raw)
            except (OSError, ValueError, RuntimeError):
                text = None
        self._text_cache[key] = text
        return text

    def iter_text(
        self, entries: Iterable[FileEntry], limit: int = MAX_READ_BYTES
    ) -> Iterator[tuple[FileEntry, str]]:
        for entry in entries:
            if entry.size > limit:
                continue
            text = self.read(entry.path, limit)
            if text is not None:
                yield entry, text


def decode(raw: bytes) -> str | None:
    """UTF-8 (BOM tolerated) or UTF-16 with BOM; None for binary content."""
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return raw.decode("utf-16")
        except UnicodeDecodeError:
            return None
    if b"\x00" in raw[:8192]:
        return None
    return raw.decode("utf-8-sig", errors="replace")


def _git_ls_files(root: Path) -> list[str] | None:
    """Tracked files when ``root`` is the top of a git work tree, else None."""
    if not (root / ".git").exists():
        return None
    env = {**os.environ, "GIT_CEILING_DIRECTORIES": str(root.parent)}
    try:
        top = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
        )
        if top.returncode != 0 or Path(top.stdout.strip()).resolve() != root:
            return None
        proc = subprocess.run(
            ["git", "-c", "core.quotepath=off", "ls-files", "-z", "--cached"],
            cwd=root,
            capture_output=True,
            timeout=300,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return [p for p in proc.stdout.decode("utf-8", "replace").split("\0") if p]


def _walk(root: Path) -> Iterator[str]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if not _skip_dir(d, tracked=False))
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        for fname in sorted(filenames):
            yield fname if rel_dir == "." else f"{rel_dir}/{fname}"


def escape_glob(path: str) -> str:
    """Escape a literal path for use inside a glob pattern."""
    return re.sub(r"([*?\[\]{}])", r"[\1]", path)


_GLOB_CACHE: dict[str, re.Pattern[str]] = {}


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate a glob to a regex. Supports ``**/`` (zero or more dirs), ``*``, ``?``,
    ``[abc]`` / ``[!abc]`` classes and ``{a,b}`` alternation (alternatives may contain
    wildcards). Matching is case-insensitive."""
    cached = _GLOB_CACHE.get(pattern)
    if cached:
        return cached
    compiled = re.compile("^" + _translate(pattern) + "$", re.IGNORECASE)
    _GLOB_CACHE[pattern] = compiled
    return compiled


def _translate(pattern: str) -> str:
    out: list[str] = []
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
            continue
        if pattern.startswith("**", i):
            out.append(".*")
            i += 2
            continue
        if c == "*":
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[":
            j = i + 1
            if j < n and pattern[j] in "!^":
                j += 1
            if j < n and pattern[j] == "]":  # leading ] is a literal member
                j += 1
            end = pattern.find("]", j)
            if end == -1:
                out.append(re.escape(c))
            else:
                body = pattern[i + 1 : end]
                negate = body[:1] in ("!", "^")
                body = body[1:] if negate else body
                body = body.replace("\\", "\\\\").replace("]", "\\]")
                out.append("[" + ("^/" if negate else "") + body + "]")
                i = end
        elif c == "{":
            end = pattern.find("}", i + 1)
            if end == -1:
                out.append(re.escape(c))
            else:
                alts = pattern[i + 1 : end].split(",")
                out.append("(?:" + "|".join(_translate(a) for a in alts) + ")")
                i = end
        else:
            out.append(re.escape(c))
        i += 1
    return "".join(out)
