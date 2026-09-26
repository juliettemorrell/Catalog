"""Walk a checkout once and give analyzers a cheap, cached view of its files."""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path, PurePosixPath

IGNORED_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        "bower_components",
        "jspm_packages",
        "vendor",
        "third_party",
        "dist",
        "build",
        "out",
        ".next",
        ".nuxt",
        ".svelte-kit",
        ".output",
        ".turbo",
        ".venv",
        "venv",
        "env",
        ".env",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        "site-packages",
        ".eggs",
        "target",
        ".gradle",
        ".idea",
        ".vscode-test",
        "coverage",
        ".coverage",
        "htmlcov",
        ".terraform",
        "Pods",
        "DerivedData",
        ".dart_tool",
        ".cache",
        ".parcel-cache",
        ".serverless",
        ".aws-sam",
        "cdk.out",
        ".docusaurus",
        "storybook-static",
    }
)

# Dot-directories that matter for the catalog even though they are hidden.
_KEEP_HIDDEN = (
    ".github",
    ".claude",
    ".claude-plugin",
    ".cursor",
    ".windsurf",
    ".clinerules",
    ".cline",
    ".continue",
    ".gemini",
    ".roo",
    ".kiro",
    ".amazonq",
    ".junie",
    ".agents",
    ".codex",
    ".vscode",
    ".devcontainer",
    ".circleci",
    ".husky",
    ".changeset",
    ".storybook",
    ".buildkite",
    ".gitlab",
    ".opencode",
    ".zed",
)

MAX_READ_BYTES = 1_000_000


@dataclass(frozen=True)
class FileEntry:
    path: str  # posix, relative to repo root
    size: int

    @property
    def name(self) -> str:
        return PurePosixPath(self.path).name

    @property
    def suffix(self) -> str:
        return PurePosixPath(self.path).suffix.lower()

    @property
    def parts(self) -> tuple[str, ...]:
        return PurePosixPath(self.path).parts

    @property
    def depth(self) -> int:
        return len(self.parts) - 1


@dataclass
class RepoFiles:
    root: Path
    files: list[FileEntry]
    truncated: bool = False
    _text_cache: dict[str, str | None] = field(default_factory=dict, repr=False)

    @classmethod
    def scan(cls, root: Path, max_files: int = 100_000) -> RepoFiles:
        entries: list[FileEntry] = []
        truncated = False
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if _keep_dir(d))
            rel_dir = Path(dirpath).relative_to(root)
            for fname in sorted(filenames):
                full = Path(dirpath, fname)
                if full.is_symlink():
                    continue
                try:
                    size = full.stat().st_size
                except OSError:
                    continue
                entries.append(FileEntry((rel_dir / fname).as_posix(), size))
                if len(entries) >= max_files:
                    truncated = True
                    break
            if truncated:
                break
        return cls(root=root, files=entries, truncated=truncated)

    @cached_property
    def paths(self) -> set[str]:
        return {f.path for f in self.files}

    @cached_property
    def by_name(self) -> dict[str, list[FileEntry]]:
        index: dict[str, list[FileEntry]] = {}
        for f in self.files:
            index.setdefault(f.name.lower(), []).append(f)
        return index

    def exists(self, path: str) -> bool:
        return path in self.paths

    def named(self, *names: str) -> list[FileEntry]:
        out: list[FileEntry] = []
        for n in names:
            out.extend(self.by_name.get(n.lower(), []))
        return out

    def glob(self, *patterns: str) -> list[FileEntry]:
        regexes = [_glob_to_regex(p) for p in patterns]
        return [f for f in self.files if any(r.match(f.path) for r in regexes)]

    def first(self, *patterns: str) -> FileEntry | None:
        hits = self.glob(*patterns)
        return min(hits, key=lambda f: (f.depth, f.path)) if hits else None

    def read(self, path: str, limit: int = MAX_READ_BYTES) -> str | None:
        """Decoded text of a file, or None for binaries/unreadable/oversized files."""
        key = f"{path}:{limit}"
        if key in self._text_cache:
            return self._text_cache[key]
        text: str | None = None
        try:
            with open(self.root / path, "rb") as fh:
                raw = fh.read(limit)
            if b"\x00" not in raw[:8192]:
                text = raw.decode("utf-8", errors="replace")
        except OSError:
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


def _keep_dir(name: str) -> bool:
    if name in IGNORED_DIRS:
        return False
    return not (name.startswith(".") and name not in _KEEP_HIDDEN)


_GLOB_CACHE: dict[str, re.Pattern[str]] = {}


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate a glob to a regex. Supports ``**/`` (zero or more dirs), ``*``, ``?``,
    ``[abc]`` classes and ``{a,b}`` alternation. Matching is case-insensitive."""
    cached = _GLOB_CACHE.get(pattern)
    if cached:
        return cached
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
            end = pattern.find("]", i + 1)
            if end == -1:
                out.append(re.escape(c))
            else:
                out.append(pattern[i : end + 1])
                i = end
        elif c == "{":
            end = pattern.find("}", i + 1)
            if end == -1:
                out.append(re.escape(c))
            else:
                alts = pattern[i + 1 : end].split(",")
                out.append("(?:" + "|".join(re.escape(a) for a in alts) + ")")
                i = end
        else:
            out.append(re.escape(c))
        i += 1
    compiled = re.compile("^" + "".join(out) + "$", re.IGNORECASE)
    _GLOB_CACHE[pattern] = compiled
    return compiled
