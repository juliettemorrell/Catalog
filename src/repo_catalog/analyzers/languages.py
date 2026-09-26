"""Line-count based language breakdown (a lightweight stand-in for linguist).

GitHub's linguist byte counts are stored separately on the record when available;
this module works offline and also counts files, which is often more telling.
"""

from __future__ import annotations

import re

from ..fs import RepoFiles
from ..models import LanguageStat

# extension -> (language, is_programming)
EXTENSIONS: dict[str, tuple[str, bool]] = {
    ".py": ("Python", True),
    ".pyi": ("Python", True),
    ".ipynb": ("Jupyter Notebook", True),
    ".js": ("JavaScript", True),
    ".mjs": ("JavaScript", True),
    ".cjs": ("JavaScript", True),
    ".jsx": ("JavaScript", True),
    ".ts": ("TypeScript", True),
    ".tsx": ("TypeScript", True),
    ".mts": ("TypeScript", True),
    ".cts": ("TypeScript", True),
    ".go": ("Go", True),
    ".rs": ("Rust", True),
    ".java": ("Java", True),
    ".kt": ("Kotlin", True),
    ".kts": ("Kotlin", True),
    ".scala": ("Scala", True),
    ".groovy": ("Groovy", True),
    ".clj": ("Clojure", True),
    ".cljs": ("Clojure", True),
    ".cs": ("C#", True),
    ".fs": ("F#", True),
    ".vb": ("Visual Basic", True),
    ".c": ("C", True),
    ".h": ("C", True),
    ".cc": ("C++", True),
    ".cpp": ("C++", True),
    ".cxx": ("C++", True),
    ".hpp": ("C++", True),
    ".hh": ("C++", True),
    ".m": ("Objective-C", True),
    ".mm": ("Objective-C", True),
    ".swift": ("Swift", True),
    ".rb": ("Ruby", True),
    ".erb": ("Ruby", True),
    ".php": ("PHP", True),
    ".pl": ("Perl", True),
    ".pm": ("Perl", True),
    ".lua": ("Lua", True),
    ".r": ("R", True),
    ".jl": ("Julia", True),
    ".dart": ("Dart", True),
    ".ex": ("Elixir", True),
    ".exs": ("Elixir", True),
    ".erl": ("Erlang", True),
    ".hs": ("Haskell", True),
    ".ml": ("OCaml", True),
    ".elm": ("Elm", True),
    ".zig": ("Zig", True),
    ".nim": ("Nim", True),
    ".sol": ("Solidity", True),
    ".vue": ("Vue", True),
    ".svelte": ("Svelte", True),
    ".astro": ("Astro", True),
    ".sh": ("Shell", True),
    ".bash": ("Shell", True),
    ".zsh": ("Shell", True),
    ".ps1": ("PowerShell", True),
    ".psm1": ("PowerShell", True),
    ".sql": ("SQL", True),
    ".tf": ("HCL", True),
    ".hcl": ("HCL", True),
    ".bicep": ("Bicep", True),
    ".apex": ("Apex", True),
    ".cls": ("Apex", True),
    ".abap": ("ABAP", True),
    ".cob": ("COBOL", True),
    ".cbl": ("COBOL", True),
    ".f90": ("Fortran", True),
    ".proto": ("Protocol Buffers", False),
    ".graphql": ("GraphQL", False),
    ".gql": ("GraphQL", False),
    ".html": ("HTML", False),
    ".htm": ("HTML", False),
    ".css": ("CSS", False),
    ".scss": ("SCSS", False),
    ".sass": ("Sass", False),
    ".less": ("Less", False),
    ".md": ("Markdown", False),
    ".mdx": ("MDX", False),
    ".mdc": ("Markdown", False),
    ".rst": ("reStructuredText", False),
    ".yml": ("YAML", False),
    ".yaml": ("YAML", False),
    ".json": ("JSON", False),
    ".toml": ("TOML", False),
    ".xml": ("XML", False),
    ".ini": ("INI", False),
    ".csv": ("CSV", False),
    ".j2": ("Jinja", False),
    ".jinja": ("Jinja", False),
    ".hbs": ("Handlebars", False),
    ".prisma": ("Prisma", False),
    ".dockerfile": ("Dockerfile", False),
}

FILENAMES: dict[str, tuple[str, bool]] = {
    "dockerfile": ("Dockerfile", False),
    "containerfile": ("Dockerfile", False),
    "makefile": ("Makefile", False),
    "jenkinsfile": ("Groovy", True),
    "rakefile": ("Ruby", True),
    "gemfile": ("Ruby", False),
    "vagrantfile": ("Ruby", False),
}

_GENERATED = re.compile(
    r"(\.min\.(js|css)$|\.bundle\.js$|\.map$|(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|"
    r"poetry\.lock|uv\.lock|Cargo\.lock|go\.sum|composer\.lock|Gemfile\.lock|Pipfile\.lock)$|"
    r"_pb2\.py$|\.pb\.go$|\.generated\.)",
    re.IGNORECASE,
)

MAX_COUNT_BYTES = 512_000


def language_for(path: str) -> tuple[str, bool] | None:
    name = path.rsplit("/", 1)[-1].lower()
    if name in FILENAMES:
        return FILENAMES[name]
    if name.startswith("dockerfile"):
        return ("Dockerfile", False)
    dot = name.rfind(".")
    return EXTENSIONS.get(name[dot:]) if dot != -1 else None


def analyze_languages(files: RepoFiles) -> tuple[list[LanguageStat], str | None, int]:
    """Returns (language stats sorted by lines, primary programming language, total lines)."""
    counts: dict[str, list[int]] = {}
    programming: set[str] = set()
    total = 0
    for entry in files.files:
        lang = language_for(entry.path)
        if not lang or _GENERATED.search(entry.path) or entry.size > MAX_COUNT_BYTES:
            continue
        text = files.read(entry.path, MAX_COUNT_BYTES)
        if text is None:
            continue
        lines = text.count("\n") + (1 if text and not text.endswith("\n") else 0)
        bucket = counts.setdefault(lang[0], [0, 0])
        bucket[0] += 1
        bucket[1] += lines
        total += lines
        if lang[1]:
            programming.add(lang[0])
    stats = [
        LanguageStat(
            name=name, files=f, lines=ln, percent=round(100 * ln / total, 1) if total else 0.0
        )
        for name, (f, ln) in counts.items()
    ]
    stats.sort(key=lambda s: s.lines, reverse=True)
    primary = next((s.name for s in stats if s.name in programming), None)
    return stats, primary, total
