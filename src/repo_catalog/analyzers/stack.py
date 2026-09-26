"""Derive the technology stack, capabilities and repo structure from files + manifests."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from ..fs import RepoFiles
from ..models import Package, Stack, Structure
from .languages import analyze_languages
from .manifests import NON_PRODUCT_DIR, ManifestResult
from .rules import FILE_RULES, Rule, match_dependency

_STACK_FIELDS = {
    "frameworks",
    "libraries",
    "testing",
    "linting",
    "databases",
    "messaging",
    "cloud",
    "infrastructure",
    "ci_cd",
    "observability",
    "auth",
    "ai",
    "build_tools",
}

# pyproject [tool.X] sections that reveal tooling
_PYPROJECT_TOOLS = {
    "ruff": ("linting", "Ruff"),
    "black": ("linting", "Black"),
    "isort": ("linting", "isort"),
    "mypy": ("linting", "mypy"),
    "pyright": ("linting", "Pyright"),
    "pylint": ("linting", "Pylint"),
    "pytest": ("testing", "pytest"),
    "coverage": ("testing", "coverage.py"),
}

# GitHub Actions `uses:` prefixes that reveal deploy targets and practices
_ACTION_HINTS = {
    "aws-actions/": ("cloud", "AWS"),
    "google-github-actions/": ("cloud", "Google Cloud"),
    "azure/": ("cloud", "Azure"),
    "docker/build-push-action": ("infrastructure", "Docker"),
    "hashicorp/setup-terraform": ("infrastructure", "Terraform"),
    "github/codeql-action": ("linting", "CodeQL"),
    "codecov/codecov-action": ("linting", "Codecov"),
    "snyk/actions": ("linting", "Snyk"),
    "sonarsource/": ("linting", "SonarQube"),
    "actions/deploy-pages": ("cloud", "GitHub Pages"),
    "peaceiris/actions-gh-pages": ("cloud", "GitHub Pages"),
    "vercel/": ("cloud", "Vercel"),
    "cloudflare/wrangler-action": ("cloud", "Cloudflare Workers"),
    "superfly/flyctl-actions": ("cloud", "Fly.io"),
    "googleapis/release-please-action": ("ci_cd", "release-please"),
    "goreleaser/goreleaser-action": ("ci_cd", "GoReleaser"),
}

_ENTRYPOINTS = (
    "main.py",
    "app.py",
    "manage.py",
    "wsgi.py",
    "asgi.py",
    "server.py",
    "__main__.py",
    "main.go",
    "main.rs",
    "main.ts",
    "main.js",
    "server.ts",
    "server.js",
    "index.ts",
    "index.js",
    "app.ts",
    "app.js",
    "program.cs",
    "application.java",
    "main.kt",
    "main.dart",
)

_DOCS_PATTERNS = (
    "docs/**",
    "doc/**",
    "**/adr/**",
    "**/adrs/**",
    "**/decisions/**",
    "mkdocs.yml",
    "**/*.md",
)


@dataclass
class StackResult:
    stack: Stack
    structure: Structure
    capabilities: list[str]
    workflow_texts: dict[str, str] = field(default_factory=dict)


class _Collector:
    def __init__(self) -> None:
        self.values: dict[str, list[str]] = {f: [] for f in _STACK_FIELDS}
        self.capabilities: list[str] = []

    def add(self, category: str, label: str, caps: Iterable[str] = ()) -> None:
        if category in self.values and label not in self.values[category]:
            self.values[category].append(label)
        for cap in caps:
            if cap not in self.capabilities:
                self.capabilities.append(cap)

    def add_rule(self, rule: Rule) -> None:
        self.add(rule.category, rule.label, rule.capabilities)


def analyze_stack(files: RepoFiles, manifests: ManifestResult) -> StackResult:
    col = _Collector()

    runtime_deps = [d for d in manifests.dependencies if d.scope in ("runtime", "peer", "optional")]
    core: set[str] = set()  # labels backed by runtime deps or product files: drive repo_type
    product_stack = {"frameworks", "databases", "messaging", "auth"}
    for dep in manifests.dependencies:
        for rule in match_dependency(dep.name):
            # dev/build-only frameworks are tooling, and indirect deps are not the repo's choice
            if dep.scope == "transitive" or (
                dep.scope in ("dev", "build") and rule.category in product_stack
            ):
                continue
            col.add_rule(rule)
            if dep.scope == "runtime":
                core.add(rule.label)

    for rule, patterns in FILE_RULES:
        if any(not NON_PRODUCT_DIR.search(f.path) for f in files.glob(*patterns)):
            col.add_rule(rule)
            core.add(rule.label)

    pyproject = files.read("pyproject.toml") or ""
    for tool, (cat, label) in _PYPROJECT_TOOLS.items():
        if re.search(rf"^\[tool\.{tool}(\.|\])", pyproject, re.M):
            col.add(cat, label)
    if files.exists("setup.cfg") and "[flake8]" in (files.read("setup.cfg") or ""):
        col.add("linting", "Flake8")
    if any(f.name == "tsconfig.json" for f in files.files):
        col.add("linting", "TypeScript")

    workflow_texts: dict[str, str] = {}
    for entry, text in files.iter_text(
        files.glob(".github/workflows/*.yml", ".github/workflows/*.yaml")
    ):
        workflow_texts[entry.path] = text
        for uses in re.findall(r"uses:\s*['\"]?([\w.-]+/[\w./-]+)", text):
            for prefix, (cat, label) in _ACTION_HINTS.items():
                if uses.lower().startswith(prefix):
                    col.add(cat, label)

    if _is_kubernetes(files):
        col.add("infrastructure", "Kubernetes", ["kubernetes"])
    if any(d.name.lower() == "boto3" for d in runtime_deps) and _grep_any(
        files, ("*.py",), r"['\"]bedrock(-runtime|-agent-runtime)?['\"]"
    ):
        col.add("ai", "Amazon Bedrock", ["llm"])

    langs, primary, total_lines = analyze_languages(files)

    stack = Stack(
        primary_language=primary,
        languages=langs[:15],
        runtimes=manifests.runtimes,
        package_managers=sorted(manifests.package_managers),
        **{f: col.values[f] for f in _STACK_FIELDS},
    )
    structure = _structure(files, manifests, stack, total_lines, core)
    caps = col.capabilities
    if structure.api_specs and "api-spec" not in caps:
        caps.append("api-spec")
    return StackResult(
        stack=stack, structure=structure, capabilities=sorted(caps), workflow_texts=workflow_texts
    )


def _is_kubernetes(files: RepoFiles) -> bool:
    candidates = [
        f
        for f in files.files
        if f.suffix in (".yaml", ".yml")
        and re.search(
            r"(^|/)(k8s|kube|kubernetes|manifests|deploy|deployment|charts|helm)/", f.path, re.I
        )
    ]
    for _, text in files.iter_text(candidates[:200], 200_000):
        if re.search(
            r"^kind:\s*(Deployment|StatefulSet|Service|Ingress|CronJob|DaemonSet)\b", text, re.M
        ):
            return True
    return False


def _grep_any(files: RepoFiles, globs: tuple[str, ...], pattern: str) -> bool:
    rx = re.compile(pattern)
    candidates = [f for f in files.glob(*(f"**/{g}" for g in globs)) if f.size < 300_000]
    return any(rx.search(text) for _, text in files.iter_text(candidates[:2000]))


def _structure(
    files: RepoFiles, man: ManifestResult, stack: Stack, total_lines: int, core: set[str]
) -> Structure:
    packages = _dedupe_packages(man.packages)
    is_monorepo = (
        man.workspaces
        or len(packages) >= 3
        or any(t in stack.build_tools for t in ("Turborepo", "Nx", "Lerna", "pnpm workspaces"))
    )
    top = sorted({f.parts[0] + ("/" if len(f.parts) > 1 else "") for f in files.files})
    entrypoints = sorted(
        f.path
        for f in files.files
        if f.name.lower() in _ENTRYPOINTS
        and f.depth <= 3
        and not f.path.startswith(("test", "tests/", "examples/"))
    )[:25]
    entrypoints += [f"bin:{b}" for b in man.bins[:10]]
    entrypoints += sorted(f.path for f in files.glob("cmd/*/main.go"))[:10]
    api_specs = sorted(
        f.path
        for f in files.glob(
            "**/openapi*.{yaml,yml,json}",
            "**/swagger*.{yaml,yml,json}",
            "**/*.proto",
            "**/schema.graphql",
            "**/*.graphqls",
            "**/asyncapi*.{yaml,yml}",
        )
    )[:50]
    dockerfiles = sorted(
        f.path for f in files.glob("**/Dockerfile", "**/Dockerfile.*", "**/*.dockerfile")
    )[:25]
    docs = sorted(
        {
            (f.parts[0] + "/") if f.depth else f.path
            for f in files.glob(*_DOCS_PATTERNS)
            if f.depth == 0 or f.parts[0].lower() in {"docs", "doc", "adr", "adrs"}
        }
    )
    structure = Structure(
        is_monorepo=is_monorepo,
        packages=packages[:100],
        entrypoints=sorted(set(entrypoints)),
        api_specs=api_specs,
        dockerfiles=dockerfiles,
        top_level=top[:80],
        docs=docs[:40],
        file_count=len(files.files),
        total_lines=total_lines,
    )
    structure.repo_type = classify_repo(stack, structure, man, core)
    return structure


def _dedupe_packages(pkgs: list[Package]) -> list[Package]:
    seen: set[tuple[str, str]] = set()
    out: list[Package] = []
    for p in sorted(pkgs, key=lambda p: (p.path.count("/"), p.path)):
        key = (p.ecosystem, p.name)
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


_FRONTEND = {
    "React",
    "Next.js",
    "Vue",
    "Nuxt",
    "Angular",
    "Svelte",
    "SvelteKit",
    "Solid",
    "Astro",
    "Gatsby",
    "Remix",
    "Preact",
    "Qwik",
    "Blazor",
}
_BACKEND = {
    "Express",
    "Fastify",
    "NestJS",
    "Koa",
    "Hono",
    "Hapi",
    "FastAPI",
    "Django",
    "Flask",
    "Starlette",
    "Litestar",
    "Spring Boot",
    "Spring",
    "Quarkus",
    "Micronaut",
    "Ktor",
    "Gin",
    "Echo",
    "Fiber",
    "Chi",
    "Actix",
    "Axum",
    "Rocket",
    "Ruby on Rails",
    "Sinatra",
    "Laravel",
    "Symfony",
    "ASP.NET Core",
    "tRPC",
    "Apollo Server",
    "GraphQL Yoga",
    "gRPC",
}
_MOBILE = {"React Native", "Expo", "Flutter", "Ionic"}
_DATA_APPS = {"Streamlit", "Gradio", "Dash", "Panel"}
_CLI = {"Typer", "Click", "Cobra", "Clap"}


def classify_repo(
    stack: Stack, structure: Structure, man: ManifestResult, core: set[str] | None = None
) -> str:
    # only frameworks the repo itself runs on (not peer/optional/indirect deps) decide the type
    fw = set(stack.frameworks) & core if core is not None else set(stack.frameworks)
    langs = {s.name: s.percent for s in stack.languages}
    code_pct = sum(
        p
        for n, p in langs.items()
        if n
        not in {"Markdown", "MDX", "YAML", "JSON", "TOML", "HCL", "reStructuredText", "CSV", "XML"}
    )
    if structure.file_count == 0:
        return "empty"
    if structure.is_monorepo:
        return "monorepo"
    if fw & _MOBILE:
        return "mobile-app"
    if fw & {"Electron", "Tauri"}:
        return "desktop-app"
    if fw & _DATA_APPS:
        return "data-app"
    if fw & _FRONTEND and fw & _BACKEND:
        return "full-stack-app"
    if fw & _FRONTEND:
        return "web-app"
    if fw & _BACKEND:
        return "service"
    if langs.get("HCL", 0) > 30 or (stack.infrastructure and code_pct < 20):
        return "infrastructure"
    if langs.get("Jupyter Notebook", 0) > 30:
        return "data-science"
    if fw & _CLI or man.bins:
        return "cli"
    if code_pct < 15 and langs.get("Markdown", 0) + langs.get("MDX", 0) > 50:
        return "docs"
    if structure.packages:
        return "library"
    if "Docker" in (core if core is not None else set(stack.infrastructure)):
        return "service"
    return "scripts" if code_pct else "other"
