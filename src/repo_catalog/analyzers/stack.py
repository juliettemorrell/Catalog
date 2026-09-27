"""Derive the technology stack, capabilities and repo structure from files + manifests."""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, cast

from ..fs import FileEntry, RepoFiles
from ..models import LanguageStat, Package, Stack, Structure
from .languages import EXTENSIONS, analyze_languages
from .manifests import (
    NON_PRODUCT_DIR,
    ManifestResult,
    _cargo,
    _composer,
    _csproj,
    _gemfile,
    _go_mod,
    _gradle,
    _package_json,
    _pom,
    _pyproject,
    _requirements,
)
from .purls import PACKAGE_ECOSYSTEMS
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


# Third-party code copied into the repo: it says nothing about the repo's own stack or APIs.
VENDORED = re.compile(
    r"(^|/)(vendor|vendored|third[_-]?party|external|node_modules|bower_components)/|"
    r"(^|/)(opentelemetry/proto|google/(api|protobuf|rpc|type|longrunning)|"
    r"grpc/(health|reflection|binlog|channelz)|envoy|validate|gogoproto|protoc-gen-openapiv2)/",
    re.I,
)
# Folders whose packages support the product rather than being it: docs sites, demos...
AUX_DIR = re.compile(
    r"(^|/)(docs?(?:[_-]src)?|www|website|site|documentation|demos?|cookbooks?|tutorials?|"
    r"scripts|tools|hack|bench|fuzz|[^/]*(?:examples?|samples?|demos?))(/|$)",
    re.I,
)
# Test-only manifests: they reveal the testing stack, never the product stack.
_TEST_MANIFEST_DIR = re.compile(
    r"(^|/)(tests?|__tests__|e2e|spec|integration[-_]?tests?|[^/]*\.tests?)/", re.I
)
_TEST_PARSERS: dict[str, Callable[[str, str, ManifestResult, RepoFiles], None]] = {
    "package.json": _package_json,
    "pyproject.toml": _pyproject,
    "go.mod": _go_mod,
    "cargo.toml": _cargo,
    "pom.xml": _pom,
    "build.gradle": _gradle,
    "build.gradle.kts": _gradle,
    "gemfile": _gemfile,
    "composer.json": _composer,
}
_PRISMA_PROVIDER = {
    "postgresql": "PostgreSQL",
    "postgres": "PostgreSQL",
    "cockroachdb": "PostgreSQL",
    "mysql": "MySQL",
    "sqlite": "SQLite",
    "sqlserver": "SQL Server",
    "mongodb": "MongoDB",
}
_PROTO_SERVICE_RX = re.compile(r"^[ \t]*service\s+\w+\s*\{", re.M)
_OPENAPI_HEAD = re.compile(
    r"^(?:\s*\{)?\s{0,4}[\"']?(?:openapi|swagger)[\"']?\s*:\s*[\"']?[23]\.\d", re.M
)
_NOT_SPEC_NAMES = frozenset(
    {
        "package.json",
        "package-lock.json",
        "composer.json",
        "composer.lock",
        "tsconfig.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "appsettings.json",
        "launchsettings.json",
        "packages.lock.json",
    }
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


_SERVICE_CATEGORIES = {"databases", "messaging", "observability"}


def analyze_stack(files: RepoFiles, manifests: ManifestResult) -> StackResult:
    col = _Collector()

    runtime_deps = [d for d in manifests.dependencies if d.scope in ("runtime", "peer", "optional")]
    core: set[str] = set()  # labels backed by runtime deps or product files: drive repo_type
    product_stack = {"frameworks", "databases", "messaging", "auth"}
    for dep in manifests.dependencies:
        if dep.ecosystem in ("docker", "helm"):
            # a postgres/redis/kafka image or chart is a service the repo runs with;
            # other images (node, python...) are runtimes, not technology choices
            base = dep.name.rsplit("/", 1)[-1]
            for rule in match_dependency(base):
                if rule.category in _SERVICE_CATEGORIES and dep.scope != "build":
                    col.add_rule(rule)
            continue
        if dep.ecosystem == "terraform":
            # providers and registry modules reveal the cloud the infrastructure targets
            for rule in match_dependency(dep.name):
                if rule.category == "cloud":
                    col.add_rule(rule)
            continue
        if dep.ecosystem not in PACKAGE_ECOSYSTEMS:
            continue  # actions, pre-commit hooks: tooling, not code deps
        for rule in match_dependency(dep.name):
            # dev/build-only frameworks are tooling, and indirect deps are not the repo's choice
            if dep.scope == "transitive" or (
                dep.scope in ("dev", "build") and rule.category in product_stack
            ):
                continue
            col.add_rule(rule)
            # a docs site or demo app does not decide what the repo is
            if dep.scope == "runtime" and not AUX_DIR.search(dep.manifest):
                core.add(rule.label)
    _test_manifest_tools(files, col)

    for rule, patterns in FILE_RULES:
        hits = [
            f
            for f in files.glob(*patterns)
            if not NON_PRODUCT_DIR.search(f.path) and not VENDORED.search(f.path)
        ]
        if hits:
            col.add_rule(rule)
            if any(not AUX_DIR.search(f.path) for f in hits):
                core.add(rule.label)
    _prisma_databases(files, col, core)

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
    ci_text = "\n".join(workflow_texts.values()) + (files.read(".gitlab-ci.yml") or "")
    if re.search(r"\bcargo\s+(?:\+\S+\s+)?fmt\b|\brustfmt\b", ci_text):
        col.add("linting", "rustfmt")
    if re.search(r"\bcargo\s+(?:\+\S+\s+)?clippy\b", ci_text):
        col.add("linting", "Clippy")
    if re.search(r"\bcheckstyle(?::check)?\b", ci_text):
        col.add("linting", "Checkstyle")
    if re.search(r"(?:vendor/bin/|\s)pint\b", ci_text) and files.exists("composer.json"):
        col.add("linting", "Laravel Pint")

    # a gRPC runtime is a server framework only when the repo defines its own services
    if "gRPC" in col.values["libraries"] and _own_proto_services(files):
        col.values["libraries"].remove("gRPC")
        if "rpc-client" in col.capabilities:
            col.capabilities.remove("rpc-client")
        col.add("frameworks", "gRPC", ["rpc-api"])
    openapi_docs = _openapi_by_content(files)
    if openapi_docs:
        col.add("libraries", "OpenAPI", ["rest-api", "api-spec"])

    if _is_kubernetes(files):
        col.add("infrastructure", "Kubernetes", ["kubernetes"])
    if any(d.name.lower() == "boto3" for d in runtime_deps) and _grep_any(
        files, ("*.py",), r"['\"]bedrock(-runtime|-agent-runtime)?['\"]"
    ):
        col.add("ai", "Amazon Bedrock", ["llm"])

    langs, primary, total_lines = analyze_languages(files)
    primary = _primary_language(files, langs, primary)

    stack = Stack(
        primary_language=primary,
        languages=langs[:15],
        runtimes=manifests.runtimes,
        package_managers=sorted(manifests.package_managers),
        **cast(dict[str, Any], {f: col.values[f] for f in _STACK_FIELDS}),
    )
    structure = _structure(files, manifests, stack, total_lines, core, openapi_docs)
    caps = col.capabilities
    if structure.api_specs and "api-spec" not in caps:
        caps.append("api-spec")
    return StackResult(
        stack=stack, structure=structure, capabilities=sorted(caps), workflow_texts=workflow_texts
    )


def _test_manifest_tools(files: RepoFiles, col: _Collector) -> None:
    """Test projects (tests/Foo.Tests/Foo.Tests.csproj, e2e/package.json) are skipped as
    product manifests, but the test frameworks they use are the repo's testing stack."""
    scratch = ManifestResult()
    seen = 0
    for entry in files.files:
        if seen >= 50:
            break
        name = entry.name.lower()
        if not _TEST_MANIFEST_DIR.search(entry.path) or re.search(
            r"(^|/)(examples?|samples?|fixtures?|testdata|node_modules)/", entry.path, re.I
        ):
            continue
        parser = _TEST_PARSERS.get(name)
        if parser is None and name.endswith((".csproj", ".fsproj", ".vbproj")):
            parser = _csproj
        if parser is None and name.startswith("requirements") and name.endswith(".txt"):
            parser = _requirements
        if parser is None:
            continue
        seen += 1
        text = files.read(entry.path)
        if not text:
            continue
        try:
            parser(entry.path, text, scratch, files)
        except Exception:  # a broken test manifest never fails the scan
            continue
    for dep in scratch.dependencies:
        for rule in match_dependency(dep.name):
            if rule.category == "testing":
                col.add_rule(rule)


def _prisma_databases(files: RepoFiles, col: _Collector, core: set[str]) -> None:
    for entry, text in files.iter_text(files.glob("**/schema.prisma", "**/prisma/*.prisma")[:20]):
        if NON_PRODUCT_DIR.search(entry.path):
            continue
        for block in re.findall(r"\bdatasource\s+\w+\s*\{([^}]*)\}", text):
            m = re.search(r"\bprovider\s*=\s*\"(\w+)\"", block)
            label = _PRISMA_PROVIDER.get(m.group(1).lower()) if m else None
            if label:
                kind = "document-database" if label == "MongoDB" else "sql-database"
                col.add("databases", label, [kind])
                core.add(label)


def own_proto(path: str) -> bool:
    """A .proto the repo owns (not an example, test fixture or vendored third-party copy)."""
    return not NON_PRODUCT_DIR.search(path) and not VENDORED.search(path)


def _own_proto_services(files: RepoFiles) -> bool:
    protos = [f for f in files.glob("**/*.proto") if own_proto(f.path)][:200]
    return any(_PROTO_SERVICE_RX.search(text) for _, text in files.iter_text(protos))


def _openapi_by_content(files: RepoFiles) -> list[str]:
    """OpenAPI/Swagger documents named after the service (Catalog.API.json), found by
    their top-level ``openapi``/``swagger`` key. Only small files, only the head is read."""
    named = re.compile(r"^(openapi|swagger)", re.I)
    candidates: list[FileEntry] = [
        f
        for f in files.files
        if f.suffix in (".json", ".yaml", ".yml")
        and 20 < f.size < 5_000_000
        and f.name.lower() not in _NOT_SPEC_NAMES
        and not named.match(f.name)
        and not f.path.startswith((".github/", ".vscode/", ".devcontainer/"))
        and not NON_PRODUCT_DIR.search(f.path)
        and not VENDORED.search(f.path)
    ][:3000]
    out = []
    for entry in candidates:
        head = files.read(entry.path, 4096, cache=False) or ""
        if _OPENAPI_HEAD.search(head):
            out.append(entry.path)
    return out[:50]


_PROGRAMMING = {name for name, prog in EXTENSIONS.values() if prog}


def _primary_language(
    files: RepoFiles, langs: list[LanguageStat], primary: str | None
) -> str | None:
    """Gradle Kotlin DSL build scripts (*.gradle.kts) do not make a Java service Kotlin."""
    if primary != "Kotlin" or any(f.suffix == ".kt" for f in files.files):
        return primary
    return next((s.name for s in langs if s.name in _PROGRAMMING and s.name != "Kotlin"), primary)


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
    files: RepoFiles,
    man: ManifestResult,
    stack: Stack,
    total_lines: int,
    core: set[str],
    extra_specs: list[str] | None = None,
) -> Structure:
    packages = _dedupe_packages(man.packages)
    # a workspace declaration alone (one uv member, examples as members) is not a monorepo:
    # it takes at least two product packages beside the root
    units = product_units(files, packages)
    is_monorepo = len(units) >= 2
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
        if not VENDORED.search(f.path)
    )
    api_specs = sorted(set(api_specs) | set(extra_specs or []))[:50]
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
    structure.repo_type = classify_repo(
        stack, structure, man, core, root_kind=_root_kind(files, packages), units=len(units)
    )
    if _EXAMPLES_REPO.search(files.root.name) and structure.repo_type != "empty":
        structure.repo_type = "examples"  # acme-examples, *-samples, cookbooks
    return structure


_EXAMPLES_REPO = re.compile(
    r"(^|[-_.])(examples?|samples?|cookbooks?|demos?|tutorials?|recipes|workshops?)([-_.]|$)",
    re.I,
)


def product_units(files: RepoFiles, packages: list[Package]) -> list[str]:
    """Independent product packages beside the root: docs sites, examples, tests and
    benchmarks do not count; nested packages belong to their parent; the projects of one
    .NET solution or one Maven/Gradle build are a single product."""
    units: list[str] = []
    solution = bool(files.glob("*.sln", "*.slnx"))
    jvm_build = any(files.exists(n) for n in ("pom.xml", "settings.gradle", "settings.gradle.kts"))
    paths = sorted(
        p.path
        for p in packages
        if p.path
        and not AUX_DIR.search(p.path + "/")
        and not NON_PRODUCT_DIR.search(p.path + "/")
        and not VENDORED.search(p.path + "/")
        and not (p.ecosystem == "nuget" and solution)
        and not (p.ecosystem in ("maven", "gradle") and jvm_build)
    )
    for path in paths:
        if not any(path.startswith(u + "/") for u in units):
            units.append(path)
    if solution and any(p.ecosystem == "nuget" for p in packages):
        units.append("<solution>")
    return units


def _root_kind(files: RepoFiles, packages: list[Package]) -> str | None:
    """What the root package is, when it is clearly a product of its own: "cli" or
    "library". None for a bare workspace root (private package.json, no code)."""
    try:
        return _root_kind_inner(files, packages)
    except Exception:  # a malformed root manifest only loses the hint
        return None


def _root_kind_inner(files: RepoFiles, packages: list[Package]) -> str | None:
    roots = {p.ecosystem for p in packages if p.path == ""}
    if "npm" in roots:
        data = json.loads(files.read("package.json") or "{}")
        if isinstance(data, dict) and data.get("bin"):
            return "cli"
    if "cargo" in roots:
        cargo = tomllib.loads(files.read("Cargo.toml") or "")
        if cargo.get("bin") or files.exists("src/main.rs"):
            return "cli"
        if files.exists("src/lib.rs"):
            return "library"
    if "pypi" in roots:
        py = tomllib.loads(files.read("pyproject.toml") or "")
        project = py.get("project") if isinstance(py.get("project"), dict) else {}
        if project and not re.search(r"workspace|monorepo", str(project.get("name")), re.I):
            name = str(project.get("name") or "").replace("-", "_").lower()
            code = [
                f
                for f in files.files
                if f.suffix == ".py"
                and f.parts[0] in ("src", name)
                and not NON_PRODUCT_DIR.search(f.path)
            ]
            if code:
                return "library"
    if "go" in roots:
        if files.exists("main.go"):
            return "cli" if files.glob("cmd/*/main.go") or not files.glob("*_test.go") else None
        if any(f.suffix == ".go" and f.depth == 0 for f in files.files):
            return "library"
    if "npm" in roots:
        data = json.loads(files.read("package.json") or "{}")
        if (
            isinstance(data, dict)
            and data.get("private") not in (True, "true")
            and (data.get("main") or data.get("exports") or data.get("module"))
        ):
            return "library"
    return None


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
_MOBILE = {"React Native", "Expo", "Flutter", "Ionic", "Android", "Jetpack Compose", ".NET MAUI"}
_DATA_PIPELINE = {"Airflow", "dbt", "Dagster", "Prefect"}
_DATA_APPS = {"Streamlit", "Gradio", "Dash", "Panel"}
_CLI = {"Typer", "Click", "Cobra", "Clap"}


def classify_repo(
    stack: Stack,
    structure: Structure,
    man: ManifestResult,
    core: set[str] | None = None,
    *,
    root_kind: str | None = None,
    units: int | None = None,
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
    md = langs.get("Markdown", 0) + langs.get("MDX", 0)
    if md > 50 and code_pct < 40:
        return "docs"  # awesome lists and prompt/rule collections, whatever tooling they ship
    # the type is the product's: a CLI or library root with helper crates stays a CLI/library
    # a frontend/ + backend/ pair without monorepo tooling is one full-stack app
    app_pair = (
        bool(fw & _FRONTEND and fw & _BACKEND)
        and (units or 0) <= 3
        and not set(stack.build_tools) & {"Turborepo", "Nx", "Lerna", "Rush"}
    )
    if structure.is_monorepo and root_kind is None and not app_pair:
        return "monorepo"
    if root_kind == "cli" and (structure.is_monorepo or man.workspaces):
        return "cli"
    # a published library that merely depends on a web framework (an SDK with an ASGI
    # transport) is still a library; services ship a container or have no package root
    if root_kind == "library" and not fw & _FRONTEND and "Docker" not in stack.infrastructure:
        return "library"
    if fw & _MOBILE and not fw & _BACKEND:  # a MAUI client beside the services: full stack
        return "mobile-app"
    if fw & {"Electron", "Tauri"}:
        return "desktop-app"
    pipeline = (core if core is not None else set(stack.libraries)) & _DATA_PIPELINE
    if pipeline and not fw & (_FRONTEND | _BACKEND):
        return "data-pipeline"
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
