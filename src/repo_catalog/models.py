"""Typed records emitted by the scanner.

These models are the contract between the scanner, the SQLite/JSON outputs, the
frontend and the MCP server. JSON Schemas are generated from them into ``schema/``
so downstream consumers (SDLC agents, dashboards) can validate what they read.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "1.0"


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --------------------------------------------------------------------------- #
# General repository catalog
# --------------------------------------------------------------------------- #


class Dependency(_Model):
    name: str
    version: str | None = None  # as declared (a range such as ^1.2 or an exact pin)
    # npm, pypi, go, cargo, maven, gem, composer, nuget, pub, swift, cocoapods, hex, cran,
    # conda, bazel, vcpkg, conan, jsr, terraform, helm, docker, github-actions, pre-commit,
    # ansible-galaxy
    ecosystem: str
    # transitive: pulled in by another dependency (lockfile entries, Go "// indirect")
    scope: Literal["runtime", "dev", "optional", "peer", "build", "transitive"] = "runtime"
    manifest: str  # path of the manifest (or lockfile, for transitive deps) it came from
    resolved: str | None = None  # exact version from a lockfile, when there is one
    purl: str | None = None  # package URL (https://github.com/package-url/purl-spec)
    vulns: list[str] = Field(default_factory=list)  # known advisories (OSV ids), --osv


class DependencySummary(_Model):
    direct: int = 0
    transitive: int = 0
    ecosystems: dict[str, int] = Field(default_factory=dict)  # direct deps per ecosystem
    lockfile_coverage: float = 0.0  # share of direct package deps with a resolved version
    vulnerable: int = 0  # deps with known advisories (--osv)


class Package(_Model):
    """A publishable/buildable unit inside the repo (monorepos have several)."""

    name: str
    path: str
    ecosystem: str
    version: str | None = None
    description: str | None = None
    private: bool | None = None


class LanguageStat(_Model):
    name: str
    files: int
    lines: int
    percent: float


class RuntimeVersion(_Model):
    """A concrete runtime version the repo pins (Dockerfile, version file, CI, manifest)."""

    runtime: str  # python, node, java, dotnet, go, ruby, php
    version: str  # as written, e.g. "3.8", "18", "net6.0"
    path: str


class Stack(_Model):
    primary_language: str | None = None
    languages: list[LanguageStat] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    libraries: list[str] = Field(default_factory=list)  # notable, curated libraries
    runtimes: dict[str, str] = Field(default_factory=dict)  # e.g. {"node": ">=20"}
    runtime_versions: list[RuntimeVersion] = Field(default_factory=list)  # pinned versions
    package_managers: list[str] = Field(default_factory=list)
    build_tools: list[str] = Field(default_factory=list)
    testing: list[str] = Field(default_factory=list)
    linting: list[str] = Field(default_factory=list)
    databases: list[str] = Field(default_factory=list)
    messaging: list[str] = Field(default_factory=list)
    cloud: list[str] = Field(default_factory=list)
    infrastructure: list[str] = Field(default_factory=list)
    ci_cd: list[str] = Field(default_factory=list)
    observability: list[str] = Field(default_factory=list)
    auth: list[str] = Field(default_factory=list)
    ai: list[str] = Field(default_factory=list)


class Structure(_Model):
    repo_type: str = "unknown"  # service, web-app, library, cli, monorepo, infra, docs, ...
    is_monorepo: bool = False
    packages: list[Package] = Field(default_factory=list)
    entrypoints: list[str] = Field(default_factory=list)
    api_specs: list[str] = Field(default_factory=list)
    dockerfiles: list[str] = Field(default_factory=list)
    top_level: list[str] = Field(default_factory=list)
    docs: list[str] = Field(default_factory=list)
    file_count: int = 0
    total_lines: int = 0


class PracticeCheck(_Model):
    id: str
    category: str  # docs, security, quality, delivery, governance
    label: str
    passed: bool
    weight: int = 1
    evidence: str | None = None


class Practices(_Model):
    score: int = 0  # 0-100 weighted
    grade: Literal["A", "B", "C", "D", "F"] = "F"
    checks: list[PracticeCheck] = Field(default_factory=list)


class Contributor(_Model):
    name: str
    commits: int


class Ownership(_Model):
    codeowners: list[str] = Field(default_factory=list)
    top_contributors: list[Contributor] = Field(default_factory=list)
    contributor_count: int = 0
    commit_count: int = 0
    first_commit: datetime | None = None
    last_commit: datetime | None = None


class Summary(_Model):
    one_liner: str | None = None  # best short description available
    readme_title: str | None = None
    readme_excerpt: str | None = None
    purpose: str | None = None  # LLM-written "what it does" (optional)
    key_features: list[str] = Field(default_factory=list)
    reuse_notes: str | None = None  # LLM-written "what could other teams borrow"
    domains: list[str] = Field(default_factory=list)  # business/technical domain tags
    source: Literal["github", "readme", "manifest", "llm", "none"] = "none"


class AIUsageSummary(_Model):
    has_ai: bool = False
    asset_count: int = 0
    asset_kinds: dict[str, int] = Field(default_factory=dict)
    ecosystems: list[str] = Field(default_factory=list)
    sdks: list[str] = Field(default_factory=list)
    models: list[str] = Field(default_factory=list)
    mcp_servers_provided: list[str] = Field(default_factory=list)
    mcp_servers_consumed: list[str] = Field(default_factory=list)


class Declared(_Model):
    """Metadata a team declared themselves (Backstage/Cortex/OpsLevel/Compass files,
    GitHub custom properties). Treated as ground truth over inferred values."""

    source_files: list[str] = Field(default_factory=list)
    name: str | None = None
    owner: str | None = None
    system: str | None = None
    domain: str | None = None
    lifecycle: str | None = None
    type: str | None = None
    tier: str | None = None
    tags: list[str] = Field(default_factory=list)
    links: list[dict[str, str]] = Field(default_factory=list)
    provides_apis: list[str] = Field(default_factory=list)
    consumes_apis: list[str] = Field(default_factory=list)
    depends_on: list[str] = Field(default_factory=list)
    custom_properties: dict[str, Any] = Field(default_factory=dict)


Severity = Literal["high", "medium", "low"]


class Flag(_Model):
    """Something worth a human's attention: a risk, a gap or upcoming maintenance.

    Flags never carry secret values: only what was found, and where."""

    id: str  # e.g. "committed-secret", "eol-runtime", "mcp-unpinned-package"
    category: Literal["security", "maintenance", "ownership", "ai-governance"]
    severity: Severity
    message: str
    path: str | None = None
    line: int | None = None


ReusableKind = Literal[
    "action",  # GitHub Action (action.yml)
    "reusable-workflow",  # workflow with on: workflow_call
    "terraform-module",
    "helm-chart",
    "template",  # cookiecutter / copier / Backstage scaffolder / GitHub template repo
    "api",  # OpenAPI / AsyncAPI / GraphQL / protobuf contract
    "config-package",  # shared lint/format/tsconfig presets
]


class Reusable(_Model):
    """A building block other teams can adopt as-is."""

    kind: ReusableKind
    name: str
    path: str
    description: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)  # inputs, operations, version...


class CrossRef(_Model):
    """A reference from this repo to code in another repository (resolved org-wide)."""

    kind: Literal["action", "reusable-workflow", "terraform", "go-module", "git", "container"]
    target: str  # owner/repo (lowercase) or image name
    path: str  # where the reference is


class RepoLink(_Model):
    repo: str  # owner/name
    via: str  # e.g. "npm @acme/ui", "action acme/setup-env"


class Repo(_Model):
    """One entry in the general catalog."""

    id: str  # owner/name
    name: str
    owner: str
    url: str
    description: str | None = None
    homepage: str | None = None
    topics: list[str] = Field(default_factory=list)
    visibility: str | None = None
    archived: bool = False
    fork: bool = False
    is_template: bool = False
    default_branch: str | None = None
    head_sha: str | None = None
    license: str | None = None
    stars: int | None = None
    open_issues: int | None = None
    created_at: datetime | None = None
    pushed_at: datetime | None = None
    lifecycle: Literal["active", "maintained", "stale", "archived"] = "active"
    capabilities: list[str] = Field(default_factory=list)  # e.g. payments, auth, pdf-generation
    github_languages: dict[str, int] = Field(default_factory=dict)  # linguist bytes from GitHub
    declared: Declared = Field(default_factory=Declared)
    summary: Summary = Field(default_factory=Summary)
    stack: Stack = Field(default_factory=Stack)
    dependencies: list[Dependency] = Field(default_factory=list)
    dependency_summary: DependencySummary = Field(default_factory=DependencySummary)
    structure: Structure = Field(default_factory=Structure)
    practices: Practices = Field(default_factory=Practices)
    ownership: Ownership = Field(default_factory=Ownership)
    ai: AIUsageSummary = Field(default_factory=AIUsageSummary)
    flags: list[Flag] = Field(default_factory=list)
    reusables: list[Reusable] = Field(default_factory=list)
    references: list[CrossRef] = Field(default_factory=list)
    # org-wide, filled when the catalog is built (not stored in per-repo files)
    depends_on: list[RepoLink] = Field(default_factory=list)
    used_by: list[RepoLink] = Field(default_factory=list)
    scanned_at: datetime
    scanner_version: str
    scan_fingerprint: str | None = None  # scanner version + options that shape the output
    scan_errors: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# AI asset library
# --------------------------------------------------------------------------- #

AssetKind = Literal[
    "skill",  # Agent Skills (SKILL.md folder)
    "agent",  # subagent / agent definition (markdown, yaml, code)
    "command",  # slash command / reusable prompt command
    "prompt",  # prompt template or embedded system prompt
    "instructions",  # always-on context: CLAUDE.md, AGENTS.md, rules files
    "mcp-server",  # an MCP server implemented in this repo
    "mcp-config",  # MCP servers this repo configures/consumes
    "settings",  # agent tool settings: permission policy, auto-approved MCP servers
    "hook",  # agent lifecycle hooks
    "plugin",  # plugin / marketplace manifest bundling other assets
    "eval",  # evals / prompt tests
    "workflow",  # agent orchestration code (LangGraph, CrewAI, SDK agents, CI agents)
    "sdk-usage",  # code calling an LLM provider SDK
]


class AssetFile(_Model):
    path: str
    size: int


class AIAsset(_Model):
    """One entry in the AI asset library."""

    id: str  # stable hash of repo + path + name
    kind: AssetKind
    ecosystem: str  # claude-code, cursor, copilot, agents-md, langchain, crewai, generic, ...
    name: str
    title: str | None = None
    description: str | None = None
    repo: str
    path: str
    url: str
    scope: Literal["repo", "plugin", "package", "user"] = "repo"
    confidence: Literal["high", "medium", "low"] = "high"
    detector: str  # which rule found it
    # Parsed metadata
    frontmatter: dict[str, Any] = Field(default_factory=dict)
    tools: list[str] = Field(default_factory=list)
    models: list[str] = Field(default_factory=list)
    providers: list[str] = Field(default_factory=list)
    triggers: list[str] = Field(default_factory=list)  # globs, events, slash names, when-to-use
    arguments: list[str] = Field(default_factory=list)
    mcp_servers: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    license: str | None = None
    version: str | None = None
    # Content
    content: str | None = None  # full text (capped), markdown or source
    content_truncated: bool = False
    excerpt: str | None = None
    headings: list[str] = Field(default_factory=list)
    files: list[AssetFile] = Field(default_factory=list)  # bundled files (skills/plugins)
    line_count: int = 0
    word_count: int = 0
    token_estimate: int = 0
    content_sha: str | None = None
    # Provenance
    last_modified: datetime | None = None
    last_author: str | None = None
    commit_count: int | None = None
    # Quality + enrichment
    quality_score: int = 0  # 0-100 heuristic
    quality_notes: list[str] = Field(default_factory=list)
    summary: str | None = None  # LLM-written
    use_cases: list[str] = Field(default_factory=list)  # LLM-written
    category: str | None = None  # LLM-assigned, e.g. "code-review", "testing"
    duplicates: list[str] = Field(default_factory=list)  # ids of assets with same content
    flags: list[Flag] = Field(default_factory=list)  # governance/risk findings


class CatalogMeta(_Model):
    schema_version: str = SCHEMA_VERSION
    generated_at: datetime
    scanner_version: str
    source: str  # e.g. "org:acme"
    repo_count: int
    asset_count: int
    llm_enriched: bool = False
    # repos whose latest scan failed in the run that wrote this catalog: id -> error
    failures: dict[str, str] = Field(default_factory=dict)
