"""Orchestrates discovery -> clone -> analyze for every repository, incrementally."""

from __future__ import annotations

import hashlib
import logging
import re
from collections import Counter, defaultdict
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from . import __version__, git
from .analyzers.ai_code import scan_code
from .analyzers.ai_common import RepoContext
from .analyzers.ai_files import FileDetector
from .analyzers.ai_risk import asset_flags
from .analyzers.docs import (
    declared_description,
    is_placeholder_description,
    parse_codeowners,
    parse_declared,
    readme_lead,
    summarize_readme,
)
from .analyzers.flags import repo_flags, runtime_versions
from .analyzers.manifests import parse_manifests
from .analyzers.practices import assess_practices
from .analyzers.purls import PACKAGE_ECOSYSTEMS, merge_github_sbom, summarize
from .analyzers.reusables import find_references, find_reusables
from .analyzers.stack import AUX_DIR, analyze_stack
from .fs import RepoFiles
from .github import GitHubClient, RepoRef
from .models import AIAsset, AIUsageSummary, Contributor, Ownership, Repo

log = logging.getLogger(__name__)

MAX_PROVENANCE_LOOKUPS = 2000
MAX_DEPENDENCIES = 15_000
_TESTISH = re.compile(r"(^|/)(tests?|testing|testdata|fixtures?|__tests__|e2e)(/|$)", re.I)


@dataclass
class ScanOptions:
    workdir: Path
    token: str | None = None
    shallow: bool = False
    workers: int = 4
    max_files: int = 100_000
    force: bool = False
    provenance: bool = True
    github_sbom: bool = False  # merge GitHub's dependency graph (needs a token)

    def fingerprint(self) -> str:
        """Options that change the output; a stored record is reused only if they match."""
        return (
            f"{__version__}|shallow={self.shallow}|prov={self.provenance}|max={self.max_files}"
            f"|sbom={self.github_sbom}"
        )


@dataclass
class ScanResult:
    repo: Repo
    assets: list[AIAsset]
    readme: str = ""
    reused: bool = False


@dataclass
class ScanReport:
    results: list[ScanResult] = field(default_factory=list)
    failures: dict[str, str] = field(default_factory=dict)


def scan_all(
    refs: list[RepoRef],
    opts: ScanOptions,
    previous: dict[str, tuple[Repo, list[AIAsset]]],
    on_result: Callable[[ScanResult], None] | None = None,
) -> ScanReport:
    """``on_result`` runs as each repo finishes, so a killed run keeps finished work."""
    report = ScanReport()
    gh = GitHubClient(opts.token) if opts.github_sbom and opts.token else None

    def one(ref: RepoRef) -> ScanResult:
        prev = previous.get(ref.full_name)
        if prev and not ref.properties_known:  # the lookup failed: keep what we had
            ref.custom_properties = prev[0].declared.custom_properties
            ref.properties_known = True
        if prev and not ref.head_sha:
            ref.head_sha = git.remote_head(ref.clone_url, opts.token, ref.default_branch)
        if prev and not opts.force and _unchanged(ref, prev[0], opts):
            log.info("unchanged, reusing: %s", ref.full_name)
            return ScanResult(repo=_refresh_meta(prev[0], ref), assets=prev[1], reused=True)
        checkout = opts.workdir / ref.owner / ref.name
        log.info("syncing %s", ref.full_name)
        sha = git.sync(
            ref.clone_url,
            checkout,
            branch=ref.default_branch,
            token=opts.token,
            shallow=opts.shallow,
        )
        ref.head_sha = sha
        result = analyze_checkout(ref, checkout, opts)
        if gh is not None:
            sbom = gh.dependency_sbom(ref.full_name)
            if sbom and merge_github_sbom(result.repo.dependencies, sbom):
                result.repo.dependency_summary = summarize(result.repo.dependencies)
        return result

    with ThreadPoolExecutor(max_workers=max(1, opts.workers)) as pool:
        futures = {pool.submit(one, ref): ref for ref in refs}
        for fut in as_completed(futures):
            ref = futures[fut]
            try:
                result = fut.result()
            except Exception as exc:
                log.error("scan failed for %s: %s", ref.full_name, exc)
                report.failures[ref.full_name] = _relative_error(exc, opts.workdir)
                continue
            report.results.append(result)
            if on_result is not None:
                try:
                    on_result(result)
                except OSError as exc:
                    log.error("could not save %s: %s", ref.full_name, exc)
    report.results.sort(key=lambda r: r.repo.id.lower())
    mark_duplicates([a for r in report.results for a in r.assets])
    return report


def _relative_error(exc: Exception, workdir: Path) -> str:
    """Error text without the scanner host's absolute clone path."""
    text = f"{type(exc).__name__}: {exc}"
    for root in {str(workdir.resolve()), str(workdir)}:
        text = text.replace(root + "/", "").replace(root, ".")
    return text[:500]


def _unchanged(ref: RepoRef, prev: Repo, opts: ScanOptions) -> bool:
    m = ref.meta
    return (
        bool(ref.head_sha)
        and ref.head_sha == prev.head_sha
        and prev.scan_fingerprint == opts.fingerprint()
        and ref.default_branch == prev.default_branch
        # declared metadata from org custom properties is part of the record
        and ref.custom_properties == prev.declared.custom_properties
        # GitHub-side fields that feed flags, building blocks, the summary and practices
        and bool(m.get("archived")) == prev.archived
        and bool(m.get("is_template")) == prev.is_template
        and (m.get("description") or None) == (prev.description or None)
        and list(m.get("topics") or []) == list(prev.topics)
    )


def _refresh_meta(repo: Repo, ref: RepoRef) -> Repo:
    """Cheap GitHub-side fields can change without a push; keep them current."""
    m = ref.meta
    update: dict[str, Any] = {
        k: m[k]
        for k in (
            "description",
            "homepage",
            "visibility",
            "archived",
            "fork",
            "is_template",
            "stars",
            "open_issues",
            "topics",
            "license",
            "pushed_at",
        )
        if k in m
    }
    if m.get("languages") and not m.get("languages_partial"):
        update["github_languages"] = m["languages"]
    repo = repo.model_copy(update=update)
    repo.lifecycle = _lifecycle(
        repo.archived, repo.ownership.last_commit or repo.pushed_at, repo.declared.lifecycle
    )
    return repo


def analyze_checkout(ref: RepoRef, checkout: Path, opts: ScanOptions) -> ScanResult:
    errors: list[str] = []
    files = RepoFiles.scan(checkout, max_files=opts.max_files)
    if files.truncated:
        errors.append(f"File walk truncated at {opts.max_files} files")

    manifests = parse_manifests(files)
    errors += manifests.errors[:20]
    stack_res = analyze_stack(files, manifests)
    stack, structure = stack_res.stack, stack_res.structure
    summary, readme = summarize_readme(files)
    declared = parse_declared(files, ref.custom_properties, errors)

    # ---- AI assets ----
    ctx = RepoContext(
        repo=ref.full_name, html_url=ref.html_url, ref=ref.head_sha or ref.default_branch or "HEAD"
    )
    detector = FileDetector(files, repo_name=ref.name)
    drafts = detector.run()
    errors += detector.errors[:50]
    code = scan_code(files, detector.claimed)
    assets = [d.build(ctx) for d in drafts + code.drafts]
    assets = _dedupe_assets(assets)
    full_history = not opts.shallow and not git.is_shallow(checkout)
    if opts.provenance and full_history:
        _add_provenance(checkout, assets)

    for label in sorted(code.sdks):
        if label not in stack.ai:
            stack.ai.append(label)
    ai_summary = _ai_summary(
        assets,
        code.models,
        detector.mcp_consumed,
        detector.mcp_provided | code.mcp_provided,
        stack.ai,
    )
    # an MCP server is the product only when it lives outside examples, docs and tests
    product_server = any(
        a.kind == "mcp-server" and not AUX_DIR.search(a.path) and not _TESTISH.search(a.path)
        for a in assets
    )
    # a CLI that also offers an MCP mode (``tool mcp``) stays a CLI
    if product_server and structure.repo_type in {
        "library",
        "service",
        "scripts",
        "other",
    }:
        structure.repo_type = "mcp-server"

    # ---- ownership / history ----
    history = git.repo_history(checkout) if full_history else None
    ownership = Ownership(codeowners=parse_codeowners(files))
    if history:
        ownership.commit_count = history.commit_count
        ownership.first_commit = history.first_commit
        ownership.last_commit = history.last_commit
        # history lists every author (most commits first): count them all, keep the top 10
        ownership.top_contributors = [
            Contributor(name=n, commits=c) for n, c in history.contributors[:10]
        ]
        ownership.contributor_count = len(history.contributors)

    # direct deps first so the cap never drops them in favour of lockfile entries
    deps = sorted(manifests.dependencies, key=lambda d: d.scope == "transitive")[:MAX_DEPENDENCIES]

    # ---- risk flags, building blocks, cross-repo references ----
    meta = ref.meta
    workflows = stack_res.workflow_texts
    stack.runtime_versions = runtime_versions(files, workflows, stack.runtimes)
    flags = repo_flags(files, workflows, ownership, declared, bool(meta.get("archived")), errors)
    for asset in assets:
        asset.flags += asset_flags(asset)
    reusables = find_reusables(
        files,
        workflows,
        structure.api_specs,
        structure.packages,
        ref.name,
        bool(meta.get("is_template")),
        errors,
    )
    references = find_references(files, workflows)

    # ---- summary ----
    # GitHub description, then what the team declared (catalog-info), then the ROOT
    # manifest (a nested package describes itself, not the repo), then the README lead
    descriptor_desc = declared_description(files)
    manifest_desc = next(
        (
            p.description
            for p in manifests.packages
            if p.path == "" and not is_placeholder_description(p.description)
        ),
        None,
    )
    if meta.get("description"):
        summary.one_liner, summary.source = meta["description"], "github"
    elif descriptor_desc:
        summary.one_liner, summary.source = descriptor_desc, "manifest"
    elif manifest_desc:
        summary.one_liner, summary.source = " ".join(manifest_desc.split()), "manifest"
    else:
        lead = readme_lead(readme)
        title = summary.readme_title
        if not lead and title and len(title.split()) >= 2:
            lead = title  # "Spring PetClinic Sample Application" beats a setup step
        summary.one_liner = lead
        summary.source = "readme" if lead else "none"

    practices = assess_practices(
        files,
        stack,
        structure,
        manifests.lockfiles,
        stack_res.workflow_texts,
        len(
            [
                d
                for d in manifests.dependencies
                if d.scope not in ("build", "transitive") and d.ecosystem in PACKAGE_ECOSYSTEMS
            ]
        ),
        description=meta.get("description"),
        topics=meta.get("topics") or [],
        has_descriptor=bool(declared.source_files),
    )

    repo = Repo(
        id=ref.full_name,
        name=ref.name,
        owner=ref.owner,
        url=ref.html_url,
        description=meta.get("description"),
        homepage=meta.get("homepage"),
        topics=meta.get("topics") or [],
        visibility=meta.get("visibility"),
        archived=bool(meta.get("archived")),
        fork=bool(meta.get("fork")),
        is_template=bool(meta.get("is_template")),
        default_branch=ref.default_branch,
        head_sha=ref.head_sha,
        license=meta.get("license") or _license_from_files(files),
        stars=meta.get("stars"),
        open_issues=meta.get("open_issues"),
        created_at=meta.get("created_at"),
        pushed_at=meta.get("pushed_at"),
        lifecycle=_lifecycle(
            bool(meta.get("archived")),
            ownership.last_commit or meta.get("pushed_at"),
            declared.lifecycle,
        ),
        capabilities=stack_res.capabilities,
        github_languages=meta.get("languages") or {},
        declared=declared,
        summary=summary,
        stack=stack,
        dependencies=deps,
        dependency_summary=summarize(deps),
        structure=structure,
        practices=practices,
        ownership=ownership,
        ai=ai_summary,
        flags=flags,
        reusables=reusables,
        references=references,
        scanned_at=datetime.now(UTC),
        scan_fingerprint=opts.fingerprint(),
        scanner_version=__version__,
        scan_errors=errors,
    )
    return ScanResult(repo=repo, assets=assets, readme=readme)


def _dedupe_assets(assets: list[AIAsset]) -> list[AIAsset]:
    seen: set[str] = set()
    out = []
    for a in assets:
        if a.id not in seen:
            seen.add(a.id)
            out.append(a)
    return out


def _add_provenance(checkout: Path, assets: list[AIAsset]) -> None:
    paths = sorted({a.path for a in assets if a.kind != "sdk-usage"})[:MAX_PROVENANCE_LOOKUPS]
    history = git.files_history(checkout, paths)
    for a in assets:
        hist = history.get(a.path)
        if hist:
            a.last_modified, a.last_author, a.commit_count = (
                hist.last_modified,
                hist.last_author,
                hist.commit_count,
            )


def _ai_summary(
    assets: list[AIAsset],
    models: dict[str, int],
    consumed: set[str],
    provided: set[str],
    sdk_labels: list[str],
) -> AIUsageSummary:
    kinds = Counter(a.kind for a in assets)
    return AIUsageSummary(
        has_ai=bool(assets or sdk_labels),
        asset_count=len(assets),
        asset_kinds=dict(sorted(kinds.items())),
        ecosystems=sorted({a.ecosystem for a in assets}),
        sdks=sorted(sdk_labels),
        models=[m for m, _ in sorted(models.items(), key=lambda kv: (-kv[1], kv[0]))][:40],
        mcp_servers_provided=sorted(provided),
        mcp_servers_consumed=sorted(consumed),
    )


Lifecycle = Literal["active", "maintained", "stale", "archived"]


def _lifecycle(archived: bool, last: datetime | None, declared: str | None) -> Lifecycle:
    if archived:
        return "archived"
    if declared and declared.lower() in {"deprecated", "retired", "sunset"}:
        return "stale"
    if not last:
        return "active"
    age = datetime.now(UTC) - (last if last.tzinfo else last.replace(tzinfo=UTC))
    if age > timedelta(days=365):
        return "stale"
    if age > timedelta(days=90):
        return "maintained"
    return "active"


_LICENSE_HINTS = (
    ("MIT License", "MIT"),
    ("Apache License", "Apache-2.0"),
    ("GNU GENERAL PUBLIC LICENSE", "GPL"),
    ("BSD", "BSD"),
    ("Mozilla Public License", "MPL-2.0"),
    ("ISC License", "ISC"),
)


def _license_from_files(files: RepoFiles) -> str | None:
    hits = files.glob(
        "LICENSE",
        "LICENSE.*",
        "LICENSE-*",
        "LICENCE",
        "LICENCE.*",
        "COPYING",
        "COPYING.*",
        "UNLICENSE",
    )
    found: list[str] = []
    for hit in hits[:4]:
        text = (files.read(hit.path, 4000) or "").lower()
        spdx = next((sp for needle, sp in _LICENSE_HINTS if needle.lower() in text), None)
        spdx = spdx or ("Unlicense" if "unlicense" in hit.name.lower() else None)
        if spdx and spdx not in found:
            found.append(spdx)
    if found:
        return " OR ".join(sorted(found))  # e.g. Rust's dual MIT / Apache-2.0
    return "Other" if hits else None


def mark_duplicates(assets: list[AIAsset]) -> None:
    """Link assets whose content is identical across the org (copy-pasted skills/rules)."""
    groups: dict[str, list[AIAsset]] = defaultdict(list)
    for a in assets:
        if (
            a.content_sha
            and a.kind not in ("sdk-usage", "mcp-config", "settings", "hook")
            and a.word_count >= 10
        ):
            groups[a.content_sha].append(a)
    for group in groups.values():
        ids = [a.id for a in group]
        for a in group:
            a.duplicates = [i for i in ids if i != a.id]


def slug(repo_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "__", repo_id)


def stable_hash(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:12]
