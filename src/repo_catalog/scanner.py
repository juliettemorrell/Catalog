"""Orchestrates discovery -> clone -> analyze for every repository, incrementally."""

from __future__ import annotations

import hashlib
import logging
import re
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from . import __version__, git
from .analyzers.ai_code import scan_code
from .analyzers.ai_common import RepoContext
from .analyzers.ai_files import FileDetector
from .analyzers.docs import first_sentence, parse_codeowners, parse_declared, summarize_readme
from .analyzers.manifests import parse_manifests
from .analyzers.practices import assess_practices
from .analyzers.stack import analyze_stack
from .fs import RepoFiles
from .github import RepoRef
from .models import AIAsset, AIUsageSummary, Contributor, Ownership, Repo

log = logging.getLogger(__name__)

MAX_PROVENANCE_LOOKUPS = 2000


@dataclass
class ScanOptions:
    workdir: Path
    token: str | None = None
    shallow: bool = False
    workers: int = 4
    max_files: int = 100_000
    force: bool = False
    provenance: bool = True

    def fingerprint(self) -> str:
        """Options that change the output; a stored record is reused only if they match."""
        return f"{__version__}|shallow={self.shallow}|prov={self.provenance}|max={self.max_files}"


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
    refs: list[RepoRef], opts: ScanOptions, previous: dict[str, tuple[Repo, list[AIAsset]]]
) -> ScanReport:
    report = ScanReport()

    def one(ref: RepoRef) -> ScanResult:
        prev = previous.get(ref.full_name)
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
        return analyze_checkout(ref, checkout, opts)

    with ThreadPoolExecutor(max_workers=max(1, opts.workers)) as pool:
        futures = {pool.submit(one, ref): ref for ref in refs}
        for fut in as_completed(futures):
            ref = futures[fut]
            try:
                report.results.append(fut.result())
            except Exception as exc:
                log.error("scan failed for %s: %s", ref.full_name, exc)
                report.failures[ref.full_name] = f"{type(exc).__name__}: {exc}"[:500]
    report.results.sort(key=lambda r: r.repo.id.lower())
    mark_duplicates([a for r in report.results for a in r.assets])
    return report


def _unchanged(ref: RepoRef, prev: Repo, opts: ScanOptions) -> bool:
    return (
        bool(ref.head_sha)
        and ref.head_sha == prev.head_sha
        and prev.scan_fingerprint == opts.fingerprint()
        # declared metadata from org custom properties is part of the record
        and ref.custom_properties == prev.declared.custom_properties
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
            "stars",
            "open_issues",
            "topics",
            "license",
            "pushed_at",
        )
        if k in m
    }
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
    if ai_summary.mcp_servers_provided and structure.repo_type in {
        "library",
        "cli",
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
        ownership.top_contributors = [
            Contributor(name=n, commits=c) for n, c in history.contributors
        ]
        ownership.contributor_count = len(history.contributors)

    # ---- summary ----
    meta = ref.meta
    manifest_desc = min(manifests.descriptions, default=(0, None))[1]
    if meta.get("description"):
        summary.one_liner, summary.source = meta["description"], "github"
    elif manifest_desc:
        summary.one_liner, summary.source = manifest_desc, "manifest"
    else:
        summary.one_liner = first_sentence(summary.readme_excerpt)

    practices = assess_practices(
        files,
        stack,
        structure,
        manifests.lockfiles,
        stack_res.workflow_texts,
        len([d for d in manifests.dependencies if d.scope != "build"]),
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
        dependencies=manifests.dependencies[:2000],
        structure=structure,
        practices=practices,
        ownership=ownership,
        ai=ai_summary,
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
            and a.kind not in ("sdk-usage", "mcp-config", "hook")
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
