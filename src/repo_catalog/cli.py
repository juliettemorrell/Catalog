"""Command line entry point: ``repo-catalog scan|build|search|blocks|deps|flags|sql|mcp|schema``."""

from __future__ import annotations

import argparse
import gc
import json
import logging
import os
import re
import sqlite3
import subprocess
import sys
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path

import httpx

from . import __version__
from .analyzers.org import link_org
from .github import GitHubClient, GitHubError, RepoRef
from .models import AIAsset, Repo
from .outputs import exports, store
from .outputs.sqlite import CatalogDB, dump_meta
from .scanner import ScanOptions, ScanResult, analyze_checkout, mark_duplicates, scan_all
from .vulns import annotate, dependency_keys, lookup_vulnerabilities

log = logging.getLogger("repo_catalog")

DB_FILE = "catalog.db"


def _positive(value: str) -> int:
    n = int(value)
    if n < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return n


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    return int(args.func(args) or 0)


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="repo-catalog", description=__doc__)
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(required=True)

    s = sub.add_parser("scan", help="Discover, clone and analyze repositories.")
    src = s.add_argument_group("sources (combine freely)")
    src.add_argument("--org", action="append", default=[], help="GitHub org or user login.")
    src.add_argument("--repo", action="append", default=[], help="owner/name (repeatable).")
    src.add_argument(
        "--local",
        action="append",
        default=[],
        type=Path,
        help="Existing checkout, or a folder of checkouts. No network needed.",
    )
    s.add_argument("--out", type=Path, default=Path("data"), help="Output folder.")
    s.add_argument(
        "--workdir",
        type=Path,
        default=Path(".cache/repos"),
        help="Where clones are kept between runs.",
    )
    s.add_argument(
        "--token",
        default=os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"),
        help="GitHub token (default: $GITHUB_TOKEN / $GH_TOKEN).",
    )
    s.add_argument(
        "--no-git-auth",
        action="store_true",
        help="Do not pass the token to git (use your own credential helper).",
    )
    s.add_argument("--include-forks", action="store_true")
    s.add_argument("--skip-archived", action="store_true")
    s.add_argument("--match", help="Only repos whose name matches this regex.")
    s.add_argument("--exclude", help="Skip repos whose name matches this regex.")
    s.add_argument("--limit", type=_positive, help="Scan at most N repos (for trials).")
    s.add_argument("--workers", type=_positive, default=4)
    s.add_argument(
        "--shallow", action="store_true", help="Depth-1 clones: faster, but no history/provenance."
    )
    s.add_argument("--force", action="store_true", help="Rescan even if HEAD is unchanged.")
    s.add_argument("--no-provenance", action="store_true", help="Skip per-file git history.")
    s.add_argument("--max-files", type=int, default=100_000)
    s.add_argument(
        "--github-sbom",
        action="store_true",
        help="Also merge GitHub's dependency graph (needs a token with contents: read).",
    )
    s.add_argument(
        "--osv",
        action="store_true",
        help="Check locked dependency versions against OSV.dev for known vulnerabilities.",
    )
    s.add_argument(
        "--llm",
        action="store_true",
        help="Enrich with Claude summaries (needs ANTHROPIC_API_KEY and the [llm] extra).",
    )
    s.add_argument("--llm-model", default=None, help="Claude model id (default: claude-opus-5).")
    s.add_argument("--llm-effort", default="medium", choices=["low", "medium", "high"])
    s.set_defaults(func=cmd_scan)

    b = sub.add_parser("build", help="Rebuild aggregates, SQLite and exports from data/repos.")
    b.add_argument("--out", type=Path, default=Path("data"))
    b.add_argument("--source", default="catalog")
    b.add_argument("--osv", action="store_true", help="Check dependencies against OSV.dev.")
    b.set_defaults(func=cmd_build)

    q = sub.add_parser("search", help="Full-text search the catalog.")
    q.add_argument("query")
    q.add_argument("--assets", action="store_true", help="Search AI assets instead of repos.")
    q.add_argument("--limit", type=int, default=15)
    q.add_argument("--out", type=Path, default=Path("data"))
    q.set_defaults(func=cmd_search)

    bl = sub.add_parser("blocks", help="Find reusable building blocks (actions, modules...).")
    bl.add_argument("query", nargs="?", default="")
    bl.add_argument(
        "--kind",
        choices=[
            "action",
            "reusable-workflow",
            "terraform-module",
            "helm-chart",
            "template",
            "api",
            "config-package",
        ],
    )
    bl.add_argument("--limit", type=_positive, default=20)
    bl.add_argument("--out", type=Path, default=Path("data"))
    bl.set_defaults(func=cmd_blocks)

    du = sub.add_parser("deps", help="Which repos ship a package, at which versions.")
    du.add_argument("package")
    du.add_argument("--ecosystem")
    du.add_argument("--version", dest="version_prefix", help="Version prefix, e.g. 4.17")
    du.add_argument("--direct", action="store_true", help="Skip transitive dependencies.")
    du.add_argument("--limit", type=_positive, default=200)
    du.add_argument("--out", type=Path, default=Path("data"))
    du.set_defaults(func=cmd_deps)

    fl = sub.add_parser("flags", help="List security, maintenance and AI-governance findings.")
    fl.add_argument("--severity", choices=["high", "medium", "low"])
    fl.add_argument("--category", choices=["security", "maintenance", "ownership", "ai-governance"])
    fl.add_argument("--id", dest="flag_id", help="e.g. committed-secret, eol-runtime")
    fl.add_argument("--repo")
    fl.add_argument("--limit", type=_positive, default=100)
    fl.add_argument("--out", type=Path, default=Path("data"))
    fl.set_defaults(func=cmd_flags)

    sql = sub.add_parser("sql", help="Run a read-only SQL query against catalog.db.")
    sql.add_argument("query")
    sql.add_argument("--limit", type=_positive, default=1000)
    sql.add_argument("--out", type=Path, default=Path("data"))
    sql.set_defaults(func=cmd_sql)

    m = sub.add_parser("mcp", help="Serve the catalog to AI agents over MCP (stdio).")
    m.add_argument("--out", type=Path, default=Path("data"))
    m.set_defaults(func=cmd_mcp)

    sc = sub.add_parser("schema", help="Write JSON Schemas for the output records.")
    sc.add_argument("--dir", type=Path, default=Path("schema"))
    sc.set_defaults(func=lambda a: store.write_schemas(a.dir))
    return p


# --------------------------------------------------------------------------------------- #


def cmd_scan(args: argparse.Namespace) -> int:
    if not (args.org or args.repo or args.local):
        sys.exit("Nothing to scan: pass --org, --repo or --local.")
    for flag in ("match", "exclude"):
        if getattr(args, flag):
            try:
                re.compile(getattr(args, flag))
            except re.error as exc:
                sys.exit(f"--{flag} is not a valid regular expression: {exc}")
    for path in args.local:
        if not path.is_dir():
            sys.exit(f"--local {path}: not a directory")
    args.out.mkdir(parents=True, exist_ok=True)
    opts = ScanOptions(
        workdir=args.workdir,
        token=None if args.no_git_auth else args.token,
        shallow=args.shallow,
        workers=args.workers,
        max_files=args.max_files,
        force=args.force,
        provenance=not args.no_provenance,
        github_sbom=args.github_sbom,
    )
    # records without their transitive deps: those stay in the files (see store.write_repo)
    with _gc_paused():
        previous = store.load_previous(args.out, direct_only=True)
    gc.freeze()  # long-lived and cycle-free: keep the collector from re-scanning it all run
    results: list[ScanResult] = []
    failures: dict[str, str] = {}
    discovered: set[str] = set()
    incomplete: set[str] = set()

    saved_duplicates: dict[str, list[list[str]]] = {}

    def save(result: ScanResult) -> None:  # as each repo finishes: a killed run keeps work
        # reused results come from `previous`, so their transitive deps are in the file
        light = result.light or result.reused
        store.write_repo(args.out, result.repo, result.assets, merge_transitive=light)
        saved_duplicates[result.repo.id] = [a.duplicates for a in result.assets]
        # a big org's transitive deps would not fit in memory for the whole run
        store.strip_transitive(result.repo)
        result.light = True

    if args.org or args.repo:
        try:
            refs, incomplete = _discover(args)
        except (GitHubError, httpx.HTTPError) as exc:
            sys.exit(f"GitHub discovery failed: {exc}")
        discovered.update(r.full_name for r in refs)
        log.info("scanning %d repositories", len(refs))
        report = scan_all(refs, opts, previous, on_result=save)
        results += report.results
        failures.update(report.failures)
        del report
    local = _local_refs(args.local)
    if args.local and not local and not (args.org or args.repo):
        log.error("no git repositories found under %s", ", ".join(map(str, args.local)))
        return 1
    if local:
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
            futures = {pool.submit(analyze_checkout, ref, root, opts): ref for ref, root in local}
            for fut, ref in futures.items():
                discovered.add(ref.full_name)
                try:
                    result = fut.result()
                except Exception as exc:
                    log.error("scan failed for %s: %s", ref.full_name, exc)
                    failures[ref.full_name] = f"{type(exc).__name__}: {exc}"[:500]
                    continue
                results.append(result)
                save(result)
            futures.clear()
    fresh = len(results)

    for failed in failures:  # keep last good data rather than dropping the repo
        if failed in previous:
            repo, assets = previous[failed]
            note = f"latest scan failed: {failures[failed]}"
            errors = [e for e in repo.scan_errors if not e.startswith("latest scan failed")]
            repo = repo.model_copy(update={"scan_errors": [*errors, note]})
            results.append(ScanResult(repo=repo, assets=assets, reused=True, light=True))
    previous.clear()
    gc.unfreeze()

    mark_duplicates([a for r in results for a in r.assets])
    for r in results:  # persist first: enrichment problems must never lose scan results
        if saved_duplicates.get(r.repo.id) != [a.duplicates for a in r.assets]:
            store.write_repo(args.out, r.repo, r.assets, merge_transitive=r.light or r.reused)
    saved_duplicates.clear()
    if args.llm and _enrich(args, results):
        for r in results:
            if not r.reused:  # only fresh scans are enriched
                store.write_repo(args.out, r.repo, r.assets, merge_transitive=r.light)
    if args.org and not (args.match or args.exclude or args.limit):
        owners = {
            o.lower()
            for o in args.org
            if any(d.lower().startswith(o.lower() + "/") for d in discovered)
        }
        for owner in sorted(owners & incomplete):
            log.warning("GitHub returned an incomplete repo list for %s; not pruning", owner)
        owners -= incomplete
        removed = store.prune(args.out, discovered | set(failures), owners)
        if removed:
            log.info("pruned %d repos no longer in %s", len(removed), ", ".join(sorted(owners)))
            _prune_clones(args.workdir, removed)

    source = ",".join([f"org:{o}" for o in args.org] + args.repo + [str(p) for p in args.local])
    counts = (len(results), sum(not r.reused for r in results), sum(r.reused for r in results))
    results.clear()  # _build reloads everything from the files; free this run's copies
    rejected = _build(args.out, source, llm=args.llm, osv=args.osv, failures=failures)
    log.info("done: %d repos (%d scanned, %d reused), %d failed", *counts, len(failures))
    for name, err in failures.items():
        log.warning("FAILED %s: %s", name, err)
    # 1: nothing usable; 2: the catalog was written but some repos failed (see meta) or
    # stored records could not be loaded (see the warning above)
    if failures and not fresh:
        return 1
    return 2 if failures or rejected else 0


def _prune_clones(workdir: Path, slugs: list[str]) -> None:
    """Drop the clones of repos that were deleted or renamed, so the workdir stays bounded."""
    import shutil

    root = workdir.resolve()
    for slug in slugs:
        owner, _, name = slug.partition("__")
        clone = (root / owner / name).resolve()
        if name and clone.parent.parent == root and clone.is_dir():
            shutil.rmtree(clone, ignore_errors=True)


def _discover(args: argparse.Namespace) -> tuple[list[RepoRef], set[str]]:
    """Refs to scan, plus the owners whose listing GitHub returned incomplete."""
    with GitHubClient(args.token) as gh:
        refs: list[RepoRef] = []
        props_cache: dict[str, dict[str, dict[str, object]] | None] = {}

        def props_for(owner: str) -> dict[str, dict[str, object]] | None:
            if owner.lower() not in props_cache:
                props_cache[owner.lower()] = gh.org_custom_properties(owner)
            return props_cache[owner.lower()]

        def attach(ref: RepoRef) -> RepoRef:
            props = props_for(ref.owner)
            if props is None:
                ref.properties_known = False
            else:
                ref.custom_properties = props.get(ref.full_name, {})
            return ref

        for org in args.org:
            owner_refs = gh.list_owner_repos(org)
            if not owner_refs:
                log.warning("no repositories visible for %s (check token access)", org)
            refs += [attach(ref) for ref in owner_refs]
        refs += [attach(gh.get_repo(name)) for name in args.repo]
        incomplete = set(gh.incomplete)
    seen: set[str] = set()
    out = []
    for ref in refs:
        m = ref.meta
        if (
            ref.full_name in seen
            or (m.get("fork") and not args.include_forks)
            or (m.get("archived") and args.skip_archived)
        ):
            continue
        if args.match and not re.search(args.match, ref.full_name):
            continue
        if args.exclude and re.search(args.exclude, ref.full_name):
            continue
        if not ref.default_branch:  # empty repository
            continue
        seen.add(ref.full_name)
        out.append(ref)
    return (out[: args.limit] if args.limit else out), incomplete


_GITHUB_REMOTE = re.compile(r"github\.com[:/]+([^/]+)/([^/]+?)(?:\.git)?/*$")


_SKIP_DIRS = {"node_modules", "vendor", "__pycache__"}


def _find_git_roots(path: Path, depth: int = 3) -> list[Path]:
    """Git work trees at or below ``path`` (e.g. a folder of clones, or the scanner's own
    ``workdir/<owner>/<repo>`` layout). Nested repos inside a found repo are not listed."""
    if (path / ".git").exists():
        return [path]
    if depth == 0:
        return []
    try:
        children = sorted(p for p in path.iterdir() if p.is_dir() and not p.is_symlink())
    except OSError:
        return []
    return [
        root
        for child in children
        if not child.name.startswith(".") and child.name not in _SKIP_DIRS
        for root in _find_git_roots(child, depth - 1)
    ]


def _local_refs(paths: list[Path]) -> list[tuple[RepoRef, Path]]:
    found: list[tuple[Path, Path]] = []  # (--local folder, repo root)
    for path in (p.resolve() for p in paths):
        roots = _find_git_roots(path)
        if not roots:
            log.warning("no git repositories found in %s", path)
        found += [(path, root) for root in roots]
    names = [root.name for _, root in found]
    refs = []
    seen: set[str] = set()
    for base, root in found:
        remote = _git(root, "remote", "get-url", "origin")
        m = _GITHUB_REMOTE.search(remote or "")
        local_name = root.name
        if names.count(root.name) > 1:  # same folder name twice: qualify by its path
            local_name = "-".join((base.name, *root.relative_to(base).parts))
        full_name = f"{m.group(1)}/{m.group(2)}" if m else f"local/{local_name}"
        if full_name.lower() in seen:
            log.warning("skipping %s: another checkout of %s was already found", root, full_name)
            continue
        seen.add(full_name.lower())
        html = f"https://github.com/{full_name}" if m else root.as_uri()
        branch = _git(root, "rev-parse", "--abbrev-ref", "HEAD")
        ref = RepoRef(
            full_name=full_name,
            clone_url=remote or "",
            html_url=html,
            default_branch=None if branch in (None, "HEAD") else branch,
            head_sha=_git(root, "rev-parse", "HEAD"),
        )
        refs.append((ref, root))
    return refs


def _git(cwd: Path, *args: str) -> str | None:
    proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    return proc.stdout.strip() if proc.returncode == 0 else None


def _enrich(args: argparse.Namespace, results: list[ScanResult]) -> bool:
    """Best effort: returns True if anything was enriched. Never raises."""
    todo = [r for r in results if not r.reused]
    if not todo:
        return False
    try:
        from .enrich import DEFAULT_MODEL, Enricher

        enricher = Enricher(
            cache_dir=Path(".cache/llm"),
            model=args.llm_model or DEFAULT_MODEL,
            effort=args.llm_effort,
        )
        log.info("LLM-enriching %d repos with %s", len(todo), enricher.model)
        enricher.enrich_repos([r.repo for r in todo], {r.repo.id: r.readme for r in todo})
        enricher.enrich_assets([a for r in todo for a in r.assets])
    except Exception as exc:
        log.error("LLM enrichment skipped: %s", exc)
        return False
    return True


def cmd_build(args: argparse.Namespace) -> int:
    if not (args.out / store.REPOS_DIR).is_dir():
        sys.exit(f"{args.out / store.REPOS_DIR} not found; run `repo-catalog scan` first.")
    rejected = _build(args.out, args.source, llm=False, osv=args.osv)
    return 2 if rejected else 0


@contextmanager
def _gc_paused() -> Iterator[None]:
    """Building creates millions of small objects and hardly any reference cycles; the
    cyclic collector would re-scan the growing heap over and over (most of the load time
    at scale), so it is paused for the duration."""
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        yield
    finally:
        if was_enabled:
            gc.enable()


def _build(
    out: Path, source: str, llm: bool, osv: bool = False, failures: dict[str, str] | None = None
) -> int:
    """Aggregates, SQLite and exports from ``out/repos``. Returns the number of stored
    records that could not be loaded (they are left out of the catalog).

    Memory stays proportional to the direct dependencies: locked transitive ones (most of
    a large org's dependency rows) are read back from each repo's file, one repo at a
    time, for the outputs that list them (SQLite, SBOMs, the OSV lookup)."""
    with _gc_paused():
        prev = store.load_previous(out, direct_only=True)
        if prev.rejected:
            log.warning(
                "%d stored record(s) in %s could not be loaded and are NOT in this catalog "
                "(rescan them, or delete the files): %s",
                len(prev.rejected),
                out / store.REPOS_DIR,
                ", ".join(sorted(prev.rejected)[:20]) + (" ..." if len(prev.rejected) > 20 else ""),
            )
        repos: list[Repo] = sorted((r for r, _ in prev.values()), key=lambda r: r.id.lower())
        assets: list[AIAsset] = [
            a for r in repos for a in sorted(prev[r.id][1], key=lambda a: (a.kind, a.path))
        ]
        paths = prev.paths
        rejected = len(prev.rejected)

        def full(r: Repo) -> Repo:  # the record with its transitive deps, for one output
            return r.model_copy(update={"dependencies": store.full_dependencies(paths[r.id], r)})

        duplicate_counts = mark_duplicates(assets)
        links = link_org(repos, assets, transitive=prev.transitive_refs)
        del prev  # with the packed transitive names, only needed for linking
        findings = None
        if osv:
            keys = dependency_keys(d for r in repos for d in full(r).dependencies)
            findings = lookup_vulnerabilities(keys, Path(".cache/osv"))
            hits = 0
            for r in repos:
                record = full(r)  # shares r's direct Dependency objects: they get the ids
                hits += annotate(record, findings)
                r.flags, r.dependency_summary = record.flags, record.dependency_summary
            log.info("OSV: %d vulnerable dependency versions", hits)
        llm = llm or any(r.summary.source == "llm" for r in repos)
        used_by_totals: dict[str, int] = {}
        for targets in links.values():
            for link in targets:
                used_by_totals[link.repo] = used_by_totals.get(link.repo, 0) + 1
        meta = store.write_aggregates(
            out, repos, assets, source, llm, failures or {}, used_by_totals, duplicate_counts
        )
        store.write_site_details(out, repos, assets)  # drawer/Insights detail for the web UI
        exports.write_backstage(out / "backstage-entities.yaml", repos)
        exports.write_aibom(out / "ai-bom.cdx.json", repos, assets, source)
        sboms = exports.SbomWriter(out / "sbom")
        with CatalogDB(out / DB_FILE, dump_meta(meta.model_dump(mode="json"))) as db:
            for r in repos:
                record = full(r)
                if findings is not None:
                    for d in record.dependencies:
                        if d.scope == "transitive":
                            d.vulns = findings.vulns_for(d)
                db.add_repo(record, links.get(r.id))
                sboms.write(record)
            for a in assets:
                db.add_asset(a, duplicate_counts.get(a.id))
        sboms.finish()
        log.info("wrote %d repos and %d AI assets to %s", len(repos), len(assets), out)
    gc.collect()
    return rejected


def _connect(out: Path) -> sqlite3.Connection:
    db = out / DB_FILE
    if not db.exists():
        sys.exit(f"{db} not found; run `repo-catalog scan` first.")
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    return con


def cmd_search(args: argparse.Namespace) -> int:
    from .query import search_assets, search_repos

    con = _connect(args.out)
    rows = (search_assets if args.assets else search_repos)(con, args.query, limit=args.limit)
    print(json.dumps(rows, indent=2))
    return 0


def cmd_blocks(args: argparse.Namespace) -> int:
    from .query import find_building_blocks

    rows = find_building_blocks(_connect(args.out), args.query, kind=args.kind, limit=args.limit)
    print(json.dumps(rows, indent=2))
    return 0


def cmd_deps(args: argparse.Namespace) -> int:
    from .query import dependency_usage

    rows = dependency_usage(
        _connect(args.out),
        args.package,
        ecosystem=args.ecosystem,
        version_prefix=args.version_prefix,
        include_transitive=not args.direct,
        limit=args.limit,
    )
    print(json.dumps(rows, indent=2))
    return 0


def cmd_flags(args: argparse.Namespace) -> int:
    from .query import list_flags

    rows = list_flags(
        _connect(args.out),
        severity=args.severity,
        category=args.category,
        flag_id=args.flag_id,
        repo=args.repo,
        limit=args.limit,
    )
    print(json.dumps(rows, indent=2))
    return 0


def cmd_sql(args: argparse.Namespace) -> int:
    con = _connect(args.out)
    from .query import read_only_sql

    try:
        rows = read_only_sql(con, args.query, limit=args.limit)
    except (sqlite3.Error, ValueError) as exc:
        sys.exit(f"SQL error: {exc}")
    print(json.dumps(rows, indent=2, default=str))
    return 0


def cmd_mcp(args: argparse.Namespace) -> int:
    from .mcp_server import serve

    serve(args.out / DB_FILE)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
