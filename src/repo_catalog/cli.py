"""Command line entry point: ``repo-catalog scan|build|search|sql|mcp|schema``."""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx

from . import __version__
from .analyzers.org import link_org
from .github import GitHubClient, GitHubError, RepoRef
from .models import AIAsset, Repo
from .outputs import exports, store
from .outputs.sqlite import build_sqlite, dump_meta
from .scanner import ScanOptions, ScanResult, analyze_checkout, mark_duplicates, scan_all
from .vulns import apply_vulnerabilities

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
    previous = store.load_previous(args.out)
    results: list[ScanResult] = []
    failures: dict[str, str] = {}
    discovered: set[str] = set()

    if args.org or args.repo:
        try:
            refs = _discover(args)
        except (GitHubError, httpx.HTTPError) as exc:
            sys.exit(f"GitHub discovery failed: {exc}")
        discovered.update(r.full_name for r in refs)
        log.info("scanning %d repositories", len(refs))
        report = scan_all(refs, opts, previous)
        results += report.results
        failures.update(report.failures)
    local = [pair for path in args.local for pair in _local_refs(path)]
    if local:
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
            futures = {pool.submit(analyze_checkout, ref, root, opts): ref for ref, root in local}
            for fut, ref in futures.items():
                discovered.add(ref.full_name)
                try:
                    results.append(fut.result())
                except Exception as exc:
                    log.error("scan failed for %s: %s", ref.full_name, exc)
                    failures[ref.full_name] = f"{type(exc).__name__}: {exc}"[:500]
    fresh = len(results)

    for failed in failures:  # keep last good data rather than dropping the repo
        if failed in previous:
            repo, assets = previous[failed]
            note = f"latest scan failed: {failures[failed]}"
            errors = [e for e in repo.scan_errors if not e.startswith("latest scan failed")]
            repo = repo.model_copy(update={"scan_errors": [*errors, note]})
            results.append(ScanResult(repo=repo, assets=assets, reused=True))

    mark_duplicates([a for r in results for a in r.assets])
    for r in results:  # persist first: enrichment problems must never lose scan results
        store.write_repo(args.out, r.repo, r.assets)
    if args.llm and _enrich(args, results):
        for r in results:
            store.write_repo(args.out, r.repo, r.assets)
    if args.org and not (args.match or args.exclude or args.limit):
        owners = {
            o.lower()
            for o in args.org
            if any(d.lower().startswith(o.lower() + "/") for d in discovered)
        }
        removed = store.prune(args.out, discovered | set(failures), owners)
        if removed:
            log.info("pruned %d repos no longer in %s", len(removed), ", ".join(sorted(owners)))

    source = ",".join([f"org:{o}" for o in args.org] + args.repo + [str(p) for p in args.local])
    _build(args.out, source, llm=args.llm, osv=args.osv)
    log.info(
        "done: %d repos (%d scanned, %d reused), %d failed",
        len(results),
        sum(not r.reused for r in results),
        sum(r.reused for r in results),
        len(failures),
    )
    for name, err in failures.items():
        log.warning("FAILED %s: %s", name, err)
    return 1 if failures and not fresh else 0


def _discover(args: argparse.Namespace) -> list[RepoRef]:
    with GitHubClient(args.token) as gh:
        refs: list[RepoRef] = []
        for org in args.org:
            owner_refs = gh.list_owner_repos(org)
            if not owner_refs:
                log.warning("no repositories visible for %s (check token access)", org)
            props = gh.org_custom_properties(org)
            for ref in owner_refs:
                ref.custom_properties = props.get(ref.full_name, {})
            refs += owner_refs
        refs += [gh.get_repo(name) for name in args.repo]
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
    return out[: args.limit] if args.limit else out


_GITHUB_REMOTE = re.compile(r"github\.com[:/]+([^/]+)/([^/]+?)(?:\.git)?/*$")


def _local_refs(path: Path) -> list[tuple[RepoRef, Path]]:
    path = path.resolve()
    roots = (
        [path]
        if (path / ".git").exists()
        else sorted(p for p in path.iterdir() if p.is_dir() and (p / ".git").exists())
    )
    if not roots:
        log.warning("no git repositories found in %s", path)
    refs = []
    for root in roots:
        remote = _git(root, "remote", "get-url", "origin")
        m = _GITHUB_REMOTE.search(remote or "")
        full_name = f"{m.group(1)}/{m.group(2)}" if m else f"local/{root.name}"
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
    _build(args.out, args.source, llm=False, osv=args.osv)
    return 0


def _build(out: Path, source: str, llm: bool, osv: bool = False) -> None:
    prev = store.load_previous(out)
    repos: list[Repo] = sorted((r for r, _ in prev.values()), key=lambda r: r.id.lower())
    assets: list[AIAsset] = [
        a for r in repos for a in sorted(prev[r.id][1], key=lambda a: (a.kind, a.path))
    ]
    mark_duplicates(assets)
    link_org(repos, assets)
    if osv:
        hits = apply_vulnerabilities(repos, Path(".cache/osv"))
        log.info("OSV: %d vulnerable dependency versions", hits)
    llm = llm or any(r.summary.source == "llm" for r in repos)
    meta = store.write_aggregates(out, repos, assets, source, llm)
    build_sqlite(out / DB_FILE, repos, assets, dump_meta(meta.model_dump(mode="json")))
    exports.write_backstage(out / "backstage-entities.yaml", repos)
    exports.write_aibom(out / "ai-bom.cdx.json", repos, assets, source)
    exports.write_sboms(out / "sbom", repos)
    log.info("wrote %d repos and %d AI assets to %s", len(repos), len(assets), out)


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
