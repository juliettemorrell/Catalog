# Handoff: Repo Catalog

A briefing for whoever (human or Claude) integrates this into existing work. Read this first, then `README.md` for usage and `docs/catalog-data.md` for every field.

## What it is

A scanner plus a static web UI that catalog every repository in a GitHub org:

1. **General repo catalog**: what each repo is and does, its stack, capabilities, every dependency (declared, locked and transitive, 25 ecosystems), structure, best-practice score, ownership, reusable building blocks, and how repos depend on each other.
2. **AI asset library**: every skill, agent, prompt, rules file, MCP server/config, hook, plugin, eval and LLM integration, with full content, metadata, quality score and duplicates across the org.
3. **Findings**: security, maintenance, ownership and AI-governance flags with severity and file/line (secret values are never stored).

It is built for SDLC agents: the same data is available as JSON (with JSON Schemas), SQLite with full-text search, an MCP server, Backstage entities, CycloneDX SBOMs and an AI-BOM.

## Status

| Area | State |
|---|---|
| Local scanning (`--local`) | Verified on 22 public OSS repos: 0 crashes, 0 scan errors, ~1 minute for the lot |
| Outputs | JSON validated by the Pydantic models; SBOMs and AI-BOM pass strict CycloneDX 1.6 schema validation |
| Tests | 70 Python tests (`uv run pytest`), 17 site tests (`cd site && npm test`); ruff, mypy, tsc, actionlint and zizmor clean |
| Web UI | Axe accessibility checks: 0 violations in light and dark themes; no mobile overflow |
| **Not verified live** | GitHub org discovery against a real org (tested with mocked HTTP only), `--github-sbom`, `--osv` (OSV.dev was unreachable from the build sandbox; tested with mocked responses) and `--llm` summaries. Run a small trial first: `repo-catalog scan --org <org> --limit 5` |

## Five-minute start

```bash
uv sync --all-extras                        # Python 3.11+; or: pip install dist/repo_catalog-*.whl
export GITHUB_TOKEN=...                      # read-only: Contents + Metadata (+ org Custom properties)
uv run repo-catalog scan --org <your-org> --limit 5 --osv
uv run repo-catalog search "payments"
uv run repo-catalog deps lodash              # who ships it, which versions, direct or transitive
uv run repo-catalog flags --severity high
cd site && npm ci && npm run dev             # UI at http://localhost:5173 (reads ../data)
```

Without network or a token: clone repos into a folder and run `repo-catalog scan --local <folder>`.

A prebuilt UI is in `site-dist/` (if this came as a zip): serve that folder with a `data/` subfolder containing `catalog.json` and `ai-assets.json`. `demo-data/` holds a catalog of 22 public open-source repos to explore before scanning your own.

## Integration points (pick what fits the existing work)

| Need | Use |
|---|---|
| An agent that finds prior art, standards, owners, blast radius | MCP server: `repo-catalog mcp --out data` (stdio). Tools: `search_repos`, `get_repo`, `search_ai_assets`, `get_ai_asset`, `find_building_blocks`, `repo_relationships`, `dependency_usage`, `list_flags`, `repos_using`, `technology_usage`, `sql` (read-only, guarded). `.mcp.json` registers it for Claude Code; `.claude/skills/repo-catalog/SKILL.md` teaches the workflow |
| Python code | `from repo_catalog import query` over `sqlite3.connect("data/catalog.db")`; or scan programmatically with `repo_catalog.scanner.analyze_checkout(ref, path, ScanOptions(...))` |
| Another system's database or pipeline | `data/repos/*.json` (source of truth, one per repo) validated by `schema/*.schema.json`; or `data/catalog.db` |
| Backstage | `data/backstage-entities.yaml` (Components with owner, lifecycle, tags, `dependsOn`, API links). Values teams declared in `catalog-info.yaml` always win |
| Dependency-Track, GitHub, security tooling | `data/sbom/<owner>__<name>.cdx.json` (CycloneDX 1.6, purls, OSV advisories) |
| AI governance / inventory | `data/ai-bom.cdx.json` and the `ai_assets` table |
| Scheduled refresh | `.github/workflows/catalog.yml` (nightly; GitHub App auth; incremental: unchanged repos are not re-cloned) |

## How it works

```
discover (GitHub GraphQL, REST fallback) -> blobless clone/fetch -> analyze checkout -> data/repos/*.json
                                                                    |
      build: org-wide links, calendar-based flags, optional OSV  <-+
      -> catalog.json, ai-assets.json, catalog.db, SBOMs, Backstage, AI-BOM -> UI / MCP / CLI
```

- `scanner.py` orchestrates; everything under `analyzers/` is a pure function of the checked-out files.
- Incremental: a repo is re-analyzed only when its HEAD or the scanner version/options change.
- Build-time (`org.py`): cross-repo links, end-of-life and retired-model flags, archived-dependency flags and OSV lookups are recomputed on every build, so they stay current for repos that did not change.

## Where to change things

| Change | File |
|---|---|
| Recognize a new technology or capability | `analyzers/rules.py` (plain-text tables, one line each) |
| New AI file convention | `analyzers/ai_files.py`; AI in source code: `ai_code.py`, `ai_python.py` |
| New manifest or lockfile format | `analyzers/deps_more.py`, `analyzers/lockfiles.py` |
| New finding | `analyzers/flags.py` (repo), `ai_risk.py` (AI assets), `org.py` (cross-repo or calendar) |
| Runtime EOL dates, retired model IDs | `analyzers/reference.py` (sourced data; update when vendors announce changes) |
| Output contract | `models.py`, then `uv run repo-catalog schema --dir schema` and mirror in `site/src/types.ts` |

Conventions (also in `CLAUDE.md`): detectors never raise on bad input (errors go to `scan_errors`); secrets are never persisted; every new detector gets a fixture in `tests/test_scan.py`; Actions are pinned to full SHAs.

## Security and data handling

- The catalog describes private code. Keep `data/` out of public places: it is gitignored, Pages publishing is off by default, and the workflow uploads data as a private artifact.
- Tokens are passed to git through environment config (never argv or URLs) and scrubbed from errors. Symlinks cannot escape a repo; YAML alias bombs and oversized files are bounded.
- Secrets found in repos are reported by kind and location only; AI asset content is redacted before it is stored.
- The GitHub App needs read-only permissions; nothing writes to scanned repos.

## Known limitations

- Dependency trees are flat: a transitive dependency is known, but not which direct dependency pulled it in. Gradle and Maven transitive deps need a lockfile (`gradle.lockfile`) or `--github-sbom`.
- Retired-model data covers Anthropic fully and only long-retired OpenAI models; Gemini is not yet listed (`reference.py`).
- Findings are heuristics with evidence; high-severity ones were tuned against real repos, but review before acting at scale.
- LLM enrichment (`--llm`) is optional and costs tokens; everything else is deterministic and offline-capable except discovery, `--osv` and `--github-sbom`.
