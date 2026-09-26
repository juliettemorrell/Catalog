# Repo Catalog

Python scanner (`src/repo_catalog`) + static site (`site/`) that catalog every repo in a GitHub org and its AI assets.

## Commands

- Setup: `uv sync --all-extras`; `cd site && npm ci`
- Test: `uv run pytest`
- Lint/format/types: `uv run ruff check src tests && uv run ruff format src tests && uv run mypy`
- Site: `cd site && npm run dev` (serves `../data`), `npm run build`
- Scan without network: `uv run repo-catalog scan --local <dir-of-clones>`
- After changing `models.py`: `uv run repo-catalog schema --dir schema` (CI checks it is current)

## Layout

- `models.py`: output contract (Repo, AIAsset). Mirror field changes in `site/src/types.ts`.
- `analyzers/rules.py`: technology/capability tables (plain text, one line per technology).
- `analyzers/ai_files.py`: AI conventions found in files; `ai_code.py`: AI found in source code.
- `analyzers/manifests.py` + `deps_more.py` (declared deps, 25 ecosystems), `lockfiles.py` (locked and transitive versions), `purls.py` (purls, exact versions, summary, GitHub SBOM merge). `vulns.py`: opt-in OSV lookup at build time.
- `analyzers/flags.py` (repo findings), `ai_risk.py` (AI asset findings), `reusables.py` (building blocks, cross-repo refs), `org.py` (build-time links and calendar-based flags), `reference.py` (EOL and model retirement dates: update when vendors announce changes).
- `scanner.py` orchestrates; `outputs/` writes JSON, SQLite, Backstage, CycloneDX; `query.py` is shared by the CLI and `mcp_server.py`.

## Conventions

- Detectors must never raise on bad input: catch, record in `scan_errors`, move on.
- Never persist secrets: MCP env values, `.env` contents and tokens stay out of outputs.
- Every new detector gets a fixture in `tests/test_scan.py`.
- GitHub Actions are pinned to full commit SHAs with a version comment.
