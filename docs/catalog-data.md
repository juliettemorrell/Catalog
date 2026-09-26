# Catalog data reference

The authoritative definitions are the Pydantic models in [`src/repo_catalog/models.py`](../src/repo_catalog/models.py), exported as JSON Schema in [`schema/`](../schema). This page explains what each field means and where it comes from.

## Output files (`data/`)

| File | Contents |
|---|---|
| `repos/<owner>__<name>.json` | Source of truth: one repo record plus its AI assets. |
| `catalog.json` | `{meta, repos: Repo[]}`, loaded by the web UI. |
| `ai-assets.json` | `{meta, assets: AIAsset[]}`, loaded by the web UI. |
| `catalog.db` | SQLite with FTS5 (tables below). |
| `backstage-entities.yaml` | One Backstage `Component` per repo. |
| `ai-bom.cdx.json` | CycloneDX 1.6 AI bill of materials. |

## Repo

| Field | Meaning | Source |
|---|---|---|
| `id`, `name`, `owner`, `url` | `owner/name` identity | GitHub |
| `description`, `topics`, `homepage`, `visibility`, `archived`, `fork`, `license`, `stars`, `pushed_at` | GitHub metadata | GitHub API (license falls back to the LICENSE file) |
| `lifecycle` | `archived`; `stale` (no commit in 12 months, or declared deprecated); `maintained` (3–12 months); `active` | git history + declared |
| `capabilities` | What the code can do (`payments`, `pdf`, `oauth`, `rag`…) | dependency/file rules (+ LLM) |
| `github_languages` | Linguist bytes per language | GitHub API |
| `declared` | Owner, system, domain, lifecycle, type, tier, tags, links, APIs as the team declared them | `catalog-info.yaml`, `cortex.yaml`, `opslevel.yml`, `compass.yml`, custom properties |
| `summary.one_liner` | Best short description: GitHub description, else manifest description, else first README sentence | |
| `summary.readme_title/excerpt/key_features` | First heading, first paragraphs and the "Features" bullets of the README | README |
| `summary.purpose/domains/reuse_notes` | Plain-language purpose, domain tags and what others could borrow | Claude (`--llm`), `summary.source = "llm"` |
| `stack.*` | `primary_language`, `languages` (files/lines/%), `frameworks`, `libraries`, `databases`, `messaging`, `auth`, `ai`, `cloud`, `infrastructure`, `ci_cd`, `testing`, `linting`, `build_tools`, `observability`, `package_managers`, `runtimes` | manifests, config files, workflow `uses:` |
| `dependencies[]` | `name`, `version` (as declared), `ecosystem`, `scope` (runtime/dev/peer/optional/build, or transitive for Go `// indirect`; transitive deps never count toward the stack), `manifest` path | manifests |
| `structure.repo_type` | `service`, `web-app`, `full-stack-app`, `library`, `cli`, `mcp-server`, `monorepo`, `data-app`, `mobile-app`, `desktop-app`, `infrastructure`, `data-science`, `docs`, `scripts` | heuristics over the above |
| `structure.*` | `packages`, `entrypoints`, `api_specs`, `dockerfiles`, `docs`, `top_level`, `file_count`, `total_lines` | file tree |
| `practices` | `score` 0–100, `grade` A–F (≥85/70/55/40), `checks[]` with `id`, `category`, `label`, `passed`, `weight`, `evidence` | see below |
| `ownership` | `codeowners`, `top_contributors`, `contributor_count`, `commit_count`, `first_commit`, `last_commit` | CODEOWNERS, git log |
| `ai` | `has_ai`, `asset_count`, `asset_kinds`, `ecosystems`, `sdks`, `models`, `mcp_servers_provided`, `mcp_servers_consumed` | AI detectors |
| `scanned_at`, `scanner_version`, `scan_errors` | Provenance of the record | scanner |

### Practice checks

| id | Weight | Passes when |
|---|---|---|
| `readme` / `readme-substantial` | 3 / 1 | README exists / is ≥ 800 chars |
| `license` | 2 | LICENSE/COPYING present |
| `contributing`, `changelog`, `docs` | 1 each | CONTRIBUTING, CHANGELOG/changesets, `docs/` or ADRs |
| `codeowners` | 2 | CODEOWNERS present |
| `descriptor` | 1 | catalog descriptor present |
| `description`, `topics` | 1 each | set on GitHub |
| `security-policy` | 1 | SECURITY.md |
| `dependency-updates` | 2 | Dependabot or Renovate |
| `lockfile` | 2 | lockfile committed (or no dependencies) |
| `no-env-files` | 2 | no `.env` files committed (`.env.example` is fine) |
| `actions-pinned` | 1 | every `uses:` is pinned to a 40-char SHA |
| `workflow-permissions` | 1 | every workflow declares `permissions:` |
| `tests` | 3 | test files exist |
| `linter` | 2 | linter/formatter configured |
| `type-checking` | 1 | TypeScript/mypy/Pyright or a statically typed primary language |
| `editorconfig`, `pre-commit` | 1 each | `.editorconfig`; pre-commit or Husky |
| `ci` | 3 | a CI system is configured |
| `ci-runs-tests` | 2 | CI config invokes a test runner |
| `release-automation` | 1 | release-please, GoReleaser, Changesets or semantic-release |
| `gitignore` | 1 | `.gitignore` present |

## AIAsset

| Field | Meaning |
|---|---|
| `id` | Stable hash of repo + path + kind + name |
| `kind` | `skill`, `agent`, `command`, `prompt`, `instructions`, `mcp-server`, `mcp-config`, `hook`, `plugin`, `eval`, `workflow`, `sdk-usage` |
| `ecosystem` | `claude-code`, `agent-skills`, `agents-md`, `agent-plugins`, `copilot`, `gh-aw` (agentic workflows), `cursor`, `windsurf`, `cline`, `roo`, `kiro`, `amazon-q`, `junie`, `gemini`, `codex`, `opencode`, `continue`, `trae`, `augment`, `firebase-studio`, `antigravity`, `factory`, `a2a`, `mcp`, `crewai`, `langgraph`, `promptfoo`, `prompty`, `github-models`, `inline`, `generic`, or an SDK key for `sdk-usage` (`anthropic`, `openai`, `bedrock`, `snowflake-cortex`…) |
| `name`, `title`, `description` | From frontmatter/manifest; commands are named `/command` (Claude Code subfolders add a `namespace:<folder>` tag) or `/namespace:command` for other tools |
| `repo`, `path`, `url` | Location; `url` is a permalink at the scanned commit (with `#L<line>` for code) |
| `scope` | `repo` or `plugin` (shipped inside a plugin) |
| `confidence`, `detector` | `high` for file conventions, `medium` for heuristics over source code; which rule fired |
| `frontmatter` | Parsed metadata (YAML frontmatter, JSON/TOML fields, MCP server summary, hook commands…) |
| `tools` | Allowed tools (skills/agents/commands), tools exposed (MCP servers), skills (A2A) |
| `models`, `providers` | Model IDs and LLM providers referenced |
| `triggers` | Globs/`applyTo`, `alwaysApply`, hook events and matchers, workflow events |
| `arguments` | `argument-hint`, `$ARGUMENTS`, template variables |
| `mcp_servers` | MCP servers configured or required |
| `tags`, `license`, `version` | From metadata (+ LLM tags) |
| `content`, `content_truncated`, `excerpt`, `headings` | Full text up to 100 KB; for code-derived assets, the relevant snippet |
| `files` | Files bundled with a skill or plugin |
| `line_count`, `word_count`, `token_estimate` | Size (tokens ≈ chars / 4) |
| `last_modified`, `last_author`, `commit_count` | From `git log` on the file |
| `quality_score`, `quality_notes` | 0–100 heuristic: description present and well-sized, body substance, structure, examples, length, plus kind-specific checks (Agent Skills naming rules, least-privilege tools, parameters, build/test instructions) |
| `summary`, `use_cases`, `category` | Claude (`--llm`) |
| `duplicates` | IDs of assets with byte-identical content elsewhere in the org |

## SQLite (`catalog.db`)

Tables: `repos` (flat columns + `json`), `repo_tech(repo_id, category, name)`, `repo_capabilities`, `repo_topics`, `repo_languages`, `dependencies`, `packages`, `practice_checks`, `ai_assets` (flat columns + `content` + `json`), `asset_tools`, `asset_models`, `asset_tags`, and `meta`. Full-text search: `repos_fts`, `assets_fts` (unicode61, prefix matching). Views: `tech_usage`, `dependency_usage`.

```sql
-- Which repos already integrate Stripe, newest first?
SELECT r.id, r.one_liner FROM repos r JOIN repo_tech t ON t.repo_id = r.id
WHERE t.name = 'Stripe' ORDER BY r.last_commit DESC;

-- Our standard Python web stack
SELECT name, repo_count FROM tech_usage WHERE category = 'frameworks' LIMIT 10;

-- Services missing tests
SELECT r.id FROM repos r JOIN practice_checks c ON c.repo_id = r.id
WHERE r.repo_type = 'service' AND c.check_id = 'tests' AND c.passed = 0;

-- Best skills about testing
SELECT a.name, a.repo_id, a.quality_score FROM assets_fts f JOIN ai_assets a ON a.id = f.id
WHERE assets_fts MATCH 'test*' AND a.kind = 'skill' ORDER BY a.quality_score DESC;
```
