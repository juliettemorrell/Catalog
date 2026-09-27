# Catalog data reference

The authoritative definitions are the Pydantic models in [`src/repo_catalog/models.py`](../src/repo_catalog/models.py), exported as JSON Schema in [`schema/`](../schema). This page explains what each field means and where it comes from.

## Output files (`data/`)

| File | Contents |
|---|---|
| `repos/<owner>__<name>.json` | Source of truth: one repo record plus its AI assets. One JSON member per line (one line per dependency), so git diffs stay readable. A file whose content did not change is not rewritten. A record that no longer loads (hand-edited, or written by an incompatible version) is left out of the build with a WARNING, and `build`/`scan` exit `2`. |
| `catalog.json` | `{meta, repos: [...]}`: one slim list entry per repo, loaded by the web UI (see below). |
| `ai-assets.json` | `{meta, assets: [...]}`: one slim list entry per AI asset, loaded by the web UI (see below). |
| `site/repos/<owner>__<name>.json` | `{repo: Repo, assets: [{id, kind, name, path}]}`: the full repo record as built (direct dependencies, org links, build-time flags), loaded when the UI drawer opens. |
| `site/assets/<id>.json` | The full `AIAsset` (content, frontmatter, bundled files, duplicates), loaded when the UI drawer opens. |
| `site/insights.json` | `{version_drift: [...]}`: aggregates the UI Insights page needs from dependency versions, computed at build time. |
| `catalog.db` | SQLite with FTS5 (tables below). |
| `backstage-entities.yaml` | One Backstage `Component` per repo. |
| `ai-bom.cdx.json` | CycloneDX 1.6 AI bill of materials. |
| `sbom/<owner>__<name>.cdx.json` | CycloneDX 1.6 SBOM per repo: every dependency with purl, version, scope, and OSV advisories when built with `--osv`. |

`catalog.json` and `ai-assets.json` hold only what the web UI needs to list, search, filter, chart and export, so it loads fast at thousands of repos (at 4,000 repos and 34,000 assets: about 90 MB instead of 560 MB). Full records are in `site/` (one file per repo and per asset, fetched on demand), the per-repo files, `catalog.db` and the SBOMs; read those, not the list files, when you need complete data (`store.load_aggregates` does). A list entry differs from the full record as follows:

- **Repo entry**: the `Repo` fields `id name owner url description homepage topics visibility archived fork default_branch head_sha license stars pushed_at lifecycle capabilities summary dependency_summary ai flags reusables depends_on scanned_at`; `declared` with only `owner`, `system`; `stack` without `runtimes`/`runtime_versions` and `languages` as `{name, percent}`; `structure` as `{repo_type, is_monorepo, packages: [{name}]}`; `practices.checks` as `{id, label, passed}`; `ownership` as `{codeowners, last_commit}`. Instead of `dependencies` and `used_by`: `dependency_names` (unique direct dependency names), `vulnerable_dependencies` (names with known advisories) and `used_by_count`. Locked transitive dependencies are never in the web files.
- **Asset entry**: the `AIAsset` fields `id kind ecosystem name title description repo path url scope confidence tools models mcp_servers tags excerpt headings quality_score last_modified summary use_cases category flags`, plus `duplicate_count` instead of `duplicates`. No `content`, `frontmatter`, `files`, `quality_notes` or git provenance; the UI's full-text search covers the excerpt and headings, not the whole content (`catalog.db`'s `assets_fts` does).

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
| `dependencies[]` | `name`, `version` (as declared), `resolved` (exact version from a lockfile or an exact pin), `ecosystem`, `scope` (runtime/dev/peer/optional/build/transitive), `manifest` (for transitive deps: the lockfile), `purl`, `vulns` (OSV ids, with `--osv`). Ecosystems: npm, pypi, go, cargo, maven, gem, composer, nuget, pub, swift, cocoapods, hex, cran, conda, bazel, vcpkg, conan, jsr, deno, docker, terraform, helm, github-actions, pre-commit, ansible-galaxy. Only code-package ecosystems drive the tech stack; database/queue images and charts count as data stores | manifests, lockfiles, GitHub dependency graph (`--github-sbom`) |
| `dependency_summary` | `direct`, `transitive`, `ecosystems` (direct deps per ecosystem), `lockfile_coverage` (share of direct package deps with an exact version), `vulnerable` | derived |
| `structure.repo_type` | `service`, `web-app`, `full-stack-app`, `library`, `cli`, `mcp-server`, `monorepo`, `data-app`, `mobile-app`, `desktop-app`, `infrastructure`, `data-science`, `data-pipeline`, `examples`, `docs`, `scripts` | the product type (`structure.is_monorepo` says whether it holds several products) |
| `structure.*` | `packages`, `entrypoints`, `api_specs`, `dockerfiles`, `docs`, `top_level`, `file_count`, `total_lines` | file tree |
| `practices` | `score` 0–100, `grade` A–F (≥85/70/55/40), `checks[]` with `id`, `category`, `label`, `passed`, `weight`, `evidence` | see below |
| `ownership` | `codeowners`, `top_contributors`, `contributor_count`, `commit_count`, `first_commit`, `last_commit` | CODEOWNERS, git log |
| `ai` | `has_ai`, `asset_count`, `asset_kinds`, `ecosystems`, `sdks`, `models`, `mcp_servers_provided`, `mcp_servers_consumed` | AI detectors |
| `stack.runtime_versions[]` | Concrete pinned versions (`runtime`, `version`, `path`) from Dockerfiles, `.nvmrc`/`.python-version`/`.tool-versions`, `global.json`, CI `*-version:` inputs, csproj/pom/Gemfile/composer pins. Ranges and `go.mod`'s `go` line are compatibility, not pins, so they are skipped | files |
| `flags[]` | Findings: `id`, `category` (security, maintenance, ownership, ai-governance), `severity` (high, medium, low), `message`, `path`, `line`. See the table below | flag detectors |
| `reusables[]` | Building blocks: `kind` (action, reusable-workflow, terraform-module, helm-chart, template, api, config-package), `name`, `path`, `description`, `details` (inputs, secrets, variables, outputs, providers, operations and a sample, version…) | files |
| `references[]` | Pointers to other repos: `kind` (action, reusable-workflow, terraform, container, git), `target` (`owner/repo`, lowercase), `path` | workflows, `.tf`, Dockerfiles, `.gitmodules` |
| `depends_on[]`, `used_by[]` | Org repos linked by packages, actions, workflows, modules, images or git deps: `repo`, `via` (e.g. `npm @acme/ui`). Filled at build time, so only in `site/repos/*.json` and SQLite (`catalog.json` has `depends_on` and `used_by_count`), not per-repo files. Each list holds at most 200 links (a core library can be used by thousands of repos): when there are more, the strongest ones are kept (runtime before optional/dev/build/transitive, live repos before archived ones), still listed by repo name. The SQLite `repo_links` table has every link | org-wide |
| `scanned_at`, `scanner_version`, `scan_errors` | Provenance of the record | scanner |

### Flags

| id | Category | Severity | Raised when |
|---|---|---|---|
| `committed-secret` | security | high (low in test/example/docs paths) | A credential-shaped string with a real-looking value (GitHub, AWS, Anthropic, OpenAI, Slack, Google, GitLab, Stripe live, npm, Hugging Face, SendGrid, Azure storage, private key with a body). Only kind, file and line are stored |
| `workflow-script-injection` | security | high | Untrusted event text (issue/PR titles and bodies, comments, branch names, commit messages) interpolated into `run:` or `github-script` |
| `workflow-pwn-request` | security | high (medium behind an `environment:` approval) | `pull_request_target` job checks out the PR head |
| `docker-unpinned-base` | security | medium | `FROM image` or `:latest` without a digest |
| `docker-runs-as-root` | security | low | Final stage has no non-root `USER` |
| `eol-runtime` | maintenance | high (EOL > 1 year ago), medium (EOL passed), low (within 180 days) | A pinned runtime version past its end-of-life |
| `depends-on-archived` | maintenance | medium | Depends on an archived org repo |
| `no-owner` | ownership | low | No CODEOWNERS and no declared owner |
| `single-maintainer` | ownership | medium | 90%+ of 30+ human commits by one person |
| `deprecated-model` | ai-governance | high (retired), medium (deprecated), low (in example code) | A retired or deprecated model ID is referenced |
| `ai-permissions-bypassed` | ai-governance | high (medium in skills/agents/commands) | Committed agent config or automation disables approvals |
| `ai-unrestricted-shell` | ai-governance | medium in settings, low on assets | `Bash` allowed without a command scope |
| `ai-remote-code-exec` | ai-governance | high in hooks/workflows/plugins, medium in skills/commands | `curl … \| sh` and equivalents |
| `ai-mcp-auto-enabled`, `ai-personal-settings-committed` | ai-governance | low | `enableAllProjectMcpServers`, committed `settings.local.json` |
| `mcp-unpinned-package` | ai-governance | medium | MCP launcher fetches an unpinned package or image (`npx -y pkg`, `uvx pkg`, `docker run img:latest`); local runners like `tsx` are ignored |
| `mcp-inline-secret` | ai-governance | high | A literal credential in an MCP server's env/headers/args instead of `${VAR}` |
| `mcp-plaintext-http` | ai-governance | medium | Remote MCP server over `http://` (localhost excluded) |
| `secret-in-asset` | security | high | An AI file contained a credential (redacted in the catalog) |
| `vulnerable-dependency` | security | from the advisory (GHSA CRITICAL/HIGH = high, MODERATE = medium, LOW = low) | A locked dependency version has known OSV advisories (`--osv`); the message names the fixed version |

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
| `kind` | `skill`, `agent`, `command`, `prompt`, `instructions`, `mcp-server`, `mcp-config`, `settings`, `hook`, `plugin`, `eval`, `workflow`, `sdk-usage` |
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
| `duplicates` | IDs of assets with byte-identical content elsewhere in the org: at most 20 (the first copies in repo-name order); `ai_assets.duplicate_count` in SQLite has the total |
| `flags[]` | Governance findings for this asset (same shape as repo flags) |

## SQLite (`catalog.db`)

Tables: `repos` (flat columns + `json`: the full record without locked transitive dependencies, which are rows in `dependencies`), `repo_tech(repo_id, category, name)`, `repo_capabilities`, `repo_topics`, `repo_languages`, `dependencies`, `packages`, `practice_checks`, `ai_assets` (flat columns + `content` + `json`, plus space-separated `use_cases` and `tags`), `asset_tools`, `asset_models`, `asset_tags`, `flags(repo_id, asset_id, flag_id, category, severity, message, path, line)`, `reusables(repo_id, kind, name, path, description, details)`, `repo_links(repo_id, depends_on, via)`, `dependencies` (also `resolved`, `purl`, `vulns`, and `norm_name`: the indexed lookup key, lower case and PEP 503-normalized for PyPI, so `WHERE norm_name = 'typing-extensions'` finds `typing_extensions`), `runtime_versions`, and `meta`. Full-text search: `repos_fts`, `assets_fts` (unicode61, prefix matching; `assets_fts` is an external-content table over `ai_assets`, columns `id, name, description, summary, use_cases, content, tags`). Views: `tech_usage`, `vulnerable_dependencies`, `flag_summary`. `dependency_usage` and `dependency_versions` (version drift, by locked version) have the same columns as before plus `norm_name`, but are tables computed at build time: aggregating every transitive dependency of a large org takes seconds.

```sql
-- Which repos already integrate Stripe, newest first?
SELECT r.id, r.one_liner FROM repos r JOIN repo_tech t ON t.repo_id = r.id
WHERE t.name = 'Stripe' ORDER BY r.last_commit DESC;

-- Our standard Python web stack
SELECT name, repo_count FROM tech_usage WHERE category = 'frameworks' LIMIT 10;

-- Services missing tests
SELECT r.id FROM repos r JOIN practice_checks c ON c.repo_id = r.id
WHERE r.repo_type = 'service' AND c.check_id = 'tests' AND c.passed = 0;

-- High-severity security findings across the org
SELECT repo_id, flag_id, message, path, line FROM flags
WHERE category = 'security' AND severity = 'high' ORDER BY repo_id;

-- Exposure: which repos ship log4j-core 2.x, directly or transitively
SELECT repo_id, COALESCE(resolved, version) AS version, scope, manifest FROM dependencies
WHERE name = 'org.apache.logging.log4j:log4j-core' AND COALESCE(resolved, version) LIKE '2.%';

-- Blast radius: who depends on this repo, and how
SELECT repo_id, via FROM repo_links WHERE depends_on = 'acme/shared-ui';

-- Terraform modules we already have
SELECT repo_id, name, path, description FROM reusables WHERE kind = 'terraform-module';

-- Best skills about testing
SELECT a.name, a.repo_id, a.quality_score FROM assets_fts f JOIN ai_assets a ON a.id = f.id
WHERE assets_fts MATCH 'test*' AND a.kind = 'skill' ORDER BY a.quality_score DESC;
```
