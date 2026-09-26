# Repo Catalog

Scan every repository in a GitHub org and produce two catalogs:

1. **AI Asset Library**: every skill, subagent, slash command, prompt, rules/instructions file, MCP server, MCP config, hook, plugin, eval, agent workflow and LLM SDK integration in the org. Each one is parsed, scored and linked back to its source.
2. **Repository Catalog**: what each repo is and does, its stack, dependencies, structure, owners, activity and best-practice health. Built so people and SDLC agents can find code to reuse and learn how the org builds software.

Both catalogs are exposed four ways. There's a static web UI with instant search, and a SQLite database with full-text search. There's an **MCP server** that agents can query. There are also standard exports: Backstage entities and a CycloneDX AI-BOM.

```
GitHub org ──► discover (GraphQL, REST fallback) ──► blobless clone (incremental by HEAD SHA)
                                                        │
          ┌──────────────── analyzers ──────────────────┤
          │ manifests · stack rules · languages · README │  AI: file conventions · source code
          │ practices · CODEOWNERS · git history         │  (skills, agents, prompts, MCP, SDKs…)
          └──────────────────────┬───────────────────────┘
                                 ▼  optional: Claude summaries (cached)
        data/repos/*.json ─► catalog.json · ai-assets.json · catalog.db (FTS5)
                               backstage-entities.yaml · ai-bom.cdx.json
                                 │
             ┌───────────────────┼────────────────────┐
         site/ (web UI)     repo-catalog mcp      repo-catalog search / sql
```

## Quick start

```bash
uv sync --all-extras                        # or: pip install -e ".[llm,mcp]"
export GITHUB_TOKEN=...                     # read-only: Contents + Metadata
uv run repo-catalog scan --org my-org       # writes ./data
cd site && npm ci && npm run dev            # open http://localhost:5173
```

Other sources and options:

```bash
repo-catalog scan --repo my-org/api --repo my-org/web   # specific repos
repo-catalog scan --local ~/code                        # folders you already cloned, no network
repo-catalog scan --org my-org --llm                    # add Claude summaries (ANTHROPIC_API_KEY)
repo-catalog scan --org my-org --match '^svc-' --limit 20 --skip-archived
```

Re-runs are incremental: a repo whose default-branch HEAD hasn't changed is reused without cloning or analysis. Use `--force` to rescan everything.

## What gets cataloged

### AI Asset Library

| Kind | Detected from |
|---|---|
| `skill` | `**/SKILL.md` (Agent Skills spec: `.claude/skills`, `.github/skills`, `.agents/skills`, plugin `skills/`), including bundled scripts/references |
| `agent` | `.claude/agents/*.md`, Copilot `.github/agents/*.agent.md` and chat modes, OpenCode agents, Roo modes, CrewAI `config/agents.yaml`, A2A agent cards, agents defined in code (OpenAI Agents SDK, Claude Agent SDK, Google ADK, PydanticAI, AutoGen, smolagents, Mastra…) |
| `command` | `.claude/commands`, Copilot `.github/prompts/*.prompt.md`, Cursor/Windsurf/Codex/OpenCode/Continue commands, Gemini CLI `.gemini/commands/*.toml` |
| `prompt` | `*.prompty`, `*.prompt.yml`, `*.prompt(.md)`, `prompts/` folders, `*system-prompt*` files, Claude output styles, **prompts embedded in code** (`SYSTEM_PROMPT = """…"""`, `instructions: \`…\``) |
| `instructions` | `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, Copilot instructions, Cursor/Windsurf/Cline/Roo/Kiro/Amazon Q/Junie/Continue rules, `llms.txt` |
| `mcp-server` | MCP servers implemented in the repo (Python/TS/Go/C#/Java SDKs and hand-written JSON-RPC), with their tools and descriptions; MCP registry `server.json` |
| `mcp-config` | `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, Gemini/Codex/Kiro/Roo configs (env **values are never stored**, only names) |
| `hook` | Claude Code hooks in `.claude/settings.json` and plugin `hooks/hooks.json` |
| `plugin` | Claude Code plugins and marketplaces, Gemini CLI extensions |
| `eval` | promptfoo configs and CI actions |
| `workflow` | LangGraph apps/graphs, CrewAI task files, AI agents in GitHub Actions (Claude Code, Codex, Gemini CLI, GitHub Models) |
| `sdk-usage` | Per-repo usage of each LLM SDK/API (Anthropic, OpenAI, Bedrock, Vertex, Gemini, Azure OpenAI, LangChain, LlamaIndex, Vercel AI, LiteLLM, Snowflake Cortex, raw HTTP…) with call-site snippets and models used |

Every asset records its kind, ecosystem, name, description, parsed frontmatter, tools, models, triggers (globs, events), arguments, tags, license and version. It also records the full content (capped at 100 KB), headings, bundled files, and size in lines, words and estimated tokens. Provenance comes from git: last edit, author and commit count. Each asset gets a GitHub permalink, a **quality score with actionable notes**, and links to **identical copies elsewhere in the org**. With `--llm`, Claude adds a summary, category, use cases and tags.

### Repository Catalog

- **Summary**: the GitHub description, README title/excerpt and key features. With `--llm` you also get a plain-language purpose, domains and **reuse notes** (what other teams could borrow).
- **Stack**: languages (by lines), frameworks, notable libraries, data stores, messaging, auth, AI/ML, cloud, infra (Docker, Kubernetes, Terraform…), CI/CD, testing, quality tooling, build tools, runtimes and package managers. The rules live in [`analyzers/rules.py`](src/repo_catalog/analyzers/rules.py): 400+ technologies, plain-text tables that are easy to extend.
- **Capabilities**: tags such as `payments`, `pdf`, `oauth`, `queue`, `healthcare`, `vector-search`. They answer "who already does X?".
- **Dependencies**: every declared dependency with its declared range, the **exact locked version**, scope (runtime/dev/peer/optional/build/transitive), manifest and **purl**, plus every **transitive** dependency from lockfiles. Deduped where one repo repeats itself, never where manifests differ.
  - *Package managers*: npm/yarn/pnpm/bun, PyPI (requirements, pyproject, setup.py, setup.cfg, Poetry, uv, PDM, Pipenv, Conda), Go, Cargo, Maven/Gradle/sbt, NuGet (incl. central package management and MSBuild SDKs), Bundler, Composer, pub, Swift PM, CocoaPods, Hex, CRAN, Bazel, vcpkg, Conan, Deno/JSR.
  - *Lockfiles*: package-lock/npm-shrinkwrap, yarn (v1 and Berry), pnpm (v5 to v9), bun.lock, poetry.lock, uv.lock, pdm.lock, Pipfile.lock, Cargo.lock, Gemfile.lock, composer.lock, packages.lock.json, pubspec.lock, gradle.lockfile, mix.lock, Package.resolved, Podfile.lock, renv.lock, `.terraform.lock.hcl`.
  - *What it runs on and builds with*: container images (Dockerfiles with build vs runtime stages, Compose, Kubernetes manifests), Terraform providers and modules, Helm chart dependencies, GitHub Actions (with the pinned ref), pre-commit hooks and Ansible Galaxy content.
  - *Optional*: `--github-sbom` merges GitHub's own dependency graph; `--osv` checks every locked version against [OSV.dev](https://osv.dev) and raises `vulnerable-dependency` findings with the fixed version.
  - *Outputs*: a CycloneDX 1.6 **SBOM per repo** in `data/sbom/` (validated against the official schema) for Dependency-Track, GitHub or any SBOM tooling.
- **Structure**: repo type (service, web-app, library, cli, mcp-server, monorepo, infrastructure…), packages, entrypoints, API specs, Dockerfiles, docs.
- **Best practices**: 25 weighted checks → a 0–100 score and A–F grade, with evidence. The checks cover docs, governance, security (lockfiles, Dependabot, committed `.env` files, SHA-pinned Actions, workflow permissions), quality (tests, linters, typing) and delivery (CI runs tests, release automation).
- **Ownership**: CODEOWNERS, declared owner/system/lifecycle (from `catalog-info.yaml`, `cortex.yaml`, `opslevel.yml`, `compass.yml`, or GitHub custom properties), top contributors, commit history and lifecycle (active / maintained / stale / archived).

### Building blocks and relationships

- **Building blocks** other teams can adopt as-is: GitHub Actions (`action.yml`, with inputs/outputs), reusable workflows (`on: workflow_call`), Terraform modules (variables, outputs, providers, README blurb), Helm charts, project templates (cookiecutter, copier, Backstage scaffolder, GitHub template repos), APIs (OpenAPI/AsyncAPI operations, gRPC services, GraphQL fields) and shared config packages (`eslint-config`, `tsconfig`…).
- **Relationships**: which org repos each repo depends on, and which depend on it, resolved across the whole org from published packages (direct and transitive, any ecosystem), `uses:` of actions and reusable workflows, Terraform `source = "github.com/…"`, `ghcr.io/…` images in Dockerfiles, Compose and Kubernetes, git dependencies, submodules, pre-commit hooks, MCP servers a repo configures that another repo implements, and what teams declared in Backstage (`dependsOn`, `consumesApis`/`providesApis`). Exported to Backstage as `dependsOn`.

### Findings (flags)

Things worth a human's attention, each with severity, location and a line number where it applies. Secret values are never stored: only the kind of secret and where it is.

| Category | Flags |
|---|---|
| Security | known-vulnerable dependency versions (`--osv`), committed secrets (GitHub/AWS/Anthropic/OpenAI/Slack/Stripe/… keys, private keys; placeholders and test paths are down-ranked), GitHub Actions script injection (`${{ github.event.issue.title }}` in `run:`), `pull_request_target` checkouts of untrusted PR code, `:latest`/untagged base images, containers running as root |
| Maintenance | end-of-life runtimes (Python, Node.js, Java, .NET, Go, Ruby, PHP pinned in Dockerfiles, version files, CI or manifests; dates from endoflife.date), depending on an archived org repo |
| Ownership | no CODEOWNERS or declared owner, bus factor 1 |
| AI governance | retired/deprecated model IDs (Bedrock/Vertex spellings too), agent approvals disabled (`bypassPermissions`, `--dangerously-skip-permissions`, `--yolo`, Copilot auto-approve, Codex `danger-full-access`), unrestricted agent shell, `curl \| sh` in hooks and skills, unpinned MCP packages (`npx -y pkg`, `uvx pkg`, `:latest` images), credentials written into MCP configs, MCP over plain HTTP, secrets inside AI files |

Calendar-dependent flags (EOL, retired models) and cross-repo ones are recomputed on every `build`, so they stay current for repos that were not re-scanned. Reference dates live in [`analyzers/reference.py`](src/repo_catalog/analyzers/reference.py).

Field-by-field reference: [docs/catalog-data.md](docs/catalog-data.md). JSON Schemas: [`schema/`](schema).

## Querying it

**Web UI** (`site/`): instant search over repos, AI assets and building blocks, with facets, detail drawers, an insights dashboard (findings, most depended-on repos, version drift) and CSV export. The query syntax is shared across the UI:

```
payments lang:python -type:library     fastapi missing:tests grade:D
kind:skill eco:claude-code             kind:mcp-server tool:jira
cap:pdf                                uses:anthropic ai:yes
fw:fastapi data:postgresql minscore:70  kind:skill minq:60 dup:no
sev:high flag:committed-secret         reuse:terraform-module usedby:yes
dep:express vuln:yes                   depeco:terraform
```

Filters: `lang` (primary language), `anylang`, `fw`, `data`, `infra`, `tech` (any stack item, partial), `type`, `grade`, `cap`, `topic`, `owner`, `lifecycle`, `ai`, `uses`, `missing`, `has`, `is`, `minscore`, `flag`, `sev`, `reuse`, `usedby`, `dep`, `depeco`, `vuln`; for assets `kind`, `eco`, `repo`, `tool`, `model`, `tag`, `conf`, `scope`, `dup`, `minq`, `flag`, `sev`; for building blocks `kind`, `format`, `repo`, `lang`, `grade`, `lifecycle`. Prefix with `-` to exclude. Unknown keys are searched as text.

**CLI**

```bash
repo-catalog search "stripe webhooks"
repo-catalog search "code review" --assets
repo-catalog blocks "postgres" --kind terraform-module
repo-catalog deps lodash --version 4.17        # every repo shipping it, direct or transitive
repo-catalog flags --severity high --category security
repo-catalog sql "SELECT name, repo_count FROM tech_usage WHERE category='frameworks'"
repo-catalog sql "SELECT repo_id FROM practice_checks WHERE check_id='tests' AND passed=0"
```

**MCP server** for SDLC and coding agents. `.mcp.json` in this repo already registers it for Claude Code:

```json
{ "mcpServers": { "repo-catalog": { "command": "uv", "args": ["run", "--extra", "mcp", "repo-catalog", "mcp", "--out", "data"] } } }
```

Tools: `search_repos`, `get_repo`, `search_ai_assets`, `get_ai_asset`, `find_building_blocks`, `repo_relationships`, `list_flags`, `dependency_usage`, `repos_using`, `technology_usage`, `sql` (read-only). The skill in [`.claude/skills/repo-catalog`](.claude/skills/repo-catalog/SKILL.md) teaches an agent how to use them for prior-art searches.

## Running it on a schedule

[`.github/workflows/catalog.yml`](.github/workflows/catalog.yml) scans nightly and on demand. It uploads the data and the built site as workflow artifacts, and can deploy to GitHub Pages.

1. **Auth.** Create a GitHub App with read-only *Contents* and *Metadata* permissions, plus *Custom properties* read on the org, and install it on the org. Set `vars.CATALOG_APP_CLIENT_ID` (the App's Client ID) and `secrets.CATALOG_APP_PRIVATE_KEY`. A fine-grained PAT in `secrets.CATALOG_TOKEN` also works. An App is preferred because its rate limits scale with the org and the token is short-lived.
2. Set `vars.CATALOG_ORG` if the org differs from this repo's owner.
3. *Optional:* add `secrets.ANTHROPIC_API_KEY` and set `vars.CATALOG_LLM=true` to turn on summaries. Responses are cached, so only changed repos are re-summarized. The default model is `claude-opus-5`; override it with `--llm-model`.
4. *Optional:* set `vars.CATALOG_PUBLISH_PAGES=true` to deploy the site. Only do this if the Pages site is private to your org: the catalog describes private code.
5. The nightly job runs with `--osv --github-sbom`. OSV needs outbound access to `api.osv.dev`; the dependency graph needs it enabled on the repos (it is by default for public repos). Both degrade gracefully when unavailable.

> **Privacy:** the catalog describes private repositories: names, READMEs, dependencies, prompts. Only publish to Pages when Pages access is restricted to your org (private Pages on GitHub Enterprise Cloud), or host `site/dist` behind SSO. This repository is public, so keep `data/` out of git (it is ignored by default).

## Development

```bash
uv sync --all-extras
uv run pytest && uv run ruff check src tests && uv run ruff format --check src tests && uv run mypy
cd site && npm ci && npm run build
```

To add a technology, add a line to the tables in `rules.py`. For a new AI convention, add a row to `MARKDOWN_RULES` or a method on `FileDetector` in `ai_files.py`; for patterns found in code, extend `ai_code.py`. Add a fixture file to `tests/test_scan.py` for any new detector.

Design notes and prior art: [docs/research.md](docs/research.md).
