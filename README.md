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
- **Dependencies**: every declared dependency with version, scope and manifest. Covers npm, PyPI (requirements, pyproject, Poetry, uv, Pipenv), Go, Cargo, Maven/Gradle, Bundler, Composer, NuGet and pub.
- **Structure**: repo type (service, web-app, library, cli, mcp-server, monorepo, infrastructure…), packages, entrypoints, API specs, Dockerfiles, docs.
- **Best practices**: 25 weighted checks → a 0–100 score and A–F grade, with evidence. The checks cover docs, governance, security (lockfiles, Dependabot, committed `.env` files, SHA-pinned Actions, workflow permissions), quality (tests, linters, typing) and delivery (CI runs tests, release automation).
- **Ownership**: CODEOWNERS, declared owner/system/lifecycle (from `catalog-info.yaml`, `cortex.yaml`, `opslevel.yml`, `compass.yml`, or GitHub custom properties), top contributors, commit history and lifecycle (active / maintained / stale / archived).

Field-by-field reference: [docs/catalog-data.md](docs/catalog-data.md). JSON Schemas: [`schema/`](schema).

## Querying it

**Web UI** (`site/`): instant search with facets, detail drawers, an insights dashboard and CSV export. The query syntax is shared across the UI:

```
payments lang:python -type:library     fastapi missing:tests grade:D
kind:skill eco:claude-code             kind:mcp-server tool:jira
cap:pdf                                uses:anthropic ai:yes
```

**CLI**

```bash
repo-catalog search "stripe webhooks"
repo-catalog search "code review" --assets
repo-catalog sql "SELECT name, repo_count FROM tech_usage WHERE category='frameworks'"
repo-catalog sql "SELECT repo_id FROM practice_checks WHERE check_id='tests' AND passed=0"
```

**MCP server** for SDLC and coding agents. `.mcp.json` in this repo already registers it for Claude Code:

```json
{ "mcpServers": { "repo-catalog": { "command": "uv", "args": ["run", "repo-catalog", "mcp", "--out", "data"] } } }
```

Tools: `search_repos`, `get_repo`, `search_ai_assets`, `get_ai_asset`, `repos_using`, `technology_usage`, `sql` (read-only). The skill in [`.claude/skills/repo-catalog`](.claude/skills/repo-catalog/SKILL.md) teaches an agent how to use them for prior-art searches.

## Running it on a schedule

[`.github/workflows/catalog.yml`](.github/workflows/catalog.yml) scans nightly and on demand. It uploads the data and the built site as workflow artifacts, and can deploy to GitHub Pages.

1. **Auth.** Create a GitHub App with read-only *Contents* and *Metadata* permissions, plus *Custom properties* read on the org, and install it on the org. Set `vars.CATALOG_APP_ID` and `secrets.CATALOG_APP_PRIVATE_KEY`. A fine-grained PAT in `secrets.CATALOG_TOKEN` also works. An App is preferred because its rate limits scale with the org and the token is short-lived.
2. Set `vars.CATALOG_ORG` if the org differs from this repo's owner.
3. *Optional:* add `secrets.ANTHROPIC_API_KEY` and set `vars.CATALOG_LLM=true` to turn on summaries. Responses are cached, so only changed repos are re-summarized. The default model is `claude-opus-5`; override it with `--llm-model`.
4. *Optional:* set `vars.CATALOG_PUBLISH_PAGES=true` to deploy the site.

> **Privacy:** the catalog describes private repositories: names, READMEs, dependencies, prompts. Only publish to Pages when Pages access is restricted to your org (private Pages on GitHub Enterprise Cloud), or host `site/dist` behind SSO. This repository is public, so keep `data/` out of git (it is ignored by default).

## Development

```bash
uv sync --all-extras
uv run pytest && uv run ruff check src tests && uv run ruff format --check src tests && uv run mypy
cd site && npm ci && npm run build
```

To add a technology, add a line to the tables in `rules.py`. For a new AI convention, add a row to `MARKDOWN_RULES` or a method on `FileDetector` in `ai_files.py`; for patterns found in code, extend `ai_code.py`. Add a fixture file to `tests/test_scan.py` for any new detector.

Design notes and prior art: [docs/research.md](docs/research.md).
