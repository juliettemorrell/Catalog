# Research notes and design decisions

What already exists, what we borrowed, and why this is a small purpose-built scanner rather than an off-the-shelf product.

## Prior art

| Area | Existing options | What we took |
|---|---|---|
| Service catalogs | Backstage, Port, Cortex, OpsLevel, Atlassian Compass | Backstage's entity vocabulary (`owner`, `system`, `lifecycle`, `type`, `providesApis`…). We **ingest** existing `catalog-info.yaml` / `cortex.yaml` / `opslevel.yml` / `compass.yml` as ground truth and **emit** Backstage entities (`backstage-entities.yaml`), so this can seed or feed a portal. |
| GitHub-native metadata | Repo topics, languages API, org **custom properties**, CODEOWNERS, dependency graph | Topics, linguist byte counts, custom properties (one paginated call per org), CODEOWNERS. |
| Stack detection | github-linguist / go-enry, `@specfy/stack-analyser`, syft, OSS Review Toolkit | Linguist data comes from the API. Everything else is a dependency-free rule table (400+ technologies) that reads manifests directly: no JVM/Go binaries to install, and easy to extend with org-specific libraries. |
| Repo health | OpenSSF Scorecard, repolinter (archived 2026) | A Scorecard-inspired subset that can be verified from a checkout (security policy, pinned Actions, workflow permissions, dependency updates, lockfiles, CI runs tests…), weighted into a score. Scorecard itself can be layered on for public repos. |
| AI-BOM | CycloneDX 1.6/1.7 ML-BOM (ECMA-424), SPDX 3 AI profile; scanners such as cisco-ai-defense/aibom, agent-bom, snyk/agent-scan | Output a CycloneDX 1.6 BOM (`ai-bom.cdx.json`): models as `machine-learning-model`, SDKs as `library`, MCP servers as `application`, prompts/skills/rules as `data`. The existing scanners focus on security posture; none catalogs skills, prompts and rules as reusable assets with content and quality. |
| Skill indexes | skills.sh, Agent Skills spec (agentskills.io) | Validate against the Agent Skills spec: `name` lowercase-hyphenated ≤ 64 chars and matching its folder, `description` ≤ 1024 chars, optional `license`, `compatibility`, `metadata`, `allowed-tools`. |

## AI asset conventions tracked (2026)

- **Claude Code**: `CLAUDE.md` (nested), `.claude/skills/*/SKILL.md`, `.claude/agents/*.md` (`name`, `description`, `tools`, `model`…), `.claude/commands/**/*.md` (`argument-hint`, `allowed-tools`), `.claude/rules/`, output styles, hooks in `.claude/settings.json`, `.mcp.json`, plugins (`.claude-plugin/plugin.json`, `marketplace.json`, root `skills/`, `agents/`, `commands/`, `hooks/hooks.json`).
- **Open standards**: Agent Skills (`SKILL.md`), `AGENTS.md` (Agentic AI Foundation), MCP (servers and `server.json` registry manifests), A2A agent cards, `llms.txt`.
- **GitHub Copilot**: `.github/copilot-instructions.md`, `.github/instructions/*.instructions.md` (`applyTo`), `.github/prompts/*.prompt.md`, `.github/agents/*.agent.md` (chat modes are deprecated but still scanned), `.github/skills/`.
- **Other agents**: Cursor (`.cursor/rules/*.mdc` with `globs`/`alwaysApply`, `.cursorrules`, commands, `mcp.json`), Windsurf, Cline, Roo (rules and `.roomodes`), Kiro steering, Amazon Q rules, JetBrains Junie, Continue, Gemini CLI (`GEMINI.md`, TOML commands, extensions), OpenAI Codex, OpenCode.
- **Frameworks**: Prompty, GitHub Models `.prompt.yml`, promptfoo, CrewAI YAML, LangGraph (`langgraph.json`, `StateGraph`), OpenAI Agents SDK, Claude Agent SDK, Google ADK, PydanticAI, AutoGen, smolagents, Mastra, Semantic Kernel.
- **LLM usage in code**: provider SDK imports and call sites, raw HTTP to provider APIs, warehouse-native LLMs (Snowflake Cortex, Databricks), model identifiers.

## Key decisions

- **Clone, don't crawl the API.** A blobless clone (`--filter=blob:none`) gives full commit history for provenance while only downloading the current tree. It costs one git operation per changed repo instead of hundreds of content API calls, and it works the same against GHES. Discovery uses GraphQL (one call per 50 repos) and falls back to REST automatically where GraphQL is blocked.
- **Incremental by HEAD SHA + scanner version.** Nightly runs over a large org only touch repos that changed.
- **Deterministic first, LLM second.** Every fact is extracted by rules and is reproducible. Claude is optional and only writes clearly-labelled summary fields (`summary.source = "llm"`). Its inputs are hashed so unchanged repos are never re-billed.
- **Never store secrets.** MCP configs keep server names, commands and env **variable names** only. Committed `.env` files are flagged, not read.
- **One JSON file per repo** is the source of truth (diffable, mergeable). Aggregates, SQLite and exports are rebuilt from it (`repo-catalog build`).
- **Static site + SQLite + MCP** serve three audiences: people browsing, analysts with SQL, and agents. The static site needs no backend and can be hosted anywhere behind SSO. For very large orgs (10k+ repos), switch the site to sql.js-httpvfs over `catalog.db`.

## Limits and next steps

- Heuristic detectors (inline prompts, code-defined agents, hand-written MCP servers) are marked `confidence: medium`.
- Dependency lists are what manifests declare. Lockfile resolution and vulnerability data can come from GitHub's SBOM endpoint (`/dependency-graph/sbom`) if needed.
- Possible additions: team ownership via GitHub teams, PR/deploy frequency (DORA) from the API, OpenSSF Scorecard for public repos, embeddings for semantic "find similar code" search.
