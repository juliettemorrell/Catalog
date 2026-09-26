---
name: repo-catalog
description: Search the org-wide repository catalog and AI asset library for prior art. Use when planning or implementing a change and you want existing code, services, libraries, skills, prompts or MCP servers to reuse, or to learn how the org usually builds something (standard stack, conventions, owners).
allowed-tools: mcp__repo-catalog__search_repos mcp__repo-catalog__get_repo mcp__repo-catalog__search_ai_assets mcp__repo-catalog__get_ai_asset mcp__repo-catalog__repos_using mcp__repo-catalog__technology_usage mcp__repo-catalog__sql
---

# Repo catalog: finding prior art

The `repo-catalog` MCP server exposes a catalog of every repository in the org and an AI asset library. Consult it **before** writing something new.

## Workflow

1. **Frame the need** as capabilities and technologies, e.g. "send transactional email", "FHIR patient lookup", "Stripe webhooks", "PDF generation".
2. **Search broadly, then narrow.**
   - `search_repos(query_text=..., capability=..., technology=..., language=...)` returns candidates with their purpose and practices score.
   - `repos_using(technology="stripe")` shows every repo that depends on a library or framework.
   - `technology_usage(category="frameworks")` shows what the org standardizes on. Prefer the majority choice unless there's a reason not to.
3. **Inspect the best 2–3 candidates** with `get_repo(repo_id)`. Look at `summary.reuse_notes`, `structure.packages` (importable libraries), `structure.entrypoints` and `api_specs`, and `practices` (prefer grade A/B, active lifecycle). The owners are in `declared.owner` and `ownership.codeowners`.
4. **For AI work**, check the asset library first:
   - `search_ai_assets(query_text=..., kind="skill" | "agent" | "prompt" | "mcp-server" | "instructions")`
   - `get_ai_asset(id)` returns the full content, so you can reuse or adapt it. Prefer high `quality_score`. `duplicates` shows where a copy already lives.
5. **Report** what you found: repo, path, permalink `url`, why it fits, and any caveats (stale, low score, different stack). If nothing fits, say so explicitly before building new.

## Tips

- Free-text search is stemmed and prefix-matched. If it returns nothing, it falls back to OR, so keep queries short and specific.
- For anything the tools don't cover, use `sql` (read-only). The tables and views are listed in the server instructions; for example:
  `SELECT name, repo_count FROM dependency_usage WHERE ecosystem='npm' LIMIT 20`.
- Scan data can be up to a day old. Confirm details in the linked source before depending on them.
