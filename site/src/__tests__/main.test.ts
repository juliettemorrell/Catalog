// @vitest-environment jsdom
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

// The app against a mocked data folder: slim list files plus on-demand detail files.
const stack = {
  primary_language: "TypeScript", languages: [{ name: "TypeScript", percent: 100 }], frameworks: ["Express"], libraries: [],
  testing: [], linting: [], databases: [], messaging: [], cloud: [], infrastructure: [], ci_cd: [], observability: [],
  auth: [], ai: [], build_tools: [], package_managers: [],
};
const item = (id: string, purpose: string) => ({
  id, name: id.split("/")[1], owner: "acme", url: `https://github.com/${id}`, description: null, homepage: null, topics: [],
  visibility: "private", archived: false, fork: false, default_branch: "main", head_sha: null, license: null, stars: 0,
  pushed_at: "2026-01-01T00:00:00Z", lifecycle: "active", capabilities: ["payments"], declared: { owner: null, system: null },
  summary: { one_liner: null, readme_title: null, readme_excerpt: null, purpose, key_features: [], reuse_notes: null, domains: [], source: "readme" },
  stack, dependency_summary: { direct: 1, transitive: 0, ecosystems: { npm: 1 }, lockfile_coverage: 1, vulnerable: 0 },
  dependency_names: ["express"], vulnerable_dependencies: [],
  structure: { repo_type: "service", is_monorepo: false, packages: [] },
  practices: { score: 80, grade: "B", checks: [{ id: "tests", label: "Has tests", passed: true }] },
  ownership: { codeowners: [], last_commit: null },
  ai: { has_ai: true, asset_count: 1, asset_kinds: { skill: 1 }, ecosystems: [], sdks: [], models: [], mcp_servers_provided: [], mcp_servers_consumed: [] },
  flags: [], reusables: [], depends_on: [], used_by_count: 0, scanned_at: "2026-01-01T00:00:00Z",
});
const assetItem = {
  id: "abc123", kind: "skill", ecosystem: "claude-code", name: "review", title: null, description: "Reviews code",
  repo: "acme/web", path: ".claude/skills/review/SKILL.md", url: "https://github.com/acme/web/blob/main/x", scope: "repo",
  confidence: "high", tools: [], models: [], mcp_servers: [], tags: [], excerpt: "Check auth", headings: [], quality_score: 60,
  last_modified: null, summary: null, use_cases: [], category: null, flags: [], duplicate_count: 0,
};
const fullRepo = {
  ...item("acme/web", "Takes payments"), stack: { ...stack, runtimes: {}, runtime_versions: [], languages: [{ name: "TypeScript", files: 3, lines: 90, percent: 100 }] },
  declared: { owner: null, system: null, lifecycle: null, tier: null, source_files: [], links: [], custom_properties: {} },
  dependencies: [{ name: "express", version: "^4", ecosystem: "npm", scope: "runtime", manifest: "package.json", resolved: "4.19.2", purl: null, vulns: [] }],
  structure: { repo_type: "service", is_monorepo: false, packages: [], entrypoints: [], api_specs: [], dockerfiles: [], top_level: [], docs: [], file_count: 3, total_lines: 90 },
  practices: { score: 80, grade: "B", checks: [{ id: "tests", category: "quality", label: "Has tests", passed: true, weight: 1, evidence: "EVIDENCE-FROM-DETAIL" }] },
  ownership: { codeowners: [], top_contributors: [], contributor_count: 1, commit_count: 1, first_commit: null, last_commit: null },
  used_by: [], scan_errors: [],
};
const files: Record<string, unknown> = {
  "data/catalog.json": { meta: { generated_at: "g1", source: "test", repo_count: 2, asset_count: 1, llm_enriched: false, scanner_version: "t" },
    repos: [item("acme/web", "Takes payments"), item("acme/mail", "Sends email")] },
  "data/ai-assets.json": { meta: {}, assets: [assetItem] },
  "data/site/repos/acme__web.json": { repo: fullRepo, assets: [{ id: "abc123", kind: "skill", name: "review", path: assetItem.path }] },
  "data/site/assets/abc123.json": { ...assetItem, content: "# Review\n\nCONTENT-FROM-DETAIL", duplicates: [], frontmatter: {}, files: [],
    providers: [], triggers: [], arguments: [], quality_notes: [], detector: "skill", content_truncated: false },
  "data/site/insights.json": { version_drift: [] },
};
const fetched: string[] = [];
const fetchMock = vi.fn(async (url: string) => {
  fetched.push(url);
  const key = url.split("?")[0]!;
  const body = files[key];
  return { ok: body !== undefined, status: body === undefined ? 404 : 200, json: async () => structuredClone(body) };
});

const until = async (check: () => unknown, ms = 2000) => {
  const end = Date.now() + ms;
  while (!check()) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${check}`);
    await new Promise((r) => setTimeout(r, 10));
  }
};
const go = async (hash: string) => {
  location.hash = hash;
  window.dispatchEvent(new HashChangeEvent("hashchange"));
  await new Promise((r) => setTimeout(r, 0));
};

beforeAll(async () => {
  const html = readFileSync(resolve(__dirname, "../../index.html"), "utf8");
  document.body.innerHTML = html.slice(html.indexOf("<body>") + 6, html.indexOf("<script type=\"module\""));
  vi.stubGlobal("fetch", fetchMock);
  vi.stubGlobal("matchMedia", () => ({ matches: false }));
  Element.prototype.scrollIntoView = () => {};
  if (!globalThis.CSS?.escape) vi.stubGlobal("CSS", { escape: (s: string) => s.replace(/["\\]/g, "\\$&") });
  location.hash = "#/repos";
  await import("../main");
  await until(() => document.querySelectorAll("article.card").length === 2);
});
afterAll(() => vi.unstubAllGlobals());

describe("app shell", () => {
  it("renders repos from catalog.json without waiting for details", () => {
    expect(fetched[0]).toBe("data/catalog.json");
    expect(fetched.some((u) => u.includes("data/site/"))).toBe(false);
  });

  it("keeps the search box (same element, caret and text) while results update", async () => {
    const input = document.getElementById("q") as HTMLInputElement;
    input.focus();
    input.value = "email";
    input.dispatchEvent(new Event("input"));
    await until(() => location.hash.includes("q=email"));
    // typed on before the debounced render: the render must not reset the box
    input.value = "email s";
    input.setSelectionRange(7, 7);
    await go("#/repos?q=email");
    expect(document.getElementById("q")).toBe(input);
    expect(input.value).toBe("email s");
    expect(input.selectionStart).toBe(7);
    expect(document.activeElement).toBe(input);
    expect([...document.querySelectorAll("article.card h2")].map((h) => h.textContent)).toEqual(["mail"]);
  });

  it("syncs the box when the query changes from elsewhere", async () => {
    const input = document.getElementById("q") as HTMLInputElement;
    input.blur();
    await go("#/repos?q=cap%3Apayments");
    expect(document.getElementById("q")).toBe(input);
    expect(input.value).toBe("cap:payments");
    expect(document.getElementById("count")!.textContent).toContain("2 of 2");
  });

  it("loads the full repo record when its drawer opens", async () => {
    await go("#/repos?open=acme%2Fweb");
    const drawer = document.getElementById("drawer")!;
    expect(drawer.classList.contains("open")).toBe(true);
    await until(() => drawer.textContent!.includes("EVIDENCE-FROM-DETAIL"));
    expect(fetched).toContain("data/site/repos/acme__web.json?v=g1");
    expect(drawer.textContent).toContain("4.19.2"); // locked version: detail only
    expect(drawer.querySelector('a[href*="open=abc123"]')).not.toBeNull(); // its AI asset
  });

  it("loads asset content only for the asset drawer, and falls back to the summary when a detail file is missing", async () => {
    await go("#/assets?open=abc123");
    const drawer = document.getElementById("drawer")!;
    await until(() => drawer.textContent!.includes("CONTENT-FROM-DETAIL"));
    await go("#/repos?open=acme%2Fmail"); // no detail file for this one
    await until(() => drawer.textContent!.includes("could not be loaded"));
    expect(drawer.textContent).toContain("acme/mail");
  });

  it("renders Insights from the list files", async () => {
    await go("#/insights");
    await until(() => document.querySelector(".insights"));
    expect(document.querySelector(".insights")!.textContent).toContain("Primary languages");
  });
});
