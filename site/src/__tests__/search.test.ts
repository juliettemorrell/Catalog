// @vitest-environment jsdom
import { describe, expect, it } from "vitest";
import { applyFilters, facetValue, hasFilter, parseQuery, resolveQuery, REPO_FILTERS, ASSET_FILTERS, BLOCK_FILTERS, toggleFilter } from "../search";
import { normalizeRepo } from "../data";
import type { AssetItem, Block, Flag, Repo, RepoItem } from "../types";
import { countBy } from "../util";

// full records (as older catalogs had them) normalised to list entries, like the UI does
const repo = (over: Partial<Repo> & { lang?: string; fw?: string[]; langs?: string[] }): RepoItem =>
  normalizeRepo({
    id: over.id ?? "acme/x", name: "x", owner: "acme", topics: [], archived: false, fork: false,
    visibility: "private", capabilities: [], dependencies: over.dependencies ?? [], lifecycle: "active",
    stack: {
      primary_language: over.lang ?? "Python", languages: (over.langs ?? [over.lang ?? "Python"]).map((n) => ({ name: n, files: 1, lines: 1, percent: 1 })),
      frameworks: over.fw ?? [], libraries: [], testing: [], linting: [], databases: [], messaging: [],
      cloud: [], infrastructure: [], ci_cd: [], observability: [], auth: [], ai: [], build_tools: [], package_managers: [], runtimes: {},
    },
    summary: { domains: [], key_features: [] }, structure: { repo_type: "service", is_monorepo: false },
    practices: { score: over.practices?.score ?? 50, grade: "C", checks: [] },
    ownership: { codeowners: [] }, declared: { owner: null }, ai: { has_ai: false, sdks: [], models: [], ecosystems: [] },
    flags: over.flags ?? [], reusables: over.reusables ?? [], depends_on: [], used_by: over.used_by ?? [],
    dependency_summary: over.dependency_summary ?? { direct: 0, transitive: 0, ecosystems: {}, lockfile_coverage: 0, vulnerable: 0 },
  });

describe("query language", () => {
  it("parses free text, filters, negation and quoted values", () => {
    const q = parseQuery('stripe lang:python -type:library fw:"Next.js"');
    expect(q.text).toBe("stripe");
    expect(q.filters).toEqual([
      { key: "lang", value: "python", negate: false },
      { key: "type", value: "library", negate: true },
      { key: "fw", value: "Next.js", negate: false },
    ]);
  });

  it("toggles filters on and off, quoting values with spaces", () => {
    const on = toggleFilter("payments", "fw", "Ruby on Rails");
    expect(on).toBe('payments fw:"Ruby on Rails"');
    expect(hasFilter(on, "fw", "ruby on rails")).toBe(true);
    expect(toggleFilter(on, "fw", "Ruby on Rails")).toBe("payments");
  });

  it("treats unknown keys as text (URLs, typos)", () => {
    const q = resolveQuery(parseQuery("docs http://example.com foo:bar lang:go"), REPO_FILTERS);
    expect(q.filters.map((f) => f.key)).toEqual(["lang"]);
    expect(q.text).toBe("docs http://example.com foo:bar");
    expect(q.unknown).toEqual(["http", "foo"]);
  });
});

describe("filters", () => {
  const repos = [
    repo({ id: "a", lang: "TypeScript", langs: ["TypeScript", "Python"], fw: ["React"] }),
    repo({ id: "b", lang: "Python", fw: ["FastAPI"], practices: { score: 90 } as Repo["practices"] }),
  ];
  const ids = (q: string) => applyFilters(repos, resolveQuery(parseQuery(q), REPO_FILTERS).filters, REPO_FILTERS).map((r) => r.id);

  it("lang is the primary language; anylang is any language", () => {
    expect(ids("lang:python")).toEqual(["b"]);
    expect(ids("anylang:python")).toEqual(["a", "b"]);
  });
  it("same key ORs, different keys AND, negation excludes", () => {
    expect(ids("fw:react fw:fastapi")).toEqual(["a", "b"]);
    expect(ids("fw:react lang:python")).toEqual([]);
    expect(ids("-fw:react")).toEqual(["b"]);
  });
  it("numeric thresholds ignore non-numbers and never crash on the wrong tab", () => {
    expect(ids("minscore:80")).toEqual(["b"]);
    expect(ids("minscore:abc")).toEqual(["a", "b"]);
    const assets = [{ quality_score: 70 }, { quality_score: 10 }] as AssetItem[];
    const q = resolveQuery(parseQuery("minscore:5 minq:50"), ASSET_FILTERS);
    expect(applyFilters(assets, q.filters, ASSET_FILTERS)).toHaveLength(1);
  });
});

describe("findings and building blocks", () => {
  const flag = (id: string, severity: Flag["severity"]): Flag =>
    ({ id, severity, category: "security", message: id, path: null, line: null });
  const risky = repo({ id: "acme/risky", flags: [flag("committed-secret", "high"), flag("no-owner", "low")] });
  const shared = repo({
    id: "acme/shared", used_by: [{ repo: "acme/app", via: "npm @acme/ui" }],
    reusables: [{ kind: "terraform-module", name: "rds", path: "modules/rds", description: null, details: {} }],
  });
  const all = [risky, shared];
  const ids = (q: string) => applyFilters(all, parseQuery(q).filters, REPO_FILTERS).map((r) => r.id);

  it("filters repos by finding id and severity", () => {
    expect(ids("flag:committed-secret")).toEqual(["acme/risky"]);
    expect(ids("sev:high")).toEqual(["acme/risky"]);
    expect(ids("-sev:high")).toEqual(["acme/shared"]);
  });

  it("filters repos that ship building blocks or are depended on", () => {
    expect(ids("reuse:terraform-module")).toEqual(["acme/shared"]);
    expect(ids("usedby:yes")).toEqual(["acme/shared"]);
  });

  it("filters building blocks by kind and format", () => {
    const block = (kind: Block["kind"], details: Record<string, unknown>): Block =>
      ({ id: kind, kind, name: kind, path: ".", description: null, details, repo: shared.id, repoRef: shared });
    const blocks = [block("api", { format: "openapi 3.0.0" }), block("action", { using: "composite" })];
    const kinds = (q: string) => applyFilters(blocks, parseQuery(q).filters, BLOCK_FILTERS).map((b) => b.kind);
    expect(kinds("format:openapi")).toEqual(["api"]);
    expect(kinds("format:composite")).toEqual(["action"]);
    expect(kinds("kind:action")).toEqual(["action"]);
  });
});

describe("dependency filters", () => {
  const dep = (name: string, ecosystem: string, vulns: string[] = []) =>
    ({ name, ecosystem, version: null, resolved: null, purl: null, scope: "runtime", manifest: "x", vulns });
  const web = repo({
    id: "acme/web", dependencies: [dep("express", "npm", ["GHSA-1"]), dep("postgres", "docker")] as never,
    dependency_summary: { direct: 2, transitive: 40, ecosystems: { npm: 1, docker: 1 }, lockfile_coverage: 1, vulnerable: 1 },
  });
  const tool = repo({ id: "acme/tool", dependencies: [dep("expressive", "npm")] as never });
  const ids = (q: string) => applyFilters([web, tool], parseQuery(q).filters, REPO_FILTERS).map((r) => r.id);

  it("matches exact dependency names, ecosystems and advisories", () => {
    expect(ids("dep:express")).toEqual(["acme/web"]); // not "expressive"
    expect(ids("dep:Postgres depeco:docker")).toEqual(["acme/web"]);
    expect(ids("vuln:yes")).toEqual(["acme/web"]);
    expect(ids("vuln:no")).toEqual(["acme/tool"]);
  });
});

describe("facets agree with their filters", () => {
  const mk = (id: string, tools: string[], tags: string[], category: string) =>
    ({ id, tools, tags, category, repo: "acme/x", models: [], flags: [], duplicate_count: 0 }) as unknown as AssetItem;
  const assets = [mk("a", ["mcp__github__*"], [], "testing"), mk("b", ["mcp__github__create_issue"], ["testing"], "docs"), mk("c", ["Read"], [], "docs")];
  const run = <T,>(items: T[], defs: Parameters<typeof applyFilters<T>>[2], q: string) =>
    applyFilters(items, parseQuery(q).filters, defs).map((x) => (x as { id: string }).id);

  it("a facet click on a value ending in * matches exactly, typed tool:x* stays a prefix", () => {
    const facets = countBy(assets, ASSET_FILTERS.tool!.get);
    expect(facets.find(([v]) => v === "mcp__github__*")?.[1]).toBe(1);
    const q = toggleFilter("", "tool", facetValue("mcp__github__*"));
    expect(run(assets, ASSET_FILTERS, q)).toEqual(["a"]);
    expect(hasFilter(q, "tool", facetValue("mcp__github__*"))).toBe(true);
    expect(run(assets, ASSET_FILTERS, "tool:mcp__github__*")).toEqual(["a", "b"]);
    expect(facetValue("Read")).toBe("Read");
  });

  it("tag and capability facets count what their filters return", () => {
    const tag = countBy(assets, ASSET_FILTERS.tag!.get).find(([v]) => v === "testing")?.[1];
    expect(tag).toBe(run(assets, ASSET_FILTERS, "tag:testing").length);
    const rs = [
      { id: "r1", capabilities: ["payments"], summary: { domains: [] } },
      { id: "r2", capabilities: [], summary: { domains: ["payments"] } },
    ] as unknown as RepoItem[];
    const cap = countBy(rs, REPO_FILTERS.cap!.get).find(([v]) => v === "payments")?.[1];
    expect(cap).toBe(2);
    expect(run(rs, REPO_FILTERS, "cap:payments")).toEqual(["r1", "r2"]);
  });
});
