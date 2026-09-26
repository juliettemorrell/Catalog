import { describe, expect, it } from "vitest";
import { applyFilters, hasFilter, parseQuery, resolveQuery, REPO_FILTERS, ASSET_FILTERS, toggleFilter } from "../search";
import type { Asset, Repo } from "../types";

const repo = (over: Partial<Repo> & { lang?: string; fw?: string[]; langs?: string[] }): Repo =>
  ({
    id: over.id ?? "acme/x", name: "x", owner: "acme", topics: [], archived: false, fork: false,
    visibility: "private", capabilities: [], dependencies: [], lifecycle: "active",
    stack: {
      primary_language: over.lang ?? "Python", languages: (over.langs ?? [over.lang ?? "Python"]).map((n) => ({ name: n, files: 1, lines: 1, percent: 1 })),
      frameworks: over.fw ?? [], libraries: [], testing: [], linting: [], databases: [], messaging: [],
      cloud: [], infrastructure: [], ci_cd: [], observability: [], auth: [], ai: [], build_tools: [], package_managers: [], runtimes: {},
    },
    summary: { domains: [], key_features: [] }, structure: { repo_type: "service", is_monorepo: false },
    practices: { score: over.practices?.score ?? 50, grade: "C", checks: [] },
    ownership: { codeowners: [] }, declared: { owner: null }, ai: { has_ai: false, sdks: [], models: [], ecosystems: [] },
  }) as unknown as Repo;

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
    const assets = [{ quality_score: 70 }, { quality_score: 10 }] as Asset[];
    const q = resolveQuery(parseQuery("minscore:5 minq:50"), ASSET_FILTERS);
    expect(applyFilters(assets, q.filters, ASSET_FILTERS)).toHaveLength(1);
  });
});
