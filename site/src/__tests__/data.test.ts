import { describe, expect, it, vi } from "vitest";
import {
  DetailStore, assetDetailUrl, detailFileName, normalizeAsset, readAssets, readCatalog, repoDetailUrl, versionDrift,
} from "../data";
import { LazyIndex, REPO_INDEX, runSearch, textFallback } from "../search";
import type { Repo, RepoItem } from "../types";

describe("detail file names", () => {
  it("mirror store.py _slug/_file_name and are URL-safe", () => {
    expect(repoDetailUrl("acme/web")).toBe("data/site/repos/acme__web.json");
    expect(repoDetailUrl("acme/web", "2026-01-01T00:00:00Z")).toBe("data/site/repos/acme__web.json?v=2026-01-01T00%3A00%3A00Z");
    expect(assetDetailUrl("0123abcd")).toBe("data/site/assets/0123abcd.json");
    expect(detailFileName("local/../x y")).toBe("local_.._x_y");
    expect(detailFileName("..hidden")).toBe("hidden");
    expect(detailFileName("")).toBe("_");
  });
});

describe("slim list entries", () => {
  const slim = { id: "acme/web", name: "web", dependency_names: ["express"], vulnerable_dependencies: [], used_by_count: 3 };

  it("keeps new-format entries as they are and loads their detail lazily", () => {
    const store = new DetailStore();
    const { repos } = readCatalog({ meta: {}, repos: [structuredClone(slim)] }, store);
    expect(repos[0]!.dependency_names).toEqual(["express"]);
    expect(repos[0]!.used_by_count).toBe(3);
    expect(store.peekRepo("acme/web")).toBeUndefined(); // nothing to seed: fetched on demand
  });

  it("derives list fields from full records written by older scanners", () => {
    const store = new DetailStore();
    const full = {
      id: "acme/old", name: "old", used_by: [{ repo: "a/b", via: "npm x" }],
      dependencies: [
        { name: "b", scope: "runtime", vulns: ["GHSA-1"] }, { name: "a", scope: "dev", vulns: [] },
        { name: "a", scope: "runtime", vulns: [] }, { name: "t", scope: "transitive", vulns: [] },
      ],
    };
    const { repos } = readCatalog({ repos: [full] }, store);
    expect(repos[0]!.dependency_names).toEqual(["a", "b"]);
    expect(repos[0]!.vulnerable_dependencies).toEqual(["b"]);
    expect(repos[0]!.used_by_count).toBe(1);
    expect(store.peekRepo("acme/old")?.repo.used_by).toHaveLength(1); // the record is the detail
    const [asset] = readAssets({ assets: [{ id: "x", duplicates: ["y", "z"], content: "hi" }] }, store);
    expect(asset!.duplicate_count).toBe(2);
    expect(store.peekAsset("x")?.content).toBe("hi");
    expect(normalizeAsset({ id: "n" }).duplicate_count).toBe(0);
  });

  it("rejects files that are not catalogs", () => {
    expect(() => readCatalog({ nope: 1 }, new DetailStore())).toThrow(/repos/);
    expect(() => readAssets({}, new DetailStore())).toThrow(/assets/);
  });
});

describe("DetailStore", () => {
  const detail = (id: string) => ({ repo: { id } as Repo, assets: [] });

  it("fetches once, caches, and retries after a failure", async () => {
    let fail = true;
    const get = vi.fn(async (url: string) => {
      if (url.includes("broken")) {
        if (fail) { fail = false; throw new Error("HTTP 404"); }
      }
      return detail(url.includes("broken") ? "acme/broken" : "acme/web");
    });
    const store = new DetailStore("v1", get);
    const [a, b] = await Promise.all([store.loadRepo("acme/web"), store.loadRepo("acme/web")]);
    expect(a).toBe(b);
    expect(get).toHaveBeenCalledTimes(1);
    expect(get).toHaveBeenCalledWith("data/site/repos/acme__web.json?v=v1");
    expect(store.peekRepo("acme/web")).toBe(a);
    await expect(store.loadRepo("acme/broken")).rejects.toThrow("404");
    await expect(store.loadRepo("acme/broken")).resolves.toMatchObject({ repo: { id: "acme/broken" } });
  });

  it("refuses a detail file for a different record", async () => {
    const store = new DetailStore("", async () => ({ id: "other" }));
    await expect(store.loadAsset("mine")).rejects.toThrow(/unexpected/);
  });

  it("is bounded", async () => {
    const store = new DetailStore("", async (url: string) => detail(decodeURIComponent(url).match(/repos\/(.*)\.json/)![1]!.replace("__", "/")), 2);
    for (const id of ["a/1", "a/2", "a/3"]) await store.loadRepo(id);
    expect(store.peekRepo("a/1")).toBeUndefined();
    expect(store.peekRepo("a/3")).toBeDefined();
  });

  it("treats a missing insights file as absent, not as an error", async () => {
    const store = new DetailStore("", async () => { throw new Error("HTTP 404"); });
    expect(await store.loadInsights()).toBeNull();
    expect(store.peekInsights()).toBeNull();
  });
});

describe("pre-index substring search", () => {
  const item = (id: string, description: string) =>
    ({
      id, name: id, description, topics: [], capabilities: [], dependency_names: ["Express"],
      summary: { key_features: [], domains: [] }, structure: { packages: [] },
      stack: { languages: [], frameworks: [], libraries: [], testing: [], linting: [], databases: [], messaging: [], cloud: [],
        infrastructure: [], ci_cd: [], observability: [], auth: [], ai: [], build_tools: [], package_managers: [] },
    }) as unknown as RepoItem;

  it("matches the indexed fields, computing each item's text once", () => {
    const docs = [item("a", "Takes Payments"), item("b", "Sends email")];
    const idx = new LazyIndex(REPO_INDEX, docs, () => {});
    const extract = vi.spyOn(REPO_INDEX, "extract");
    expect(textFallback(idx, "payments").map((r) => r.id)).toEqual(["a"]);
    const calls = extract.mock.calls.length;
    expect(textFallback(idx, "express email").map((r) => r.id)).toEqual(["b"]);
    expect(extract.mock.calls.length).toBe(calls); // cached, not recomputed per keystroke
    extract.mockRestore();
  });

  it("builds the index in slices and then ranks", async () => {
    const docs = Array.from({ length: 50 }, (_, i) => item(`r${i}`, i === 7 ? "kubernetes operator" : "service"));
    let readyCalls = 0;
    const idx = new LazyIndex(REPO_INDEX, docs, () => readyCalls++, 0);
    const q = { text: "kubernetes", filters: [] };
    expect(runSearch(idx, q, {}, () => 0).map((r) => r.id)).toEqual(["r7"]); // substring while building
    await idx.start();
    expect(idx.ready).toBe(true);
    expect(readyCalls).toBe(1);
    expect(runSearch(idx, q, {}, () => 0).map((r) => r.id)).toEqual(["r7"]);
  });
});

describe("version drift fallback", () => {
  it("matches the build-time computation's shape and rules", () => {
    const dep = (name: string, version: string, scope = "runtime", ecosystem = "npm") =>
      ({ name, version, resolved: null, ecosystem, scope, manifest: "m", purl: null, vulns: [] });
    const r = (id: string, deps: ReturnType<typeof dep>[], archived = false) => ({ id, archived, dependencies: deps }) as unknown as Repo;
    const rows = versionDrift([
      r("a", [dep("react", "^17.0.2"), dep("x", "0.3.1"), dep("act", "v4", "runtime", "github-actions")]),
      r("b", [dep("react", "18.2.0"), dep("x", "0.4.0"), dep("act", "v3", "runtime", "github-actions")]),
      r("c", [dep("react", "16.0.0")], true), // archived: ignored
      r("d", [dep("react", "19.0.0", "transitive")]), // transitive: ignored
    ]);
    expect(rows.map((x) => x.name)).toEqual(["react", "x"]);
    expect(rows[0]).toEqual({ ecosystem: "npm", name: "react", repos: 2, majors: [
      { major: "17", count: 1, sample: ["a"] }, { major: "18", count: 1, sample: ["b"] }] });
    expect(rows[1]!.majors.map((m) => m.major)).toEqual(["0.3", "0.4"]);
  });
});
