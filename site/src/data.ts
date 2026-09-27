import type { Asset, AssetItem, DriftRow, Meta, Repo, RepoDetail, RepoItem, SiteInsights } from "./types";

/**
 * Loading the catalog. catalog.json and ai-assets.json hold slim list entries (see
 * store.py `_site_repo` / `_site_asset`); full records are fetched one at a time when a
 * drawer opens, from data/site/repos/<slug>.json and data/site/assets/<id>.json.
 * Catalogs written by older scanners (full records in the list files, no data/site/) still
 * load: their records are normalised to list entries and kept as the detail.
 */

/** Mirrors store.py `_file_name`: the detail file name for a repo slug or asset id. */
export function detailFileName(key: string): string {
  return key.replace(/[^A-Za-z0-9._-]/g, "_").replace(/^\.+/, "") || "_";
}

/** Mirrors store.py `_slug`. */
export const repoSlug = (id: string) => id.split("/").join("__");

const withVersion = (path: string, version: string) => (version ? `${path}?v=${encodeURIComponent(version)}` : path);
export const repoDetailUrl = (id: string, version = "") =>
  withVersion(`data/site/repos/${encodeURIComponent(detailFileName(repoSlug(id)))}.json`, version);
export const assetDetailUrl = (id: string, version = "") =>
  withVersion(`data/site/assets/${encodeURIComponent(detailFileName(id))}.json`, version);
export const insightsUrl = (version = "") => withVersion("data/site/insights.json", version);

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

/** A full record from an older catalog.json (it has `dependencies`, not `dependency_names`). */
const isFullRepo = (r: Json) => Array.isArray(r.dependencies) && !Array.isArray(r.dependency_names);
const isFullAsset = (a: Json) => Array.isArray(a.duplicates) && typeof a.duplicate_count !== "number";

/** A list entry with defaults for fields older scanners did not write. */
export function normalizeRepo(r: Json): RepoItem {
  r.flags ??= []; r.reusables ??= []; r.depends_on ??= []; r.topics ??= []; r.capabilities ??= [];
  r.stack ??= {}; r.stack.languages ??= [];
  r.structure ??= { repo_type: "unknown", is_monorepo: false, packages: [] }; r.structure.packages ??= [];
  r.practices ??= { score: 0, grade: "F", checks: [] }; r.practices.checks ??= [];
  r.ownership ??= { codeowners: [], last_commit: null }; r.ownership.codeowners ??= [];
  r.declared ??= { owner: null, system: null };
  r.summary ??= {}; r.summary.key_features ??= []; r.summary.domains ??= [];
  r.ai ??= { has_ai: false, asset_count: 0, asset_kinds: {}, ecosystems: [], sdks: [], models: [], mcp_servers_provided: [], mcp_servers_consumed: [] };
  if (isFullRepo(r)) {
    const direct = (r.dependencies as Json[]).filter((d) => d.scope !== "transitive");
    r.dependency_names = [...new Set(direct.map((d) => String(d.name)))].sort();
    r.vulnerable_dependencies = [...new Set(direct.filter((d) => d.vulns?.length).map((d) => String(d.name)))].sort();
    r.used_by_count = Array.isArray(r.used_by) ? r.used_by.length : 0;
    r.dependency_summary ??= { direct: direct.length, transitive: 0, ecosystems: {}, lockfile_coverage: 0, vulnerable: 0 };
  }
  r.dependency_names ??= []; r.vulnerable_dependencies ??= []; r.used_by_count ??= 0;
  r.dependency_summary ??= { direct: 0, transitive: 0, ecosystems: {}, lockfile_coverage: 0, vulnerable: 0 };
  r.dependency_summary.ecosystems ??= {};
  return r as RepoItem;
}

export function normalizeAsset(a: Json): AssetItem {
  a.flags ??= []; a.tools ??= []; a.models ??= []; a.tags ??= []; a.mcp_servers ??= [];
  a.headings ??= []; a.use_cases ??= [];
  a.duplicate_count ??= Array.isArray(a.duplicates) ? a.duplicates.length : 0;
  return a as AssetItem;
}

/** A full repo record for the drawer: the detail file's, or one filled from the list entry. */
export function repoFromItem(r: RepoItem): Repo {
  const full = r as unknown as Json;
  const s = r.stack as Json;
  return {
    ...(r as unknown as Repo),
    homepage: r.homepage ?? null,
    declared: { owner: r.declared.owner, system: r.declared.system, lifecycle: null, tier: null, source_files: [], links: [], custom_properties: {}, ...full.declared },
    stack: {
      ...r.stack, runtimes: s.runtimes ?? {}, runtime_versions: s.runtime_versions ?? [],
      languages: r.stack.languages.map((l) => ({ files: 0, lines: 0, ...l })),
    },
    dependencies: Array.isArray(full.dependencies) ? full.dependencies.filter((d: Json) => d.scope !== "transitive") : [],
    structure: { entrypoints: [], api_specs: [], dockerfiles: [], top_level: [], docs: [], file_count: 0, total_lines: 0, ...full.structure,
      packages: r.structure.packages.map((p) => ({ path: "", ecosystem: "", version: null, description: null, ...p })) },
    practices: { ...r.practices, checks: r.practices.checks.map((c) => ({ category: "", weight: 1, evidence: null, ...c })) },
    ownership: { top_contributors: [], contributor_count: 0, commit_count: 0, first_commit: null, ...full.ownership },
    used_by: Array.isArray(full.used_by) ? full.used_by : [],
    scan_errors: Array.isArray(full.scan_errors) ? full.scan_errors : [],
  };
}

export function assetFromItem(a: AssetItem): Asset {
  const full = a as unknown as Json;
  return {
    detector: "", frontmatter: {}, providers: [], triggers: [], arguments: [], license: null, version: null,
    content: null, content_truncated: false, files: [], line_count: 0, word_count: 0, token_estimate: 0,
    last_author: null, commit_count: null, quality_notes: [], duplicates: [],
    ...full,
  } as unknown as Asset;
}

type Fetcher = (url: string) => Promise<unknown>;

export async function fetchJson(url: string): Promise<any> { // eslint-disable-line @typescript-eslint/no-explicit-any
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.json();
}

/**
 * Detail records fetched on demand and cached (bounded, least recently used first out).
 * `peek*` answers synchronously from the cache so a drawer re-render never flickers.
 */
export class DetailStore {
  private readonly repos = new Map<string, RepoDetail>();
  private readonly assets = new Map<string, Asset>();
  private readonly pending = new Map<string, Promise<unknown>>();
  private insights: SiteInsights | null | undefined; // null: not available

  constructor(private readonly version = "", private readonly get: Fetcher = fetchJson, private readonly max = 200) {}

  /** Older catalogs carry full records in the list files: use them as the detail. */
  seedRepo(detail: RepoDetail): void { this.remember(this.repos, detail.repo.id, detail, true); }
  seedAsset(asset: Asset): void { this.remember(this.assets, asset.id, asset, true); }

  peekRepo(id: string): RepoDetail | undefined { return this.touch(this.repos, id); }
  peekAsset(id: string): Asset | undefined { return this.touch(this.assets, id); }
  peekInsights(): SiteInsights | null | undefined { return this.insights; }

  loadRepo(id: string): Promise<RepoDetail> {
    const hit = this.peekRepo(id);
    if (hit) return Promise.resolve(hit);
    return this.once(`repo:${id}`, async () => {
      const data = (await this.get(repoDetailUrl(id, this.version))) as RepoDetail;
      if (!data?.repo || data.repo.id !== id) throw new Error(`unexpected detail file for ${id}`);
      data.assets ??= [];
      this.remember(this.repos, id, data);
      return data;
    });
  }

  loadAsset(id: string): Promise<Asset> {
    const hit = this.peekAsset(id);
    if (hit) return Promise.resolve(hit);
    return this.once(`asset:${id}`, async () => {
      const data = (await this.get(assetDetailUrl(id, this.version))) as Asset;
      if (!data || data.id !== id) throw new Error(`unexpected detail file for asset ${id}`);
      this.remember(this.assets, id, data);
      return data;
    });
  }

  /** Build-time aggregates; resolves to null when the file is missing (older catalogs). */
  loadInsights(): Promise<SiteInsights | null> {
    if (this.insights !== undefined) return Promise.resolve(this.insights);
    return this.once("insights", async () => {
      try {
        const data = (await this.get(insightsUrl(this.version))) as SiteInsights;
        this.insights = Array.isArray(data?.version_drift) ? data : null;
      } catch {
        this.insights = null;
      }
      return this.insights;
    });
  }

  private once<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const running = this.pending.get(key) as Promise<T> | undefined;
    if (running) return running;
    const p = fn().finally(() => this.pending.delete(key)); // failures are retried next time
    this.pending.set(key, p);
    return p;
  }

  private touch<T>(map: Map<string, T>, id: string): T | undefined {
    const v = map.get(id);
    if (v !== undefined) { map.delete(id); map.set(id, v); }
    return v;
  }

  private remember<T>(map: Map<string, T>, id: string, value: T, pinned = false): void {
    map.delete(id);
    map.set(id, value);
    if (pinned) return; // seeded records are already in memory: evicting would save nothing
    while (map.size > this.max) map.delete(map.keys().next().value!);
  }
}

/** Parse list files, keeping full records of older catalogs as details. */
export function readCatalog(c: Json, details: DetailStore): { meta: Meta; repos: RepoItem[] } {
  if (!Array.isArray(c?.repos)) throw new Error("catalog.json is not in the expected format (repos[])");
  const repos = (c.repos as Json[]).map((r) => {
    const full = isFullRepo(r);
    const item = normalizeRepo(r);
    if (full) details.seedRepo({ repo: repoFromItem(item), assets: [] });
    return item;
  });
  return { meta: (c.meta ?? {}) as Meta, repos };
}

export function readAssets(a: Json, details: DetailStore): AssetItem[] {
  if (!Array.isArray(a?.assets)) throw new Error("ai-assets.json is not in the expected format (assets[])");
  return (a.assets as Json[]).map((x) => {
    const full = isFullAsset(x);
    const item = normalizeAsset(x);
    if (full) details.seedAsset(assetFromItem(item));
    return item;
  });
}

/**
 * Same dependency on different major versions across active repos. Computed at build
 * time into data/site/insights.json (store.py `_version_drift`); this fallback serves
 * older catalogs whose catalog.json still carries the dependencies.
 */
export function versionDrift(repos: Repo[], limit = 15): DriftRow[] {
  const byDep = new Map<string, Map<string, string[]>>();
  for (const r of repos) {
    if (r.archived) continue;
    for (const d of r.dependencies) {
      const version = d.resolved ?? d.version;
      if (d.scope === "transitive" || !version || d.ecosystem === "github-actions") continue;
      const m = /(\d+)(?:\.(\d+))?/.exec(version.replace(/^\D*/, ""));
      if (!m) continue;
      const major = m[1] === "0" && m[2] !== undefined ? `0.${m[2]}` : m[1]!;
      const key = `${d.ecosystem}\u0000${d.name}`;
      const majors = byDep.get(key) ?? new Map<string, string[]>();
      const ids = majors.get(major) ?? [];
      if (ids[ids.length - 1] !== r.id) ids.push(r.id);
      majors.set(major, ids);
      byDep.set(key, majors);
    }
  }
  return [...byDep.entries()]
    .map(([key, majors]) => ({ key, majors, repos: new Set([...majors.values()].flat()).size }))
    .filter((x) => x.majors.size > 1 && x.repos > 1)
    .sort((a, b) => b.majors.size - a.majors.size || b.repos - a.repos)
    .slice(0, limit)
    .map(({ key, majors, repos: n }) => {
      const [ecosystem, name] = key.split("\u0000") as [string, string];
      return { ecosystem, name, repos: n, majors: [...majors].map(([major, ids]) => ({ major, count: ids.length, sample: ids.slice(0, 20) })) };
    });
}
