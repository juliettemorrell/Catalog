import MiniSearch from "minisearch";
import type { Asset, Block, Repo } from "./types";

/**
 * Query language shared by both views: free text plus `key:value` filters.
 *   fastapi payments lang:python -type:library grade:A missing:tests tech:"Next.js"
 * The query string is the single source of truth: facet clicks edit it, the URL stores it.
 */
export interface Filter { key: string; value: string; negate: boolean }
export interface ParsedQuery { text: string; filters: Filter[] }

const TOKEN = /(-?)([a-z]+):("[^"]*"|\S+)|("[^"]*"|\S+)/gi;

export function parseQuery(q: string): ParsedQuery {
  const filters: Filter[] = [];
  const words: string[] = [];
  for (const m of q.matchAll(TOKEN)) {
    if (m[2] && m[3]) {
      filters.push({ key: m[2].toLowerCase(), value: unquote(m[3]), negate: m[1] === "-" });
    } else if (m[4]) {
      words.push(unquote(m[4]));
    }
  }
  return { text: words.join(" "), filters };
}

const unquote = (s: string) => s.replace(/^"(.*)"$/, "$1");
const quote = (s: string) => (/\s/.test(s) ? `"${s}"` : s);

/** Add or remove a `key:value` token, returning the new query string. */
export function toggleFilter(q: string, key: string, value: string): string {
  const parsed = parseQuery(q);
  const exists = parsed.filters.some((f) => f.key === key && f.value.toLowerCase() === value.toLowerCase() && !f.negate);
  const kept = parsed.filters.filter((f) => !(f.key === key && f.value.toLowerCase() === value.toLowerCase()));
  const tokens = kept.map((f) => `${f.negate ? "-" : ""}${f.key}:${quote(f.value)}`);
  if (!exists) tokens.push(`${key}:${quote(value)}`);
  return [parsed.text, ...tokens].filter(Boolean).join(" ");
}

export function hasFilter(q: string, key: string, value: string): boolean {
  return parseQuery(q).filters.some((f) => !f.negate && f.key === key && f.value.toLowerCase() === value.toLowerCase());
}

type Getter<T> = (item: T) => (string | null | undefined)[] | string | null | undefined;

const lc = (v: string | null | undefined) => (v ?? "").toLowerCase();

function stackValues(r: Repo): string[] {
  const s = r.stack;
  return [
    ...s.frameworks, ...s.libraries, ...s.testing, ...s.linting, ...s.databases, ...s.messaging,
    ...s.cloud, ...s.infrastructure, ...s.ci_cd, ...s.observability, ...s.auth, ...s.ai,
    ...s.build_tools, ...s.package_managers, ...s.languages.map((l) => l.name),
    ...r.dependencies.map((d) => d.name),
  ];
}

export interface FilterDef<T> {
  get: Getter<T>;
  exact?: boolean;
  /** numeric threshold filters: `minq:60` keeps items whose value is >= 60 */
  min?: (item: T) => number;
  help: string;
}

/** Filter keys for repos. `exact` keys compare whole values; others use substring match. */
export const REPO_FILTERS: Record<string, FilterDef<Repo>> = {
  lang: { get: (r) => r.stack.primary_language, exact: true, help: "primary language" },
  anylang: { get: (r) => r.stack.languages.map((l) => l.name), exact: true, help: "any language used" },
  fw: { get: (r) => r.stack.frameworks, exact: true, help: "framework" },
  data: { get: (r) => [...r.stack.databases, ...r.stack.messaging], exact: true, help: "data store or messaging" },
  infra: { get: (r) => [...r.stack.cloud, ...r.stack.infrastructure], exact: true, help: "cloud or infrastructure" },
  tech: { get: stackValues, help: "any framework, library, tool or dependency (partial match)" },
  type: { get: (r) => r.structure.repo_type, exact: true, help: "repo type" },
  grade: { get: (r) => r.practices.grade, exact: true, help: "best-practice grade A-F" },
  cap: { get: (r) => [...r.capabilities, ...r.summary.domains], exact: true, help: "capability or domain" },
  topic: { get: (r) => r.topics, exact: true, help: "GitHub topic" },
  owner: { get: (r) => [r.declared.owner, r.owner, ...r.ownership.codeowners], help: "owner/team" },
  lifecycle: { get: (r) => r.lifecycle, exact: true, help: "active, maintained, stale, archived" },
  ai: { get: (r) => (r.ai.has_ai ? "yes" : "no"), exact: true, help: "uses AI (yes/no)" },
  uses: { get: (r) => [...r.ai.sdks, ...r.ai.models, ...r.ai.ecosystems], exact: true, help: "AI SDK, model or ecosystem" },
  missing: { get: (r) => r.practices.checks.filter((c) => !c.passed).map((c) => c.id), exact: true, help: "failing practice check id" },
  has: { get: (r) => r.practices.checks.filter((c) => c.passed).map((c) => c.id), exact: true, help: "passing practice check id" },
  is: {
    get: (r) => [r.archived ? "archived" : null, r.fork ? "fork" : null, r.structure.is_monorepo ? "monorepo" : null, r.visibility],
    exact: true, help: "archived, fork, monorepo, private, public",
  },
  minscore: { get: () => null, min: (r) => r.practices.score, help: "minimum practices score (0-100)" },
  flag: { get: (r) => r.flags.map((f) => f.id), exact: true, help: "finding id, e.g. committed-secret, eol-runtime" },
  sev: { get: (r) => r.flags.map((f) => f.severity), exact: true, help: "has a finding of severity high, medium or low" },
  reuse: { get: (r) => r.reusables.map((x) => x.kind), exact: true, help: "ships a building block: action, terraform-module, helm-chart, api…" },
  usedby: { get: (r) => (r.used_by.length ? "yes" : "no"), exact: true, help: "other org repos depend on it (yes/no)" },
  dep: { get: (r) => r.dependencies.map((d) => d.name), exact: true, help: "direct dependency, exact name (e.g. dep:express, dep:postgres)" },
  depeco: { get: (r) => Object.keys(r.dependency_summary.ecosystems), exact: true, help: "dependency ecosystem: npm, pypi, docker, terraform, github-actions…" },
  vuln: { get: (r) => (r.dependency_summary.vulnerable ? "yes" : "no"), exact: true, help: "ships a dependency with known advisories (yes/no; needs --osv)" },
};

export const ASSET_FILTERS: Record<string, FilterDef<Asset>> = {
  kind: { get: (a) => a.kind, exact: true, help: "skill, agent, command, prompt, instructions, mcp-server…" },
  eco: { get: (a) => a.ecosystem, exact: true, help: "ecosystem, e.g. claude-code, cursor, copilot" },
  repo: { get: (a) => [a.repo, a.repo.split("/")[1]], exact: true, help: "repository" },
  tool: { get: (a) => a.tools, exact: true, help: "tool the asset uses/exposes" },
  model: { get: (a) => a.models, exact: true, help: "model id" },
  tag: { get: (a) => [...a.tags, a.category], exact: true, help: "tag or category" },
  conf: { get: (a) => a.confidence, exact: true, help: "detection confidence" },
  scope: { get: (a) => a.scope, exact: true, help: "repo, plugin" },
  dup: { get: (a) => (a.duplicates.length ? "yes" : "no"), exact: true, help: "has copies elsewhere (yes/no)" },
  minq: { get: () => null, min: (a) => a.quality_score, help: "minimum quality score (0-100)" },
  flag: { get: (a) => a.flags.map((f) => f.id), exact: true, help: "governance finding id, e.g. mcp-unpinned-package" },
  sev: { get: (a) => a.flags.map((f) => f.severity), exact: true, help: "has a finding of severity high, medium or low" },
};

export const BLOCK_FILTERS: Record<string, FilterDef<Block>> = {
  kind: { get: (b) => b.kind, exact: true, help: "action, reusable-workflow, terraform-module, helm-chart, template, api, config-package" },
  repo: { get: (b) => [b.repo, b.repo.split("/")[1]], exact: true, help: "repository" },
  lang: { get: (b) => b.repoRef.stack.primary_language, exact: true, help: "primary language of the repo" },
  format: { get: (b) => String(b.details.format ?? b.details.engine ?? b.details.using ?? "").split(" ")[0], exact: true, help: "openapi, grpc, graphql, cookiecutter, composite…" },
  grade: { get: (b) => b.repoRef.practices.grade, exact: true, help: "practices grade of the repo" },
  lifecycle: { get: (b) => b.repoRef.lifecycle, exact: true, help: "active, maintained, stale, archived" },
};

function matches<T>(item: T, f: Filter, defs: Record<string, FilterDef<T>>): boolean {
  const def = defs[f.key];
  if (!def) return true;
  if (def.min) {
    const threshold = Number(f.value);
    return !Number.isFinite(threshold) || def.min(item) >= threshold; // ignore "minq:abc"
  }
  const raw = def.get(item);
  const values = (Array.isArray(raw) ? raw : [raw]).map(lc).filter(Boolean);
  const want = f.value.toLowerCase();
  if (want.length > 1 && want.endsWith("*")) { // explicit prefix match: tool:Bash*, uses:claude*
    const prefix = want.slice(0, -1);
    return values.some((v) => v.startsWith(prefix));
  }
  return values.some((v) => (def.exact ? v === want : v.includes(want)));
}

export function applyFilters<T>(items: T[], filters: Filter[], defs: Record<string, FilterDef<T>>): T[] {
  // Same key twice = OR (lang:go lang:rust); different keys = AND; `-key:v` excludes.
  const byKey = new Map<string, Filter[]>();
  for (const f of filters) {
    const k = `${f.negate ? "-" : ""}${f.key}`;
    byKey.set(k, [...(byKey.get(k) ?? []), f]);
  }
  return items.filter((item) =>
    [...byKey.values()].every((group) =>
      group[0]!.negate ? group.every((f) => !matches(item, f, defs)) : group.some((f) => matches(item, f, defs)),
    ),
  );
}

/** Split a parsed query into known filters and free text (unknown `a:b` tokens are text). */
export function resolveQuery(q: ParsedQuery, defs: Record<string, unknown>): ParsedQuery & { unknown: string[] } {
  const known = q.filters.filter((f) => f.key in defs);
  const unknown = q.filters.filter((f) => !(f.key in defs));
  const extra = unknown.map((f) => `${f.key}:${f.value}`);
  return { text: [q.text, ...extra].filter(Boolean).join(" "), filters: known, unknown: unknown.map((f) => f.key) };
}

export function repoIndex(): MiniSearch<Repo> {
  const ms = new MiniSearch<Repo>({
    idField: "id",
    fields: ["name", "description", "purpose", "readme", "features", "tech", "caps", "topics", "packages"],
    extractField: (r, field) => {
      switch (field) {
        case "id": return r.id;
        case "name": return r.name.replace(/[-_]/g, " ") + " " + r.name;
        case "description": return [r.description, r.summary.one_liner, r.summary.readme_title].filter(Boolean).join(" ");
        case "purpose": return [r.summary.purpose, r.summary.reuse_notes].filter(Boolean).join(" ");
        case "readme": return r.summary.readme_excerpt ?? "";
        case "features": return r.summary.key_features.join(" ");
        case "tech": return stackValues(r).join(" ");
        case "caps": return [...r.capabilities, ...r.summary.domains].join(" ");
        case "topics": return r.topics.join(" ");
        case "packages": return r.structure.packages.map((p) => p.name).join(" ");
        default: return "";
      }
    },
    searchOptions: {
      boost: { name: 4, description: 3, caps: 2.5, purpose: 2, tech: 2, features: 1.5, topics: 2 },
      prefix: true, fuzzy: 0.15, combineWith: "AND",
    },
  });
  return ms;
}

export function assetIndex(): MiniSearch<Asset> {
  const ms = new MiniSearch<Asset>({
    idField: "id",
    fields: ["name", "description", "summary", "tags", "tools", "content", "repo"],
    extractField: (a, field) => {
      switch (field) {
        case "id": return a.id;
        case "name": return `${a.name} ${a.title ?? ""}`.replace(/[-_:/]/g, " ");
        case "description": return a.description ?? "";
        case "summary": return [a.summary, ...a.use_cases, a.category].filter(Boolean).join(" ");
        case "tags": return [...a.tags, a.kind, a.ecosystem].join(" ");
        case "tools": return [...a.tools, ...a.models, ...a.mcp_servers].join(" ");
        case "content": return [a.headings.join(" "), (a.content ?? "").slice(0, 2_000)].join(" ");
        case "repo": return a.repo;
        default: return "";
      }
    },
    searchOptions: {
      boost: { name: 4, description: 3, summary: 2.5, tags: 2, tools: 1.5, content: 0.6 },
      prefix: true, fuzzy: 0.15, combineWith: "AND",
    },
  });
  return ms;
}

export function blockIndex(): MiniSearch<Block> {
  return new MiniSearch<Block>({
    idField: "id",
    fields: ["name", "description", "details", "repo", "path"],
    extractField: (b, field) => {
      switch (field) {
        case "id": return b.id;
        case "name": return `${b.name} ${b.kind}`.replace(/[-_/]/g, " ");
        case "description": return [b.description, b.repoRef.summary.one_liner].filter(Boolean).join(" ");
        case "details": return JSON.stringify(b.details).replace(/[{}[\]",:_-]/g, " ");
        case "repo": return b.repo;
        case "path": return b.path.replace(/[/._-]/g, " ");
        default: return "";
      }
    },
    searchOptions: { boost: { name: 4, description: 3, details: 1.5, path: 1 }, prefix: true, fuzzy: 0.15, combineWith: "AND" },
  });
}

/** A search index filled in the background, in chunks, so large catalogs never freeze the UI. */
export class LazyIndex<T> {
  ready = false;
  progress = 0;
  private started: Promise<void> | null = null;

  constructor(readonly index: MiniSearch<T>, private readonly docs: T[], private readonly onReady: () => void) {}

  start(): Promise<void> {
    this.started ??= (async () => {
      const chunk = 400;
      for (let i = 0; i < this.docs.length; i += chunk) {
        this.index.addAll(this.docs.slice(i, i + chunk));
        this.progress = Math.min(1, (i + chunk) / Math.max(1, this.docs.length));
        await new Promise((r) => setTimeout(r, 0)); // yield to input and rendering
      }
      this.ready = true;
      this.progress = 1;
      this.onReady();
    })();
    return this.started;
  }
}

export function runSearch<T extends { id: string }>(
  items: T[], index: LazyIndex<T>, q: ParsedQuery,
  defs: Record<string, FilterDef<T>>, fallbackSort: (a: T, b: T) => number,
): T[] {
  let ranked: T[];
  if (q.text.trim()) {
    const byId = new Map(items.map((i) => [i.id, i]));
    if (!index.ready) {
      void index.start();
      return applyFilters(textFallback(items, q.text), q.filters, defs); // exact-substring until ready
    }
    const idx = index.index;
    let hits = idx.search(q.text);
    if (!hits.length) hits = idx.search(q.text, { combineWith: "OR" });
    ranked = hits.map((h) => byId.get(h.id as string)).filter((x): x is T => !!x);
  } else {
    ranked = [...items].sort(fallbackSort);
  }
  return applyFilters(ranked, q.filters, defs);
}

/** Plain substring search used while the full-text index is still being built. */
function textFallback<T>(items: T[], text: string): T[] {
  const words = text.toLowerCase().split(/\s+/).filter(Boolean);
  return items.filter((item) => {
    const hay = JSON.stringify(item).slice(0, 20_000).toLowerCase();
    return words.every((w) => hay.includes(w));
  });
}
