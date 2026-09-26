// Mirrors the Python models (see ../schema/*.schema.json). Only fields the UI reads.

export interface LanguageStat { name: string; files: number; lines: number; percent: number }
export interface Dependency { name: string; version: string | null; ecosystem: string; scope: "runtime" | "dev" | "build" | "peer" | "optional" | "transitive"; manifest: string }
export interface Pkg { name: string; path: string; ecosystem: string; version: string | null; description: string | null }
export interface PracticeCheck { id: string; category: string; label: string; passed: boolean; weight: number; evidence: string | null }

export type Severity = "high" | "medium" | "low";
export interface Flag { id: string; category: "security" | "maintenance" | "ownership" | "ai-governance"; severity: Severity; message: string; path: string | null; line: number | null }
export type ReusableKind = "action" | "reusable-workflow" | "terraform-module" | "helm-chart" | "template" | "api" | "config-package";
export interface Reusable { kind: ReusableKind; name: string; path: string; description: string | null; details: Record<string, unknown> }
export interface RepoLink { repo: string; via: string }
export interface RuntimeVersion { runtime: string; version: string; path: string }

/** A building block flattened for the Building blocks view (not in the JSON as such). */
export interface Block extends Reusable { id: string; repo: string; repoRef: Repo }

export interface Stack {
  primary_language: string | null;
  languages: LanguageStat[];
  frameworks: string[]; libraries: string[]; testing: string[]; linting: string[];
  databases: string[]; messaging: string[]; cloud: string[]; infrastructure: string[];
  ci_cd: string[]; observability: string[]; auth: string[]; ai: string[]; build_tools: string[];
  package_managers: string[]; runtimes: Record<string, string>;
  runtime_versions: RuntimeVersion[];
}

export interface Repo {
  id: string; name: string; owner: string; url: string;
  description: string | null; homepage: string | null; topics: string[];
  visibility: string | null; archived: boolean; fork: boolean; default_branch: string | null;
  license: string | null; stars: number | null; pushed_at: string | null;
  lifecycle: "active" | "maintained" | "stale" | "archived";
  capabilities: string[];
  declared: { owner: string | null; system: string | null; lifecycle: string | null; tier: string | null; source_files: string[]; links: { url: string; title: string }[]; custom_properties: Record<string, unknown> };
  summary: { one_liner: string | null; readme_title: string | null; readme_excerpt: string | null; purpose: string | null; key_features: string[]; reuse_notes: string | null; domains: string[]; source: string };
  stack: Stack;
  dependencies: Dependency[];
  structure: { repo_type: string; is_monorepo: boolean; packages: Pkg[]; entrypoints: string[]; api_specs: string[]; dockerfiles: string[]; top_level: string[]; docs: string[]; file_count: number; total_lines: number };
  practices: { score: number; grade: "A" | "B" | "C" | "D" | "F"; checks: PracticeCheck[] };
  ownership: { codeowners: string[]; top_contributors: { name: string; commits: number }[]; contributor_count: number; commit_count: number; first_commit: string | null; last_commit: string | null };
  ai: { has_ai: boolean; asset_count: number; asset_kinds: Record<string, number>; ecosystems: string[]; sdks: string[]; models: string[]; mcp_servers_provided: string[]; mcp_servers_consumed: string[] };
  flags: Flag[]; reusables: Reusable[]; depends_on: RepoLink[]; used_by: RepoLink[];
  scanned_at: string; scan_errors: string[]; scan_fingerprint?: string | null;
}

export interface Asset {
  id: string; kind: string; ecosystem: string; name: string; title: string | null;
  description: string | null; repo: string; path: string; url: string; scope: string;
  confidence: "high" | "medium" | "low"; detector: string;
  frontmatter: Record<string, unknown>;
  tools: string[]; models: string[]; providers: string[]; triggers: string[]; arguments: string[];
  mcp_servers: string[]; tags: string[]; license: string | null; version: string | null;
  content: string | null; content_truncated: boolean; excerpt: string | null; headings: string[];
  files: { path: string; size: number }[];
  line_count: number; word_count: number; token_estimate: number;
  last_modified: string | null; last_author: string | null; commit_count: number | null;
  quality_score: number; quality_notes: string[];
  summary: string | null; use_cases: string[]; category: string | null; duplicates: string[];
  flags: Flag[];
}

export interface Meta { generated_at: string; source: string; repo_count: number; asset_count: number; llm_enriched: boolean; scanner_version: string }

export interface Catalog { meta: Meta; repos: Repo[]; assets: Asset[] }
