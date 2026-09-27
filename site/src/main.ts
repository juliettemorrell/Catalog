import "./styles.css";
import {
  ASSET_FILTERS, BLOCK_FILTERS, LazyIndex, REPO_FILTERS, assetIndex, blockIndex, facetValue, hasFilter, parseQuery,
  repoIndex, resolveQuery, runSearch, toggleFilter,
} from "./search";
import type { FilterDef } from "./search";
import type { Asset, Block, Catalog, Flag, Repo } from "./types";
import { chips, copyText, countBy, downloadCsv, esc, fmtNum, markdown, num, relTime, safeUrl } from "./util";

type Tab = "repos" | "assets" | "blocks" | "insights";
const TABS: Tab[] = ["repos", "assets", "blocks", "insights"];
interface State { tab: Tab; q: string; open: string | null }

const PAGE = 60;
const KIND_LABEL: Record<string, string> = {
  skill: "Skill", agent: "Agent", command: "Command", prompt: "Prompt", instructions: "Rules / instructions",
  "mcp-server": "MCP server", "mcp-config": "MCP config", settings: "Settings", hook: "Hook", plugin: "Plugin", eval: "Eval",
  workflow: "Workflow", "sdk-usage": "LLM SDK usage",
};
const TAB_TITLE: Record<Tab, string> = { repos: "Repositories", assets: "AI Asset Library", blocks: "Building blocks", insights: "Insights" };
const BLOCK_LABEL: Record<string, string> = {
  action: "GitHub Action", "reusable-workflow": "Reusable workflow", "terraform-module": "Terraform module",
  "helm-chart": "Helm chart", template: "Template", api: "API", "config-package": "Config package",
};
const FLAG_LABEL: Record<string, string> = {
  "committed-secret": "Committed secret", "secret-in-asset": "Secret in AI file", "eol-runtime": "End-of-life runtime",
  "deprecated-model": "Retired / deprecated model", "workflow-script-injection": "Workflow script injection",
  "workflow-pwn-request": "Untrusted PR checkout", "docker-unpinned-base": "Unpinned base image",
  "docker-runs-as-root": "Container runs as root", "no-owner": "No owner", "single-maintainer": "Bus factor 1",
  "depends-on-archived": "Depends on archived repo", "ai-permissions-bypassed": "Agent approvals disabled",
  "ai-unrestricted-shell": "Unrestricted agent shell", "ai-remote-code-exec": "curl | sh in AI config",
  "ai-mcp-auto-enabled": "MCP servers auto-enabled", "ai-personal-settings-committed": "Personal AI settings committed",
  "mcp-unpinned-package": "Unpinned MCP package", "mcp-inline-secret": "Secret in MCP config",
  "mcp-plaintext-http": "MCP over plain HTTP",
};
const SEV_ORDER: Record<string, number> = { high: 0, medium: 1, low: 2 };
const flagLabel = (id: string) => FLAG_LABEL[id] ?? id;
const GRADES = new Set(["A", "B", "C", "D", "F"]);
const STACK_ROWS: [keyof Repo["stack"], string, string][] = [
  ["frameworks", "Frameworks", "fw"], ["libraries", "Libraries", "tech"], ["databases", "Data", "data"],
  ["messaging", "Messaging", "data"], ["auth", "Auth", "tech"], ["ai", "AI / ML", "tech"],
  ["cloud", "Cloud", "infra"], ["infrastructure", "Infrastructure", "infra"], ["ci_cd", "CI/CD", "tech"],
  ["testing", "Testing", "tech"], ["linting", "Quality tooling", "tech"], ["build_tools", "Build", "tech"],
  ["observability", "Observability", "tech"], ["package_managers", "Package managers", "tech"],
];

let catalog: Catalog;
let repoIdx: LazyIndex<Repo>;
let assetIdx: LazyIndex<Asset>;
let blockIdx: LazyIndex<Block>;
let blocks: Block[] = [];
let blocksById = new Map<string, Block>();
let assetsById = new Map<string, Asset>();
let reposById = new Map<string, Repo>();
let shown = PAGE;
let lastList = ""; // tab+query of the rendered list: paging resets only when it changes
let lastRendered = "";
let returnFocus: string | null = null; // href of the card that opened the drawer

const $main = document.getElementById("main")!;
const $drawer = document.getElementById("drawer")!;
const $scrim = document.getElementById("scrim")!;

function onIndexReady(): void {
  if (readState().q.trim()) render(true); // upgrade substring results to ranked results
}

// ------------------------------------------------------------------------------------ state

function readState(): State {
  const [path = "", query = ""] = location.hash.replace(/^#\/?/, "").split("?");
  const params = new URLSearchParams(query);
  const tab = (TABS as string[]).includes(path) ? (path as Tab) : "repos";
  return { tab, q: params.get("q") ?? "", open: params.get("open") };
}

function href(s: Partial<State>): string {
  const next = { ...readState(), ...s };
  const params = new URLSearchParams();
  if (next.q) params.set("q", next.q);
  if (next.open) params.set("open", next.open);
  const qs = params.toString();
  return `#/${next.tab}${qs ? `?${qs}` : ""}`;
}

function navigate(s: Partial<State>, replace = false): void {
  const url = href(s);
  if (replace) history.replaceState(null, "", url);
  else history.pushState(null, "", url);
  render();
}

// ------------------------------------------------------------------------------------ boot

async function load(): Promise<void> {
  try {
    const [c, a] = await Promise.all([fetchJson("data/catalog.json"), fetchJson("data/ai-assets.json")]);
    if (!Array.isArray(c?.repos) || !Array.isArray(a?.assets)) {
      throw new Error("catalog files are not in the expected format (repos[] / assets[])");
    }
    catalog = { meta: c.meta ?? {}, repos: c.repos, assets: a.assets };
  } catch (err) {
    $main.innerHTML = `<div class="empty"><h1>No catalog data found</h1>
      <p>Run <code>repo-catalog scan --org &lt;your-org&gt;</code> to produce <code>data/catalog.json</code>
      and <code>data/ai-assets.json</code>, then reload.</p><p class="muted">${esc(err)}</p></div>`;
    return;
  }
  for (const r of catalog.repos) { // catalogs from older scanner versions lack these fields
    r.flags ??= []; r.reusables ??= []; r.depends_on ??= []; r.used_by ??= [];
    r.stack.runtime_versions ??= [];
    r.dependency_summary ??= { direct: r.dependencies.length, transitive: 0, ecosystems: {}, lockfile_coverage: 0, vulnerable: 0 };
    for (const d of r.dependencies) { d.vulns ??= []; d.resolved ??= null; d.purl ??= null; }
  }
  for (const a of catalog.assets) a.flags ??= [];
  blocks = catalog.repos.flatMap((r) => r.reusables.map((x, i) => ({ ...x, id: `${r.id}::${i}`, repo: r.id, repoRef: r })));
  reposById = new Map(catalog.repos.map((r) => [r.id, r]));
  assetsById = new Map(catalog.assets.map((a) => [a.id, a]));
  blocksById = new Map(blocks.map((b) => [b.id, b]));
  repoIdx = new LazyIndex(repoIndex(), catalog.repos, onIndexReady);
  assetIdx = new LazyIndex(assetIndex(), catalog.assets, onIndexReady);
  blockIdx = new LazyIndex(blockIndex(), blocks, onIndexReady);
  render();
  // build search indexes after first paint, repos first (smaller, default tab)
  setTimeout(() => void repoIdx.start().then(() => blockIdx.start()).then(() => assetIdx.start()), 50);
}

async function fetchJson(url: string) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.json();
}

// ------------------------------------------------------------------------------------ render

function render(force = false): void {
  if (!catalog) return;
  if (!force && location.href === lastRendered) return; // popstate + hashchange both fire
  lastRendered = location.href;
  const state = readState();
  const listKey = `${state.tab}|${state.q}`;
  if (listKey !== lastList) shown = PAGE;
  lastList = listKey;

  document.querySelectorAll<HTMLAnchorElement>(".tabs a").forEach((a) => {
    const active = a.dataset.tab === state.tab;
    a.classList.toggle("active", active);
    if (active) {
      a.setAttribute("aria-current", "page");
      a.scrollIntoView({ block: "nearest", inline: "nearest" });
    } else a.removeAttribute("aria-current");
    a.href = `#/${a.dataset.tab}`;
  });
  document.title = `${TAB_TITLE[state.tab]} · Repo Catalog`;

  const focusedHref = (document.activeElement as HTMLElement | null)?.getAttribute?.("data-focus") ?? null;
  if (state.open && !$drawer.classList.contains("open")) returnFocus = focusedHref; // before re-render
  if (state.tab === "insights") renderInsights();
  else renderSearch(state);
  renderDrawer(state);
  if (focusedHref && !state.open) {
    // keep keyboard users where they were after a facet/"more" click re-rendered the list
    $main.querySelector<HTMLElement>(`[data-focus="${CSS.escape(focusedHref)}"]`)?.focus();
  }
}

interface ListView {
  results: unknown[]; total: number; noun: string; placeholder: string; examples: string[];
  defs: Record<string, { help: string }>; idx: LazyIndex<never> | LazyIndex<Repo> | LazyIndex<Asset> | LazyIndex<Block>;
  facets: string; card: (item: never) => string; csv: () => boolean;
}

function listView(tab: Tab, q: ReturnType<typeof resolveQuery>, raw: string): ListView {
  if (tab === "repos") {
    const results = runSearch(catalog.repos, repoIdx, q, REPO_FILTERS,
      (a, b) => (b.pushed_at ?? "").localeCompare(a.pushed_at ?? ""));
    return {
      results, total: catalog.repos.length, noun: "repositories", defs: REPO_FILTERS, idx: repoIdx,
      placeholder: "Search repos: what they do, stack, capabilities…",
      examples: ["lang:python fw:fastapi", "missing:tests", "sev:high", "usedby:yes", "depeco:docker"],
      facets: repoFacets(results, raw), card: repoCard as (x: never) => string,
      csv: () => downloadCsv("repos.csv", results.map(repoRow)),
    };
  }
  if (tab === "blocks") {
    const results = runSearch(blocks, blockIdx, q, BLOCK_FILTERS,
      (a, b) => a.kind.localeCompare(b.kind) || num(b.repoRef.practices.score) - num(a.repoRef.practices.score) || a.name.localeCompare(b.name));
    return {
      results, total: blocks.length, noun: "building blocks", defs: BLOCK_FILTERS, idx: blockIdx,
      placeholder: "Search actions, reusable workflows, Terraform modules, Helm charts, templates, APIs…",
      examples: ["kind:terraform-module", "kind:reusable-workflow", "kind:action release", "kind:api", "kind:helm-chart"],
      facets: blockFacets(results, raw), card: blockCard as (x: never) => string,
      csv: () => downloadCsv("building-blocks.csv", results.map(blockRow)),
    };
  }
  const results = runSearch(catalog.assets, assetIdx, q, ASSET_FILTERS,
    (a, b) => num(b.quality_score) - num(a.quality_score) || a.name.localeCompare(b.name));
  return {
    results, total: catalog.assets.length, noun: "AI assets", defs: ASSET_FILTERS, idx: assetIdx,
    placeholder: "Search skills, agents, prompts, rules, MCP servers…",
    examples: ["kind:skill", "code review", "kind:mcp-server", "eco:cursor", "kind:prompt minq:60", "sev:high"],
    facets: assetFacets(results, raw), card: assetCard as (x: never) => string,
    csv: () => downloadCsv("ai-assets.csv", results.map(assetRow)),
  };
}

function renderSearch(state: State): void {
  const defsFor = state.tab === "repos" ? REPO_FILTERS : state.tab === "blocks" ? BLOCK_FILTERS : ASSET_FILTERS;
  const q = resolveQuery(parseQuery(state.q), defsFor);
  const view = listView(state.tab, q, state.q);
  const results = view.results as never[];

  const existing = document.getElementById("q") as HTMLInputElement | null;
  const keepFocus = existing && document.activeElement === existing;
  const sel = existing ? [existing.selectionStart, existing.selectionEnd, existing.selectionDirection] as const : null;

  const { examples, defs, idx } = view;
  const help = Object.entries(defs).map(([k, d]) => `<li><code>${k}:</code> ${esc(d.help)}</li>`).join("")
    + "<li>Prefix with <code>-</code> to exclude. Repeat a key to OR values. Quote values with spaces. End a value with <code>*</code> to match by prefix (<code>tool:Bash*</code>).</li>"
    + (state.tab === "repos" ? "<li><code>is:public</code> / <code>is:private</code> need a scan with GitHub discovery (<code>--org</code>); <code>--local</code> scans have no visibility.</li>" : "");
  const indexing = q.text.trim() && !idx.ready
    ? `<p class="notice" role="status">Building the search index (${Math.round(idx.progress * 100)}%). Showing exact matches until it is ready.</p>`
    : "";
  const unknown = q.unknown.length
    ? `<p class="notice" role="status">Not a filter here: ${q.unknown.map((k) => `<code>${esc(k)}:</code>`).join(", ")}. Searched as text.</p>`
    : "";

  $main.innerHTML = `
    <h1 class="sr-only">${esc(TAB_TITLE[state.tab])}</h1>
    <a class="skip" href="#results">Skip to results</a>
    <section class="search">
      <label class="sr-only" for="q">Search ${view.noun}</label>
      <div class="search-box">
        <svg aria-hidden="true" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>
        <input id="q" type="search" autocomplete="off" spellcheck="false" value="${esc(state.q)}"
          placeholder="${esc(view.placeholder)}" />
        <kbd aria-hidden="true">/</kbd>
      </div>
      <div class="search-meta">
        <span><strong>${fmtNum(results.length)}</strong> of ${fmtNum(view.total)} ${view.noun}</span>
        <span class="examples">Try ${examples.map((e) => `<a href="${esc(href({ q: e, open: null }))}">${esc(e)}</a>`).join(" ")}</span>
        <details class="help"><summary>Query syntax</summary><ul>${help}</ul></details>
        <button type="button" class="btn-link" id="csv" ${results.length ? "" : "disabled"}>Export CSV</button>
      </div>
      ${unknown}${indexing}
    </section>
    <div class="layout">
      <aside class="facets" aria-label="Filters">${view.facets}</aside>
      <section class="results" id="results" tabindex="-1" aria-live="polite" aria-label="Results">
        ${results.length ? results.slice(0, shown).map(view.card).join("")
          : `<div class="empty"><h2>No matches</h2><p>Remove a filter or try broader words.</p></div>`}
        ${results.length > shown ? `<button type="button" class="more-btn" id="more" data-focus="more">Show ${Math.min(PAGE, results.length - shown)} more</button>` : ""}
      </section>
    </div>`;

  const input = document.getElementById("q") as HTMLInputElement;
  if (keepFocus) {
    input.focus();
    if (sel && sel[0] !== null && sel[1] !== null) input.setSelectionRange(sel[0], sel[1], sel[2] ?? "none");
  }
  let timer: number | undefined;
  input.addEventListener("input", () => {
    clearTimeout(timer);
    timer = window.setTimeout(() => navigate({ q: input.value, open: null }, true), 140);
  });
  document.getElementById("more")?.addEventListener("click", () => {
    shown += PAGE;
    render(true);
    document.getElementById("more")?.focus();
  });
  document.getElementById("csv")?.addEventListener("click", () => view.csv());
  document.querySelector(".facets")?.addEventListener("click", (e) => {
    const btn = (e.target as HTMLElement).closest<HTMLButtonElement>("[data-more]");
    if (!btn) return;
    const group = btn.closest(".facet-group")!;
    const expanded = group.classList.toggle("expanded");
    btn.textContent = expanded ? "Less" : "More";
    btn.setAttribute("aria-expanded", String(expanded));
  });
}

// --------------------------------------------------------------------------------- facets

function facetGroup(title: string, key: string, entries: [string, number][], q: string, limit = 8, label = (v: string) => v): string {
  if (!entries.length) return "";
  const items = entries.slice(0, 40).map(([value, n], i) => {
    const on = hasFilter(q, key, facetValue(value));
    const target = href({ q: toggleFilter(q, key, facetValue(value)), open: null });
    return `<li${i >= limit && !on ? ' class="extra"' : ""}><a class="facet${on ? " on" : ""}" data-focus="facet:${esc(key)}:${esc(value)}"
      href="${esc(target)}"><span>${esc(label(value))}${on ? '<span class="sr-only"> (selected, click to remove)</span>' : ""}</span><span class="n">${num(n)}</span></a></li>`;
  }).join("");
  // "More" also serves the compact mobile layout, which shows 4 per group
  const more = entries.length > 4 ? `<button type="button" class="btn-link facet-more" data-more aria-expanded="false">More</button>` : "";
  return `<div class="facet-group${entries.length <= limit ? " few" : ""}"><h2>${esc(title)}</h2><ul>${items}</ul>${more}</div>`;
}

/** Facet counts use the filter's own getter, so a facet's number is what its click returns. */
function counts<T>(items: T[], defs: Record<string, FilterDef<T>>, key: string): [string, number][] {
  return countBy(items, defs[key]!.get);
}

function repoFacets(rs: Repo[], q: string): string {
  const c = (key: string) => counts(rs, REPO_FILTERS, key);
  return [
    facetGroup("Type", "type", c("type"), q),
    facetGroup("Language", "lang", c("lang"), q),
    facetGroup("Framework", "fw", c("fw"), q),
    facetGroup("Capability or domain", "cap", c("cap"), q),
    facetGroup("Data & messaging", "data", c("data"), q),
    facetGroup("Cloud & infra", "infra", c("infra"), q),
    facetGroup("Uses AI", "ai", c("ai"), q, 8, (v) => (v === "yes" ? "Yes" : "No")),
    facetGroup("Practices grade", "grade", c("grade").sort((a, b) => a[0].localeCompare(b[0])), q),
    facetGroup("Missing practice", "missing", c("missing"), q),
    facetGroup("Lifecycle", "lifecycle", c("lifecycle"), q),
    facetGroup("Findings", "flag", c("flag"), q, 8, flagLabel),
    facetGroup("Severity", "sev", c("sev").sort((a, b) => num(SEV_ORDER[a[0]]) - num(SEV_ORDER[b[0]])), q),
    facetGroup("Ships building blocks", "reuse", c("reuse"), q, 8, (v) => BLOCK_LABEL[v] ?? v),
    facetGroup("Used by other repos", "usedby", c("usedby"), q, 8, (v) => (v === "yes" ? "Yes" : "No")),
    facetGroup("Topic", "topic", c("topic"), q),
  ].join("");
}

function assetFacets(as: Asset[], q: string): string {
  const c = (key: string) => counts(as, ASSET_FILTERS, key);
  return [
    facetGroup("Kind", "kind", c("kind"), q, 12, (v) => KIND_LABEL[v] ?? v),
    facetGroup("Ecosystem", "eco", c("eco"), q),
    facetGroup("Repository", "repo", countBy(as, (a) => a.repo), q, 8, (v) => v.split("/")[1] ?? v),
    facetGroup("Tag or category", "tag", c("tag"), q),
    facetGroup("Tools", "tool", c("tool"), q),
    facetGroup("Models", "model", c("model"), q),
    facetGroup("Confidence", "conf", c("conf"), q),
    facetGroup("Copied elsewhere", "dup", c("dup"), q, 8, (v) => (v === "yes" ? "Yes" : "No")),
    facetGroup("Findings", "flag", c("flag"), q, 8, flagLabel),
  ].join("");
}

function blockFacets(bs: Block[], q: string): string {
  const c = (key: string) => counts(bs, BLOCK_FILTERS, key);
  return [
    facetGroup("Kind", "kind", c("kind"), q, 8, (v) => BLOCK_LABEL[v] ?? v),
    facetGroup("Format", "format", c("format"), q),
    facetGroup("Repository", "repo", countBy(bs, (b) => b.repo), q, 8, (v) => v.split("/")[1] ?? v),
    facetGroup("Repo language", "lang", c("lang"), q),
    facetGroup("Repo grade", "grade", c("grade").sort((a, b) => a[0].localeCompare(b[0])), q),
    facetGroup("Repo lifecycle", "lifecycle", c("lifecycle"), q),
  ].join("");
}

// ---------------------------------------------------------------------------------- cards

function grade(g: string, score: number): string {
  const safe = GRADES.has(g) ? g : "F";
  return `<span class="grade grade-${safe}" title="Best-practices score ${num(score)}/100">${safe}<span class="sr-only"> grade, ${num(score)} of 100</span></span>`;
}

function repoCard(r: Repo): string {
  const s = r.stack;
  const blurb = r.summary.purpose ?? r.summary.one_liner ?? r.summary.readme_excerpt ?? "No description.";
  const link = href({ open: r.id });
  return `<article class="card">
    <a class="card-link" href="${esc(link)}" data-focus="${esc(link)}" aria-label="Open ${esc(r.id)}"></a>
    <header>
      <div class="card-title"><h2>${esc(r.name)}</h2><span class="muted">${esc(r.owner)}</span>
        ${r.archived ? '<span class="badge">archived</span>' : ""}${r.visibility === "private" ? '<span class="badge">private</span>' : ""}</div>
      ${grade(r.practices.grade, r.practices.score)}
    </header>
    <p class="blurb">${esc(blurb)}</p>
    <div class="chips">
      <span class="chip type">${esc(r.structure.repo_type)}</span>
      ${s.primary_language ? `<span class="chip lang">${esc(s.primary_language)}</span>` : ""}
      ${chips([...s.frameworks, ...s.databases, ...s.cloud].slice(0, 6))}
      ${r.ai.has_ai ? `<span class="chip ai">AI · ${num(r.ai.asset_count)}</span>` : ""}
      ${r.used_by.length ? `<span class="chip reuse">used by ${num(r.used_by.length)}</span>` : ""}
      ${sevChip(r.flags)}
    </div>
    <footer class="muted"><span class="caps">${r.capabilities.slice(0, 5).map(esc).join(" · ")}</span><span class="spacer"></span><span class="when">updated ${relTime(r.ownership.last_commit ?? r.pushed_at)}</span></footer>
  </article>`;
}

function assetCard(a: Asset): string {
  const blurb = a.summary ?? a.description ?? a.excerpt ?? "";
  const link = href({ open: a.id });
  return `<article class="card">
    <a class="card-link" href="${esc(link)}" data-focus="${esc(link)}" aria-label="Open ${esc(a.name)}"></a>
    <header>
      <div class="card-title"><span class="kind kind-${esc(a.kind)}">${esc(KIND_LABEL[a.kind] ?? a.kind)}</span><h2>${esc(a.name)}</h2></div>
      <span class="quality" title="Quality heuristic ${num(a.quality_score)}/100">${num(a.quality_score)}</span>
    </header>
    <p class="blurb">${esc(blurb)}</p>
    <div class="chips"><span class="chip eco">${esc(a.ecosystem)}</span>${chips([...a.tools, ...a.models].slice(0, 5))}
      ${a.duplicates.length ? `<span class="chip">${a.duplicates.length} cop${a.duplicates.length > 1 ? "ies" : "y"}</span>` : ""}
      ${a.confidence !== "high" ? `<span class="chip muted-chip">${esc(a.confidence)} confidence</span>` : ""}${sevChip(a.flags)}</div>
    <footer class="muted"><span class="path">${esc(a.repo)} · ${esc(a.path)}</span><span class="spacer"></span><span class="when">${a.last_modified ? `edited ${relTime(a.last_modified)}` : ""}</span></footer>
  </article>`;
}

/** Chip for the worst findings on a card, e.g. "2 high". */
function sevChip(flags: Flag[]): string {
  for (const sev of ["high", "medium"] as const) {
    const n = flags.filter((f) => f.severity === sev).length;
    if (n) return `<span class="chip sev-${sev}" title="${esc(flags.filter((f) => f.severity === sev).map((f) => flagLabel(f.id)).join(", "))}">${n} ${sev}</span>`;
  }
  return "";
}

function blockSummary(b: Block): string {
  const d = b.details;
  const list = (v: unknown) => (Array.isArray(v) ? v.map(String) : []);
  const parts: string[] = [];
  if (d.format) parts.push(String(d.format));
  if (d.engine) parts.push(String(d.engine));
  if (d.using) parts.push(String(d.using));
  if (typeof d.operations === "number") parts.push(`${num(d.operations)} operations`);
  if (typeof d.variables === "number") parts.push(`${num(d.variables)} variables`);
  else if (list(d.variables).length) parts.push(`${list(d.variables).length} variables`);
  if (typeof d.outputs === "number") parts.push(`${num(d.outputs)} outputs`);
  if (list(d.inputs).length) parts.push(`inputs: ${list(d.inputs).slice(0, 4).join(", ")}${list(d.inputs).length > 4 ? "…" : ""}`);
  if (d.version) parts.push(`v${String(d.version)}`);
  return parts.join(" · ");
}

function blockCard(b: Block): string {
  const link = href({ open: b.id });
  return `<article class="card">
    <a class="card-link" href="${esc(link)}" data-focus="${esc(link)}" aria-label="Open ${esc(b.name)}"></a>
    <header>
      <div class="card-title"><span class="kind kind-block">${esc(BLOCK_LABEL[b.kind] ?? b.kind)}</span><h2>${esc(b.name)}</h2></div>
      ${grade(b.repoRef.practices.grade, b.repoRef.practices.score)}
    </header>
    <p class="blurb">${esc(b.description ?? b.repoRef.summary.one_liner ?? "")}</p>
    <div class="chips">${b.repoRef.stack.primary_language ? `<span class="chip lang">${esc(b.repoRef.stack.primary_language)}</span>` : ""}<span class="chip muted-chip">${esc(blockSummary(b))}</span></div>
    <footer class="muted"><span class="path">${esc(b.repo)} · ${esc(b.path)}</span><span class="spacer"></span><span class="when">${esc(b.repoRef.lifecycle)}</span></footer>
  </article>`;
}

// --------------------------------------------------------------------------------- drawer

function renderDrawer(state: State): void {
  const repo = state.open ? reposById.get(state.open) : undefined;
  const asset = state.open ? assetsById.get(state.open) : undefined;
  const block = state.open ? blocksById.get(state.open) : undefined;
  const open = !!(repo || asset || block);
  const wasOpen = $drawer.classList.contains("open");
  $drawer.classList.toggle("open", open);
  $drawer.toggleAttribute("inert", !open);
  $scrim.hidden = !open;
  document.body.classList.toggle("drawer-open", open);
  if (!open) {
    $drawer.innerHTML = "";
    if (wasOpen) {
      const back = returnFocus && $main.querySelector<HTMLElement>(`[data-focus="${CSS.escape(returnFocus)}"]`);
      (back || document.getElementById("q") || $main).focus();
      returnFocus = null;
    }
    return;
  }
  // focus guards at both ends keep Tab / Shift+Tab cycling inside the dialog
  $drawer.innerHTML = `<span class="focus-guard" tabindex="0" data-guard="start"></span><button type="button" class="icon-btn close" aria-label="Close details">✕</button>${repo ? repoDetail(repo) : block ? blockDetail(block) : assetDetail(asset!)}<span class="focus-guard" tabindex="0" data-guard="end"></span>`;
  $drawer.querySelectorAll<HTMLElement>("[data-guard]").forEach((guard) =>
    guard.addEventListener("focus", () => {
      const items = focusables();
      (guard.dataset.guard === "start" ? items[items.length - 1] : items[0])?.focus();
    }),
  );
  $drawer.querySelector(".close")!.addEventListener("click", closeDrawer);
  $drawer.querySelector<HTMLButtonElement>("[data-copy]")?.addEventListener("click", async (e) => {
    const btn = e.currentTarget as HTMLButtonElement;
    btn.textContent = (await copyText(asset?.content ?? "")) ? "Copied" : "Copy failed";
  });
  $drawer.focus();
}

function closeDrawer(): void {
  navigate({ open: null }, true); // replace: Back should not re-open what was just closed
}

function focusables(): HTMLElement[] {
  return [...$drawer.querySelectorAll<HTMLElement>(
    'a[href], button:not([disabled]), summary, [tabindex]:not([tabindex="-1"])',
  )].filter((el) => !el.dataset.guard && el.getClientRects().length > 0);
}

// Belt and braces: if focus lands outside the open dialog by any route, bring it back.
document.addEventListener("focusin", (e) => {
  if ($drawer.classList.contains("open") && !$drawer.contains(e.target as Node)) {
    (focusables()[0] ?? $drawer).focus();
  }
});

function section(title: string, body: string): string {
  return body.trim() ? `<section class="d-section"><h3>${esc(title)}</h3>${body}</section>` : "";
}

function kv(rows: [string, string | null | undefined][]): string {
  const body = rows.filter(([, v]) => v).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join("");
  return body ? `<dl class="kv">${body}</dl>` : "";
}

function tagLinks(values: string[], key: string, tab: Tab = "repos"): string {
  return values.map((v) => `<a class="chip" href="${esc(href({ tab, q: `${key}:${/\s/.test(v) ? `"${v}"` : v}`, open: null }))}">${esc(v)}</a>`).join("");
}

function extLink(url: unknown, label: string, cls = "btn secondary"): string {
  const u = safeUrl(url);
  return u === "#" ? "" : `<a class="${cls}" href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(label)}</a>`;
}

function repoDetail(r: Repo): string {
  const s = r.stack;
  const assets = catalog.assets.filter((a) => a.repo === r.id);
  const failing = r.practices.checks.filter((c) => !c.passed);
  const ds = r.dependency_summary;
  const deps = [...r.dependencies].sort((a, b) => num(b.vulns.length) - num(a.vulns.length) || a.ecosystem.localeCompare(b.ecosystem) || a.name.localeCompare(b.name));
  return `<div class="d-head">
      <p class="eyebrow">${esc(r.structure.repo_type)} · ${esc(r.lifecycle)}${r.declared.system ? ` · system ${esc(r.declared.system)}` : ""}</p>
      <h2 id="drawer-title">${esc(r.id)}</h2>
      <p class="lead">${esc(r.summary.one_liner ?? r.description ?? "")}</p>
      <div class="actions">${extLink(r.url, "Open on GitHub", "btn")}
        ${extLink(r.homepage, "Homepage")}
        ${r.declared.links.map((l) => extLink(l.url, l.title || "Link")).join("")}</div>
    </div>
    ${section("What it does", `${r.summary.purpose ? `<p>${esc(r.summary.purpose)}</p>` : ""}
      ${r.summary.readme_excerpt && r.summary.readme_excerpt !== r.summary.purpose ? `<p class="muted">${esc(r.summary.readme_excerpt)}</p>` : ""}
      ${r.summary.key_features.length ? `<ul>${r.summary.key_features.map((f) => `<li>${esc(f)}</li>`).join("")}</ul>` : ""}
      ${r.summary.reuse_notes ? `<p class="callout"><strong>Reuse:</strong> ${esc(r.summary.reuse_notes)}</p>` : ""}
      ${r.summary.source === "llm" ? '<p class="muted small">Summary generated by Claude from the README and code facts.</p>' : ""}`)}
    ${r.flags.length ? section(`Findings (${r.flags.length})`, flagList(r.flags, r)) : ""}
    ${section(`Building blocks (${r.reusables.length})`, r.reusables.length ? `<ul class="mini-list">${r.reusables.map((x, i) =>
      `<li><a href="${esc(href({ tab: "blocks", open: `${r.id}::${i}`, q: "" }))}"><span class="kind kind-block">${esc(BLOCK_LABEL[x.kind] ?? x.kind)}</span> ${esc(x.name)}</a> <span class="muted small">${esc(x.path)}</span></li>`).join("")}</ul>` : "")}
    ${section("Relationships", kv([
      ["Depends on", r.depends_on.map((l) => repoLink(l.repo, l.via)).join("<br>")],
      ["Used by", r.used_by.map((l) => repoLink(l.repo, l.via)).join("<br>")],
    ]))}
    ${section("Capabilities", `<div class="chips">${tagLinks([...r.capabilities, ...r.summary.domains], "cap")}</div>`)}
    ${section("Stack", `<dl class="kv">
      <dt>Languages</dt><dd>${s.languages.slice(0, 6).map((l) => `${esc(l.name)} <span class="muted">${num(l.percent)}%</span>`).join(", ") || "—"}</dd>
      ${Object.keys(s.runtimes).length ? `<dt>Runtimes</dt><dd>${Object.entries(s.runtimes).map(([k, v]) => `${esc(k)} ${esc(v)}`).join(", ")}</dd>` : ""}
      ${s.runtime_versions.length ? `<dt>Pinned versions</dt><dd>${s.runtime_versions.slice(0, 12).map((v) => `${esc(v.runtime)} ${esc(v.version)} <span class="muted small">${esc(v.path)}</span>`).join("<br>")}</dd>` : ""}
      ${STACK_ROWS.filter(([k]) => (s[k] as string[]).length).map(([k, label, key]) => `<dt>${label}</dt><dd class="chips">${tagLinks(s[k] as string[], key)}</dd>`).join("")}
    </dl>`)}
    ${section(`Best practices · ${num(r.practices.score)}/100`, `<ul class="checks">${r.practices.checks.map((c) =>
      `<li class="${c.passed ? "pass" : "fail"}"><span aria-hidden="true">${c.passed ? "✓" : "✗"}</span><span class="sr-only">${c.passed ? "Passed" : "Failed"}:</span> ${esc(c.label)}${c.evidence ? ` <span class="muted small">${esc(c.evidence)}</span>` : ""}</li>`).join("")}</ul>
      ${failing.length ? `<p class="muted small">${failing.length} check(s) failing. Weighted by importance; see docs/catalog-data.md.</p>` : ""}`)}
    ${section(`AI assets (${assets.length})`, assets.length ? `<ul class="mini-list">${assets.map((a) =>
      `<li><a href="${esc(href({ tab: "assets", open: a.id, q: "" }))}"><span class="kind kind-${esc(a.kind)}">${esc(KIND_LABEL[a.kind] ?? a.kind)}</span> ${esc(a.name)}</a> <span class="muted small">${esc(a.path)}</span></li>`).join("")}</ul>
      ${kv([["SDKs", r.ai.sdks.map(esc).join(", ")], ["Models", r.ai.models.map(esc).join(", ")],
            ["MCP provided", r.ai.mcp_servers_provided.map(esc).join(", ")], ["MCP consumed", r.ai.mcp_servers_consumed.map(esc).join(", ")]])}` : "")}
    ${section("Structure", kv([
      ["Size", `${fmtNum(r.structure.file_count)} files · ${fmtNum(r.structure.total_lines)} lines`],
      ["Packages", r.structure.packages.slice(0, 20).map((p) => `<code>${esc(p.name)}</code>${p.path ? ` <span class="muted small">${esc(p.path)}</span>` : ""}`).join("<br>")],
      ["Entrypoints", r.structure.entrypoints.slice(0, 12).map((e) => `<code>${esc(e)}</code>`).join(" ")],
      ["API specs", r.structure.api_specs.map((e) => `<code>${esc(e)}</code>`).join(" ")],
      ["Docs", r.structure.docs.map((e) => `<code>${esc(e)}</code>`).join(" ")],
      ["Top level", r.structure.top_level.slice(0, 30).map((e) => `<code>${esc(e)}</code>`).join(" ")],
    ]))}
    ${section(`Dependencies (${fmtNum(ds.direct)} direct${ds.transitive ? ` · ${fmtNum(ds.transitive)} transitive` : ""})`, r.dependencies.length ? `
      <p class="small muted">${Object.entries(ds.ecosystems).map(([e, n]) => `<a href="${esc(href({ tab: "repos", q: `depeco:${e}`, open: null }))}">${esc(e)}</a> ${num(n)}`).join(" · ")}
        ${ds.lockfile_coverage ? ` · ${Math.round(num(ds.lockfile_coverage) * 100)}% of packages locked to an exact version` : ""}
        ${ds.vulnerable ? ` · <strong class="sev sev-high">${num(ds.vulnerable)} with known advisories</strong>` : ""}</p>
      <details><summary>Show ${fmtNum(deps.length)} direct dependencies</summary>
      <div class="table-wrap" tabindex="0" role="region" aria-label="Dependencies"><table class="deps"><thead><tr><th>Name</th><th>Declared</th><th>Locked</th><th>Scope</th><th>Ecosystem</th><th>Manifest</th></tr></thead><tbody>
      ${deps.slice(0, 500).map((d) => `<tr><td><a href="${esc(href({ tab: "repos", q: `dep:${/\s/.test(d.name) ? `"${d.name}"` : d.name}`, open: null }))}">${esc(d.name)}</a>${d.vulns.length ? ` <a class="sev sev-high" href="${esc(safeUrl(`https://osv.dev/vulnerability/${encodeURIComponent(d.vulns[0]!)}`))}" target="_blank" rel="noopener noreferrer" title="${esc(d.vulns.join(", "))}">${d.vulns.length} advisor${d.vulns.length > 1 ? "ies" : "y"}</a>` : ""}</td>
        <td>${esc(d.version ?? "")}</td><td>${esc(d.resolved ?? "")}</td><td>${esc(d.scope)}</td><td>${esc(d.ecosystem)}</td><td class="muted">${esc(d.manifest)}</td></tr>`).join("")}
      </tbody></table></div>${ds.transitive ? `<p class="small muted">Transitive dependencies are in the per-repo JSON, <code>catalog.db</code> and <code>data/sbom/</code>.</p>` : ""}</details>` : "")}
    ${section("Ownership", kv([
      ["Declared owner", esc(r.declared.owner)],
      ["CODEOWNERS", r.ownership.codeowners.map(esc).join(", ")],
      ["Top contributors", r.ownership.top_contributors.slice(0, 6).map((c) => `${esc(c.name)} <span class="muted">(${num(c.commits)})</span>`).join(", ")],
      ["History", r.ownership.commit_count ? `${fmtNum(r.ownership.commit_count)} commits, last ${relTime(r.ownership.last_commit)}` : null],
      ["License", esc(r.license)],
      ["Descriptor", r.declared.source_files.map(esc).join(", ")],
    ]))}
    ${r.scan_errors.length ? section("Scan notes", `<ul class="small muted">${r.scan_errors.map((e) => `<li>${esc(e)}</li>`).join("")}</ul>`) : ""}
    <p class="muted small">Scanned ${relTime(r.scanned_at)}</p>`;
}

function assetDetail(a: Asset): string {
  const isMarkdown = /\.(md|mdc|prompt|prompty)$/i.test(a.path)
    || (["skill", "agent", "command", "instructions"].includes(a.kind) && !/\.(json|ya?ml|toml|py|[cm]?[jt]sx?|go)$/i.test(a.path));
  const body = a.content ?? "";
  const rendered = isMarkdown ? `<div class="md">${markdown(body.replace(/^---[\s\S]*?\n---\s*\n/, ""))}</div>`
    : `<pre tabindex="0"><code>${esc(body)}</code></pre>`;
  const dupes = a.duplicates.map((id) => assetsById.get(id)).filter((x): x is Asset => !!x);
  const fm = Object.keys(a.frontmatter).length ? `<details><summary>Metadata / frontmatter</summary><pre tabindex="0"><code>${esc(JSON.stringify(a.frontmatter, null, 2))}</code></pre></details>` : "";
  return `<div class="d-head">
      <p class="eyebrow"><span class="kind kind-${esc(a.kind)}">${esc(KIND_LABEL[a.kind] ?? a.kind)}</span> ${esc(a.ecosystem)} · ${esc(a.scope)} scope</p>
      <h2 id="drawer-title">${esc(a.title ?? a.name)}</h2>
      ${a.title ? `<p class="muted">${esc(a.name)}</p>` : ""}
      <p class="lead">${esc(a.summary ?? a.description ?? "")}</p>
      <div class="actions">${extLink(a.url, "Open on GitHub", "btn")}
        ${body ? '<button type="button" class="btn secondary" data-copy>Copy content</button>' : ""}
        <a class="btn secondary" href="${esc(href({ tab: "repos", open: a.repo, q: "" }))}">View repo</a></div>
    </div>
    ${a.flags.length ? section(`Findings (${a.flags.length})`, flagList(a.flags, reposById.get(a.repo), "assets")) : ""}
    ${a.summary && a.description ? section("Description", `<p>${esc(a.description)}</p>`) : ""}
    ${a.use_cases.length ? section("Use cases", `<ul>${a.use_cases.map((u) => `<li>${esc(u)}</li>`).join("")}</ul>`) : ""}
    ${section("Details", kv([
      ["Location", `${esc(a.repo)} · <code>${esc(a.path)}</code>`],
      ["Tools", a.tools.length ? `<div class="chips">${tagLinks(a.tools, "tool", "assets")}</div>` : null],
      ["Models", a.models.map(esc).join(", ")],
      ["Triggers", a.triggers.map((t) => `<code>${esc(t)}</code>`).join(" ")],
      ["Arguments", a.arguments.map((t) => `<code>${esc(t)}</code>`).join(" ")],
      ["MCP servers", a.mcp_servers.map(esc).join(", ")],
      ["Tags", a.tags.length ? `<div class="chips">${tagLinks(a.tags, "tag", "assets")}</div>` : null],
      ["Category", esc(a.category)],
      ["Version / license", [a.version, a.license].filter(Boolean).map(esc).join(" · ")],
      ["Size", `${fmtNum(a.line_count)} lines · ${fmtNum(a.word_count)} words · ~${fmtNum(a.token_estimate)} tokens`],
      ["Last edit", a.last_modified ? `${relTime(a.last_modified)} by ${esc(a.last_author)} · ${num(a.commit_count)} commit(s)` : null],
      ["Detected by", `${esc(a.detector)} · ${esc(a.confidence)} confidence`],
    ]))}
    ${section(`Quality · ${num(a.quality_score)}/100`, a.quality_notes.length ? `<ul class="checks">${a.quality_notes.map((n) => `<li class="fail"><span aria-hidden="true">!</span> ${esc(n)}</li>`).join("")}</ul>` : '<p class="muted">No issues found by the heuristics.</p>')}
    ${a.files.length ? section(`Bundled files (${a.files.length})`, `<ul class="mini-list">${a.files.map((f) => `<li><code>${esc(f.path)}</code> <span class="muted small">${fmtNum(f.size)} B</span></li>`).join("")}</ul>`) : ""}
    ${dupes.length ? section("Identical copies", `<ul class="mini-list">${dupes.map((d) => `<li><a href="${esc(href({ open: d.id }))}">${esc(d.repo)} · ${esc(d.path)}</a></li>`).join("")}</ul>`) : ""}
    ${section("Content", `${a.content_truncated ? '<p class="muted small">Truncated; open on GitHub for the full file.</p>' : ""}${fm}${body ? rendered : '<p class="muted">No content captured.</p>'}`)}`;
}

function repoLink(id: string, via: string): string {
  return `<a href="${esc(href({ tab: "repos", open: id, q: "" }))}">${esc(id)}</a> <span class="muted small">${esc(via)}</span>`;
}

function blobUrl(repo: Repo | undefined, path: string, line: number | null): string {
  if (!repo) return "#";
  const ref = (repo as Repo & { head_sha?: string | null }).head_sha || repo.default_branch || "HEAD";
  const encoded = path.split("/").map(encodeURIComponent).join("/");
  return safeUrl(`${repo.url}/blob/${encodeURIComponent(ref)}/${encoded}${line ? `#L${num(line)}` : ""}`);
}

function flagList(flags: Flag[], repo: Repo | undefined, tab: Tab = "repos"): string {
  const sorted = [...flags].sort((a, b) => num(SEV_ORDER[a.severity]) - num(SEV_ORDER[b.severity]) || a.id.localeCompare(b.id));
  return `<ul class="flag-list">${sorted.map((f) => {
    const sev = f.severity in SEV_ORDER ? f.severity : "low";
    const where = f.path
      ? ` <a class="small" href="${esc(blobUrl(repo, f.path, f.line))}" target="_blank" rel="noopener noreferrer">${esc(f.path)}${f.line ? `:${num(f.line)}` : ""}</a>`
      : "";
    return `<li><span class="sev sev-${sev}">${sev}</span><span><strong>${esc(flagLabel(f.id))}</strong> · ${esc(f.message)}${where}
      <a class="small muted" href="${esc(href({ tab, q: `flag:${f.id}`, open: null }))}">see all</a></span></li>`;
  }).join("")}</ul>`;
}

function blockDetail(b: Block): string {
  const d = b.details;
  const isList = (v: unknown): v is unknown[] => Array.isArray(v);
  const url = b.path === "." ? b.repoRef.url : blobUrl(b.repoRef, b.path, null).replace("/blob/", "/tree/");
  const rows: [string, string | null][] = Object.entries(d)
    .filter(([k, v]) => k !== "sample" && v !== null && v !== "" && !(isList(v) && !v.length))
    .map(([k, v]) => [k.replace(/_/g, " "), isList(v) ? v.map((x) => `<code>${esc(x)}</code>`).join(" ") : esc(v)]);
  const sample = isList(d.sample) && d.sample.length
    ? section("Operations", `<ul class="mini-list">${d.sample.map((x) => `<li><code>${esc(x)}</code></li>`).join("")}</ul>${num(d.operations) > d.sample.length ? `<p class="muted small">…and ${num(d.operations) - d.sample.length} more</p>` : ""}`)
    : "";
  return `<div class="d-head">
      <p class="eyebrow"><span class="kind kind-block">${esc(BLOCK_LABEL[b.kind] ?? b.kind)}</span> ${esc(b.repoRef.lifecycle)}</p>
      <h2 id="drawer-title">${esc(b.name)}</h2>
      <p class="lead">${esc(b.description ?? "")}</p>
      <div class="actions">${extLink(url, "Open on GitHub", "btn")}
        <a class="btn secondary" href="${esc(href({ tab: "repos", open: b.repo, q: "" }))}">View repo</a></div>
    </div>
    ${section("Details", kv([["Location", `${esc(b.repo)} · <code>${esc(b.path)}</code>`], ...rows]))}
    ${sample}
    ${section("About the repo", kv([
      ["Summary", esc(b.repoRef.summary.one_liner)],
      ["Practices", `${grade(b.repoRef.practices.grade, b.repoRef.practices.score)} ${num(b.repoRef.practices.score)}/100`],
      ["Owner", esc(b.repoRef.declared.owner ?? b.repoRef.ownership.codeowners.join(", "))],
      ["Last commit", relTime(b.repoRef.ownership.last_commit ?? b.repoRef.pushed_at)],
      ["Used by", b.repoRef.used_by.length ? `${num(b.repoRef.used_by.length)} org repos` : null],
    ]))}`;
}

// ------------------------------------------------------------------------------- insights

function bars(title: string, entries: [string, number][], link: (v: string) => string, total: number, limit = 10): string {
  const rows = entries.slice(0, limit);
  if (!rows.length) return "";
  const max = Math.max(1, ...rows.map(([, n]) => num(n))); // rows may be sorted by label, not size
  return `<figure class="panel"><figcaption>${esc(title)}</figcaption><ul class="bars">
    ${rows.map(([label, n]) => `<li><a href="${esc(link(label))}" title="${esc(label)}: ${num(n)} (${Math.round((100 * num(n)) / Math.max(total, 1))}%)">
      <span class="bar-label">${esc(label)}</span>
      <span class="bar-track" aria-hidden="true"><span class="bar" style="width:${Math.max(2, (100 * num(n)) / max).toFixed(1)}%"></span></span>
      <span class="bar-value">${fmtNum(n)}</span></a></li>`).join("")}
  </ul></figure>`;
}

function renderInsights(): void {
  const rs = catalog.repos;
  const as = catalog.assets;
  const active = rs.filter((r) => !r.archived);
  const pct = (n: number) => `${Math.round((100 * n) / Math.max(active.length, 1))}%`;
  const passing = (id: string) => active.filter((r) => r.practices.checks.some((c) => c.id === id && c.passed)).length;
  const avg = Math.round(active.reduce((s, r) => s + num(r.practices.score), 0) / Math.max(active.length, 1));
  const repoQ = (q: string) => href({ tab: "repos", q, open: null });
  const assetQ = (q: string) => href({ tab: "assets", q, open: null });
  const quote = (v: string) => (/\s/.test(v) ? `"${v}"` : v);
  const failCounts = countBy(active, (r) => r.practices.checks.filter((c) => !c.passed).map((c) => c.label));
  const labelToId = new Map(active.flatMap((r) => r.practices.checks.map((c) => [c.label, c.id] as const)));
  const kindByLabel = new Map(Object.entries(KIND_LABEL).map(([k, l]) => [l, k]));
  const flagIdByLabel = new Map([...rs.flatMap((r) => r.flags), ...as.flatMap((a) => a.flags)].map((f) => [flagLabel(f.id), f.id]));
  const repoFlagIds = new Set(rs.flatMap((r) => r.flags.map((f) => f.id)));
  const assetFlagsByRepo = new Map<string, Flag[]>();
  for (const a of as) if (a.flags.length) assetFlagsByRepo.set(a.repo, [...(assetFlagsByRepo.get(a.repo) ?? []), ...a.flags]);
  const blockKindByLabel = new Map(Object.entries(BLOCK_LABEL).map(([k, l]) => [l, k]));

  $main.innerHTML = `
    <h1 class="sr-only">Insights</h1>
    <section class="insights">
      <div class="kpis">
        <div class="kpi"><span class="kpi-value">${fmtNum(rs.length)}</span><span class="kpi-label">repositories · ${fmtNum(active.length)} active</span></div>
        <div class="kpi"><span class="kpi-value">${fmtNum(as.length)}</span><span class="kpi-label">AI assets in ${rs.filter((r) => r.ai.asset_count).length} repos</span></div>
        <div class="kpi"><span class="kpi-value">${avg}</span><span class="kpi-label">avg practices score / 100</span></div>
        <div class="kpi"><span class="kpi-value">${pct(passing("ci"))}</span><span class="kpi-label">have CI</span></div>
        <div class="kpi"><span class="kpi-value">${pct(passing("tests"))}</span><span class="kpi-label">have tests</span></div>
        <div class="kpi"><span class="kpi-value">${pct(passing("codeowners"))}</span><span class="kpi-label">declare owners</span></div>
      </div>
      <div class="grid">
        ${bars("Primary languages", countBy(rs, (r) => r.stack.primary_language), (v) => repoQ(`lang:${quote(v)}`), rs.length)}
        ${bars("Frameworks", countBy(rs, (r) => r.stack.frameworks), (v) => repoQ(`fw:${quote(v)}`), rs.length)}
        ${bars("Repo types", countBy(rs, (r) => r.structure.repo_type), (v) => repoQ(`type:${v}`), rs.length)}
        ${bars("Data stores", countBy(rs, (r) => r.stack.databases), (v) => repoQ(`data:${quote(v)}`), rs.length)}
        ${bars("Cloud & infrastructure", countBy(rs, (r) => [...r.stack.cloud, ...r.stack.infrastructure]), (v) => repoQ(`infra:${quote(v)}`), rs.length)}
        ${bars("Most common gaps (active repos)", failCounts, (v) => repoQ(`missing:${labelToId.get(v) ?? v} -is:archived`), active.length)}
        ${bars("AI assets by kind", countBy(as, (a) => KIND_LABEL[a.kind] ?? a.kind), (v) => assetQ(`kind:${kindByLabel.get(v) ?? v}`), as.length)}
        ${bars("AI ecosystems", countBy(as, (a) => a.ecosystem), (v) => assetQ(`eco:${v}`), as.length)}
        ${bars("LLM SDKs (repos)", countBy(rs, (r) => r.ai.sdks), (v) => repoQ(`uses:${quote(v)}`), rs.length)}
        ${bars("Models referenced (repos)", countBy(rs, (r) => r.ai.models), (v) => repoQ(`uses:${quote(v)}`), rs.length)}
        ${bars("Capabilities", countBy(rs, (r) => r.capabilities), (v) => repoQ(`cap:${quote(v)}`), rs.length, 14)}
        ${bars("Practices grade", countBy(rs, (r) => r.practices.grade).sort((a, b) => a[0].localeCompare(b[0])), (v) => repoQ(`grade:${v}`), rs.length)}
        ${bars("Findings (active repos)", countBy(active, (r) => [...r.flags, ...(assetFlagsByRepo.get(r.id) ?? [])].map((f) => flagLabel(f.id))), (v) => {
          const id = flagIdByLabel.get(v) ?? v;
          // findings raised on AI assets are filtered in the asset library, not on repos
          return repoFlagIds.has(id) ? repoQ(`flag:${id}`) : assetQ(`flag:${id}`);
        }, active.length, 12)}
        ${bars("Building blocks", countBy(blocks, (b) => BLOCK_LABEL[b.kind] ?? b.kind), (v) => href({ tab: "blocks", q: `kind:${blockKindByLabel.get(v) ?? v}`, open: null }), blocks.length)}
        ${bars("Dependency ecosystems (repos)", countBy(rs, (r) => Object.keys(r.dependency_summary.ecosystems)), (v) => repoQ(`depeco:${v}`), rs.length, 12)}
        ${bars("Packages with known advisories (repos)", countBy(rs, (r) => r.dependencies.filter((d) => d.vulns.length).map((d) => d.name)), (v) => repoQ(`dep:${quote(v)} vuln:yes`), rs.length)}
        ${bars("Most depended-on repos", rs.filter((r) => r.used_by.length).map((r) => [r.id, r.used_by.length] as [string, number]).sort((a, b) => b[1] - a[1]), (v) => href({ tab: "repos", open: v, q: "" }), rs.length)}
      </div>
      ${versionDrift(active)}
      <p class="muted small">Catalog generated ${relTime(catalog.meta.generated_at)} from ${esc(catalog.meta.source)} · scanner ${esc(catalog.meta.scanner_version)}${catalog.meta.llm_enriched ? " · summaries by Claude" : ""}. Click any bar to see the matching repos or assets.</p>
    </section>`;
}

/** Dependencies used across repos at different major versions: upgrade and consolidation targets. */
function versionDrift(rs: Repo[]): string {
  const byDep = new Map<string, Map<string, Set<string>>>();
  for (const r of rs) {
    for (const d of r.dependencies) {
      const version = d.resolved ?? d.version;
      if (d.scope === "transitive" || !version || d.ecosystem === "github-actions") continue;
      const major = /(\d+)(?:\.(\d+))?/.exec(version.replace(/^[^\d]*/, ""));
      if (!major) continue;
      const key = major[1] === "0" && major[2] !== undefined ? `0.${major[2]}` : major[1]!;
      const name = `${d.ecosystem}:${d.name}`;
      const majors = byDep.get(name) ?? new Map<string, Set<string>>();
      majors.set(key, (majors.get(key) ?? new Set()).add(r.id));
      byDep.set(name, majors);
    }
  }
  const rows = [...byDep.entries()]
    .map(([name, majors]) => ({ name, majors, repos: new Set([...majors.values()].flatMap((s) => [...s])).size }))
    .filter((x) => x.majors.size > 1 && x.repos > 1)
    .sort((a, b) => b.majors.size - a.majors.size || b.repos - a.repos)
    .slice(0, 15);
  if (!rows.length) return "";
  return `<figure class="panel wide"><figcaption>Version drift: same dependency on different major versions</figcaption>
    <div class="table-wrap" tabindex="0" role="region" aria-label="Version drift"><table class="deps"><thead><tr><th>Dependency</th><th>Repos</th><th>Major versions (repos)</th></tr></thead><tbody>
    ${rows.map((x) => {
      const [eco, ...rest] = x.name.split(":");
      const dep = rest.join(":");
      const majors = [...x.majors.entries()].sort((a, b) => Number(b[0]) - Number(a[0]))
        .map(([m, set]) => `<span class="chip" title="${esc([...set].join(", "))}">${esc(m)} · ${set.size}</span>`).join("");
      return `<tr><td><a href="${esc(href({ tab: "repos", q: `tech:${/\s/.test(dep) ? `"${dep}"` : dep}`, open: null }))}">${esc(dep)}</a> <span class="muted small">${esc(eco)}</span></td><td>${x.repos}</td><td class="chips">${majors}</td></tr>`;
    }).join("")}
    </tbody></table></div></figure>`;
}

// ---------------------------------------------------------------------------------- export

function repoRow(r: Repo): Record<string, unknown> {
  return {
    repo: r.id, url: r.url, type: r.structure.repo_type, lifecycle: r.lifecycle,
    language: r.stack.primary_language, frameworks: r.stack.frameworks.join("; "),
    databases: r.stack.databases.join("; "), cloud: r.stack.cloud.join("; "),
    capabilities: r.capabilities.join("; "), practices_score: r.practices.score,
    grade: r.practices.grade, ai_assets: r.ai.asset_count,
    direct_dependencies: r.dependency_summary.direct, transitive_dependencies: r.dependency_summary.transitive,
    vulnerable_dependencies: r.dependency_summary.vulnerable,
    high_findings: r.flags.filter((f) => f.severity === "high").map((f) => flagLabel(f.id)).join("; "),
    used_by: r.used_by.length, owner: r.declared.owner ?? r.ownership.codeowners.join("; "),
    last_commit: r.ownership.last_commit ?? r.pushed_at, summary: r.summary.purpose ?? r.summary.one_liner,
  };
}

function blockRow(b: Block): Record<string, unknown> {
  return {
    kind: b.kind, name: b.name, repo: b.repo, path: b.path,
    url: b.path === "." ? b.repoRef.url : blobUrl(b.repoRef, b.path, null).replace("/blob/", "/tree/"),
    description: b.description,
    summary: blockSummary(b), repo_grade: b.repoRef.practices.grade, repo_lifecycle: b.repoRef.lifecycle,
  };
}

function assetRow(a: Asset): Record<string, unknown> {
  return {
    name: a.name, kind: a.kind, ecosystem: a.ecosystem, repo: a.repo, path: a.path, url: a.url,
    description: a.summary ?? a.description, tools: a.tools.join("; "), models: a.models.join("; "),
    quality: a.quality_score, copies: a.duplicates.length, last_modified: a.last_modified,
  };
}

// ---------------------------------------------------------------------------------- wiring

window.addEventListener("hashchange", () => render());
window.addEventListener("popstate", () => render());
$scrim.addEventListener("click", closeDrawer);
document.addEventListener("keydown", (e) => {
  const typing = e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement;
  if (e.key === "/" && !typing && !$drawer.classList.contains("open")) {
    e.preventDefault();
    document.getElementById("q")?.focus();
  }
  if (e.key === "Escape" && readState().open) closeDrawer();
});

const THEME_KEY = "repo-catalog-theme";
const $theme = document.getElementById("theme")!;
function currentDark(): boolean {
  const t = document.documentElement.dataset.theme;
  return t ? t === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
}
function syncThemeButton(): void {
  $theme.setAttribute("aria-pressed", String(currentDark()));
  $theme.setAttribute("aria-label", currentDark() ? "Switch to light theme" : "Switch to dark theme");
}
$theme.addEventListener("click", () => {
  const next = currentDark() ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem(THEME_KEY, next); } catch { /* storage unavailable */ }
  syncThemeButton();
});
syncThemeButton();

void load();
