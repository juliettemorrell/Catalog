import "./styles.css";
import type MiniSearch from "minisearch";
import {
  ASSET_FILTERS, REPO_FILTERS, assetIndex, hasFilter, parseQuery, repoIndex, runSearch, toggleFilter,
} from "./search";
import type { Asset, Catalog, Repo } from "./types";
import { chips, countBy, downloadCsv, esc, fmtNum, markdown, relTime } from "./util";

type Tab = "repos" | "assets" | "insights";
interface State { tab: Tab; q: string; open: string | null }

const PAGE = 60;
const KIND_LABEL: Record<string, string> = {
  skill: "Skill", agent: "Agent", command: "Command", prompt: "Prompt", instructions: "Rules / instructions",
  "mcp-server": "MCP server", "mcp-config": "MCP config", hook: "Hook", plugin: "Plugin", eval: "Eval",
  workflow: "Workflow", "sdk-usage": "LLM SDK usage",
};
const STACK_ROWS: [keyof Repo["stack"], string][] = [
  ["frameworks", "Frameworks"], ["libraries", "Libraries"], ["databases", "Data"], ["messaging", "Messaging"],
  ["auth", "Auth"], ["ai", "AI / ML"], ["cloud", "Cloud"], ["infrastructure", "Infrastructure"],
  ["ci_cd", "CI/CD"], ["testing", "Testing"], ["linting", "Quality tooling"], ["build_tools", "Build"],
  ["observability", "Observability"], ["package_managers", "Package managers"],
];

let catalog: Catalog;
let repoIdx: MiniSearch<Repo>;
let assetIdx: MiniSearch<Asset>;
let assetsById = new Map<string, Asset>();
let reposById = new Map<string, Repo>();
let shown = PAGE;

const $main = document.getElementById("main")!;
const $drawer = document.getElementById("drawer")!;
const $scrim = document.getElementById("scrim")!;

// ------------------------------------------------------------------------------------ state

function readState(): State {
  const [path = "", query = ""] = location.hash.replace(/^#\/?/, "").split("?");
  const params = new URLSearchParams(query);
  const tab = (["repos", "assets", "insights"].includes(path) ? path : "repos") as Tab;
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
    catalog = { meta: c.meta, repos: c.repos, assets: a.assets };
  } catch (err) {
    $main.innerHTML = `<div class="empty"><h2>No catalog data found</h2>
      <p>Run <code>repo-catalog scan --org &lt;your-org&gt;</code> to produce <code>data/catalog.json</code>
      and <code>data/ai-assets.json</code>, then reload.</p><p class="muted">${esc(err)}</p></div>`;
    return;
  }
  reposById = new Map(catalog.repos.map((r) => [r.id, r]));
  assetsById = new Map(catalog.assets.map((a) => [a.id, a]));
  repoIdx = repoIndex(catalog.repos);
  assetIdx = assetIndex(catalog.assets);
  render();
}

async function fetchJson(url: string) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.json();
}

// ------------------------------------------------------------------------------------ render

function render(): void {
  if (!catalog) return;
  const state = readState();
  document.querySelectorAll<HTMLAnchorElement>(".tabs a").forEach((a) => {
    const active = a.dataset.tab === state.tab;
    a.classList.toggle("active", active);
    a.setAttribute("aria-current", active ? "page" : "false");
    a.href = `#/${a.dataset.tab}`;
  });
  if (state.tab === "insights") renderInsights();
  else renderSearch(state);
  renderDrawer(state);
}

function renderSearch(state: State): void {
  const isRepos = state.tab === "repos";
  const q = parseQuery(state.q);
  const results: (Repo | Asset)[] = isRepos
    ? runSearch(catalog.repos, repoIdx, q, REPO_FILTERS, (a, b) => (b.pushed_at ?? "").localeCompare(a.pushed_at ?? ""))
    : runSearch(catalog.assets, assetIdx, q, ASSET_FILTERS, (a, b) => b.quality_score - a.quality_score || a.name.localeCompare(b.name));

  const existing = document.getElementById("q") as HTMLInputElement | null;
  const keepFocus = existing && document.activeElement === existing;
  const caret = existing?.selectionStart ?? null;

  const examples = isRepos
    ? ["payments", "lang:python tech:fastapi", "type:service missing:tests", "cap:pdf", "ai:yes uses:anthropic"]
    : ["kind:skill", "code review", "kind:mcp-server", "eco:cursor", "kind:prompt minq:60", "dup:yes"];
  const help = Object.entries(isRepos ? REPO_FILTERS : ASSET_FILTERS)
    .map(([k, d]) => `<li><code>${k}:</code> ${esc(d.help)}</li>`).join("")
    + (isRepos ? "<li><code>minscore:</code> minimum practices score</li>" : "<li><code>minq:</code> minimum quality score</li>")
    + "<li>Prefix with <code>-</code> to exclude. Repeat a key to OR values.</li>";

  $main.innerHTML = `
    <section class="search">
      <label class="sr-only" for="q">Search ${isRepos ? "repositories" : "AI assets"}</label>
      <div class="search-box">
        <svg aria-hidden="true" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>
        <input id="q" type="search" autocomplete="off" spellcheck="false" value="${esc(state.q)}"
          placeholder="${isRepos ? "Search repos: what they do, stack, capabilities…" : "Search skills, agents, prompts, rules, MCP servers…"}" />
        <kbd>/</kbd>
      </div>
      <div class="search-meta">
        <span><strong>${fmtNum(results.length)}</strong> of ${fmtNum(isRepos ? catalog.repos.length : catalog.assets.length)} ${isRepos ? "repositories" : "AI assets"}</span>
        <span class="examples">Try ${examples.map((e) => `<a href="${esc(href({ q: e, open: null }))}">${esc(e)}</a>`).join(" ")}</span>
        <details class="help"><summary>Query syntax</summary><ul>${help}</ul></details>
        <button type="button" class="btn-link" id="csv">Export CSV</button>
      </div>
    </section>
    <div class="layout">
      <aside class="facets" aria-label="Filters">${isRepos ? repoFacets(results as Repo[], state.q) : assetFacets(results as Asset[], state.q)}</aside>
      <section class="results" aria-live="polite">
        ${results.length ? results.slice(0, shown).map((r) => (isRepos ? repoCard(r as Repo) : assetCard(r as Asset))).join("")
          : `<div class="empty"><h2>No matches</h2><p>Remove a filter or try broader words.</p></div>`}
        ${results.length > shown ? `<button type="button" class="more-btn" id="more">Show ${Math.min(PAGE, results.length - shown)} more</button>` : ""}
      </section>
    </div>`;

  const input = document.getElementById("q") as HTMLInputElement;
  if (keepFocus) {
    input.focus();
    if (caret !== null) input.setSelectionRange(caret, caret);
  }
  let timer: number | undefined;
  input.addEventListener("input", () => {
    clearTimeout(timer);
    timer = window.setTimeout(() => { shown = PAGE; navigate({ q: input.value, open: null }, true); }, 140);
  });
  document.getElementById("more")?.addEventListener("click", () => { shown += PAGE; render(); });
  document.querySelector(".facets")?.addEventListener("click", (e) => {
    const btn = (e.target as HTMLElement).closest<HTMLButtonElement>("[data-more]");
    if (!btn) return;
    const group = btn.closest(".facet-group")!;
    btn.textContent = group.classList.toggle("expanded") ? "Less" : "More";
  });
  document.getElementById("csv")?.addEventListener("click", () =>
    isRepos ? downloadCsv("repos.csv", (results as Repo[]).map(repoRow)) : downloadCsv("ai-assets.csv", (results as Asset[]).map(assetRow)),
  );
}

// --------------------------------------------------------------------------------- facets

function facetGroup(title: string, key: string, entries: [string, number][], q: string, limit = 8, label = (v: string) => v): string {
  if (!entries.length) return "";
  const items = entries.slice(0, 40).map(([value, n], i) => {
    const on = hasFilter(q, key, value);
    return `<li${i >= limit && !on ? ' class="extra"' : ""}><a class="facet${on ? " on" : ""}" aria-pressed="${on}"
      href="${esc(href({ q: toggleFilter(q, key, value), open: null }))}"><span>${esc(label(value))}</span><span class="n">${n}</span></a></li>`;
  }).join("");
  // "More" also serves the compact mobile layout, which shows 4 per group
  const more = entries.length > 4 ? `<button type="button" class="btn-link facet-more" data-more>More</button>` : "";
  return `<div class="facet-group${entries.length <= limit ? " few" : ""}"><h3>${esc(title)}</h3><ul>${items}</ul>${more}</div>`;
}

function repoFacets(rs: Repo[], q: string): string {
  return [
    facetGroup("Type", "type", countBy(rs, (r) => r.structure.repo_type), q),
    facetGroup("Language", "lang", countBy(rs, (r) => r.stack.primary_language), q),
    facetGroup("Framework", "tech", countBy(rs, (r) => r.stack.frameworks), q),
    facetGroup("Capability", "cap", countBy(rs, (r) => r.capabilities), q),
    facetGroup("Data & messaging", "tech", countBy(rs, (r) => [...r.stack.databases, ...r.stack.messaging]), q),
    facetGroup("Cloud & infra", "tech", countBy(rs, (r) => [...r.stack.cloud, ...r.stack.infrastructure]), q),
    facetGroup("Uses AI", "ai", countBy(rs, (r) => (r.ai.has_ai ? "yes" : "no")), q, 8, (v) => (v === "yes" ? "Yes" : "No")),
    facetGroup("Practices grade", "grade", countBy(rs, (r) => r.practices.grade).sort((a, b) => a[0].localeCompare(b[0])), q),
    facetGroup("Missing practice", "missing", countBy(rs, (r) => r.practices.checks.filter((c) => !c.passed).map((c) => c.id)), q),
    facetGroup("Lifecycle", "lifecycle", countBy(rs, (r) => r.lifecycle), q),
    facetGroup("Topic", "topic", countBy(rs, (r) => r.topics), q),
  ].join("");
}

function assetFacets(as: Asset[], q: string): string {
  return [
    facetGroup("Kind", "kind", countBy(as, (a) => a.kind), q, 12, (v) => KIND_LABEL[v] ?? v),
    facetGroup("Ecosystem", "eco", countBy(as, (a) => a.ecosystem), q),
    facetGroup("Repository", "repo", countBy(as, (a) => a.repo), q, 8, (v) => v.split("/")[1] ?? v),
    facetGroup("Category", "tag", countBy(as, (a) => a.category), q),
    facetGroup("Tools", "tool", countBy(as, (a) => a.tools), q),
    facetGroup("Models", "model", countBy(as, (a) => a.models), q),
    facetGroup("Confidence", "conf", countBy(as, (a) => a.confidence), q),
    facetGroup("Copied elsewhere", "dup", countBy(as, (a) => (a.duplicates.length ? "yes" : "no")), q, 8, (v) => (v === "yes" ? "Yes" : "No")),
  ].join("");
}

// ---------------------------------------------------------------------------------- cards

function grade(g: string, score: number): string {
  return `<span class="grade grade-${g}" title="Best-practices score ${score}/100">${g}<span class="sr-only"> grade, ${score} of 100</span></span>`;
}

function repoCard(r: Repo): string {
  const s = r.stack;
  const blurb = r.summary.purpose ?? r.summary.one_liner ?? r.summary.readme_excerpt ?? "No description.";
  return `<article class="card">
    <a class="card-link" href="${esc(href({ open: r.id }))}" aria-label="Open ${esc(r.id)}"></a>
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
      ${r.ai.has_ai ? `<span class="chip ai">AI · ${r.ai.asset_count}</span>` : ""}
    </div>
    <footer class="muted">${r.capabilities.slice(0, 5).map(esc).join(" · ")}<span class="spacer"></span>updated ${relTime(r.ownership.last_commit ?? r.pushed_at)}</footer>
  </article>`;
}

function assetCard(a: Asset): string {
  const blurb = a.summary ?? a.description ?? a.excerpt ?? "";
  return `<article class="card">
    <a class="card-link" href="${esc(href({ open: a.id }))}" aria-label="Open ${esc(a.name)}"></a>
    <header>
      <div class="card-title"><span class="kind kind-${esc(a.kind)}">${esc(KIND_LABEL[a.kind] ?? a.kind)}</span><h2>${esc(a.name)}</h2></div>
      <span class="quality" title="Quality heuristic ${a.quality_score}/100">${a.quality_score}</span>
    </header>
    <p class="blurb">${esc(blurb)}</p>
    <div class="chips"><span class="chip eco">${esc(a.ecosystem)}</span>${chips([...a.tools, ...a.models].slice(0, 5))}
      ${a.duplicates.length ? `<span class="chip">${a.duplicates.length} cop${a.duplicates.length > 1 ? "ies" : "y"}</span>` : ""}
      ${a.confidence !== "high" ? `<span class="chip muted-chip">${esc(a.confidence)} confidence</span>` : ""}</div>
    <footer class="muted"><span class="path">${esc(a.repo)} · ${esc(a.path)}</span><span class="spacer"></span>${a.last_modified ? `edited ${relTime(a.last_modified)}` : ""}</footer>
  </article>`;
}

// --------------------------------------------------------------------------------- drawer

function renderDrawer(state: State): void {
  const repo = state.open ? reposById.get(state.open) : undefined;
  const asset = state.open ? assetsById.get(state.open) : undefined;
  const open = !!(repo || asset);
  $drawer.classList.toggle("open", open);
  $drawer.setAttribute("aria-hidden", String(!open));
  $scrim.hidden = !open;
  document.body.classList.toggle("drawer-open", open);
  if (!open) { $drawer.innerHTML = ""; return; }
  $drawer.innerHTML = `<button type="button" class="icon-btn close" aria-label="Close details">✕</button>${repo ? repoDetail(repo) : assetDetail(asset!)}`;
  $drawer.querySelector(".close")!.addEventListener("click", closeDrawer);
  $drawer.querySelector<HTMLButtonElement>("[data-copy]")?.addEventListener("click", async (e) => {
    await navigator.clipboard.writeText(asset?.content ?? "");
    (e.target as HTMLButtonElement).textContent = "Copied";
  });
  $drawer.focus();
}

function closeDrawer(): void { navigate({ open: null }); }

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

function repoDetail(r: Repo): string {
  const s = r.stack;
  const assets = catalog.assets.filter((a) => a.repo === r.id);
  const failing = r.practices.checks.filter((c) => !c.passed);
  const deps = r.dependencies.filter((d) => d.scope !== "dev");
  const devDeps = r.dependencies.filter((d) => d.scope === "dev");
  return `<header class="d-head">
      <p class="eyebrow">${esc(r.structure.repo_type)} · ${esc(r.lifecycle)}${r.declared.system ? ` · system ${esc(r.declared.system)}` : ""}</p>
      <h2>${esc(r.id)}</h2>
      <p class="lead">${esc(r.summary.one_liner ?? r.description ?? "")}</p>
      <div class="actions"><a class="btn" href="${esc(r.url)}" target="_blank" rel="noopener">Open on GitHub</a>
        ${r.homepage ? `<a class="btn secondary" href="${esc(r.homepage)}" target="_blank" rel="noopener">Homepage</a>` : ""}
        ${r.declared.links.map((l) => `<a class="btn secondary" href="${esc(l.url)}" target="_blank" rel="noopener">${esc(l.title || "Link")}</a>`).join("")}</div>
    </header>
    ${section("What it does", `${r.summary.purpose ? `<p>${esc(r.summary.purpose)}</p>` : ""}
      ${r.summary.readme_excerpt && r.summary.readme_excerpt !== r.summary.purpose ? `<p class="muted">${esc(r.summary.readme_excerpt)}</p>` : ""}
      ${r.summary.key_features.length ? `<ul>${r.summary.key_features.map((f) => `<li>${esc(f)}</li>`).join("")}</ul>` : ""}
      ${r.summary.reuse_notes ? `<p class="callout"><strong>Reuse:</strong> ${esc(r.summary.reuse_notes)}</p>` : ""}
      ${r.summary.source === "llm" ? '<p class="muted small">Summary generated by Claude from the README and code facts.</p>' : ""}`)}
    ${section("Capabilities", `<div class="chips">${tagLinks([...r.capabilities, ...r.summary.domains], "cap")}</div>`)}
    ${section("Stack", `<dl class="kv">
      <dt>Languages</dt><dd>${s.languages.slice(0, 6).map((l) => `${esc(l.name)} <span class="muted">${l.percent}%</span>`).join(", ") || "—"}</dd>
      ${Object.keys(s.runtimes).length ? `<dt>Runtimes</dt><dd>${Object.entries(s.runtimes).map(([k, v]) => `${esc(k)} ${esc(v)}`).join(", ")}</dd>` : ""}
      ${STACK_ROWS.filter(([k]) => (s[k] as string[]).length).map(([k, label]) => `<dt>${label}</dt><dd class="chips">${tagLinks(s[k] as string[], "tech")}</dd>`).join("")}
    </dl>`)}
    ${section(`Best practices · ${r.practices.score}/100`, `<ul class="checks">${r.practices.checks.map((c) =>
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
    ${section(`Dependencies (${r.dependencies.length})`, r.dependencies.length ? `<details><summary>${deps.length} runtime · ${devDeps.length} dev</summary>
      <table class="deps"><thead><tr><th>Name</th><th>Version</th><th>Scope</th><th>Manifest</th></tr></thead><tbody>
      ${r.dependencies.slice(0, 400).map((d) => `<tr><td>${esc(d.name)}</td><td>${esc(d.version ?? "")}</td><td>${esc(d.scope)}</td><td class="muted">${esc(d.manifest)}</td></tr>`).join("")}
      </tbody></table></details>` : "")}
    ${section("Ownership", kv([
      ["Declared owner", esc(r.declared.owner)],
      ["CODEOWNERS", r.ownership.codeowners.map(esc).join(", ")],
      ["Top contributors", r.ownership.top_contributors.slice(0, 6).map((c) => `${esc(c.name)} <span class="muted">(${c.commits})</span>`).join(", ")],
      ["History", r.ownership.commit_count ? `${fmtNum(r.ownership.commit_count)} commits, last ${relTime(r.ownership.last_commit)}` : null],
      ["License", esc(r.license)],
      ["Descriptor", r.declared.source_files.map(esc).join(", ")],
    ]))}
    ${r.scan_errors.length ? section("Scan notes", `<ul class="small muted">${r.scan_errors.map((e) => `<li>${esc(e)}</li>`).join("")}</ul>`) : ""}
    <p class="muted small">Scanned ${relTime(r.scanned_at)}</p>`;
}

function assetDetail(a: Asset): string {
  const isMarkdown = /\.(md|mdc|prompt|prompty)$/i.test(a.path) || ["skill", "agent", "command", "instructions"].includes(a.kind) && !/\.(json|ya?ml|toml|py|ts|js)$/i.test(a.path);
  const body = a.content ?? "";
  const lang = a.path.split(".").pop() ?? "";
  const rendered = isMarkdown ? `<div class="md">${markdown(body.replace(/^---[\s\S]*?\n---\s*\n/, ""))}</div>`
    : `<pre><code class="lang-${esc(lang)}">${esc(body)}</code></pre>`;
  const dupes = a.duplicates.map((id) => assetsById.get(id)).filter((x): x is Asset => !!x);
  const fm = Object.keys(a.frontmatter).length ? `<details><summary>Metadata / frontmatter</summary><pre><code>${esc(JSON.stringify(a.frontmatter, null, 2))}</code></pre></details>` : "";
  return `<header class="d-head">
      <p class="eyebrow"><span class="kind kind-${esc(a.kind)}">${esc(KIND_LABEL[a.kind] ?? a.kind)}</span> ${esc(a.ecosystem)} · ${esc(a.scope)} scope</p>
      <h2>${esc(a.title ?? a.name)}</h2>
      ${a.title ? `<p class="muted">${esc(a.name)}</p>` : ""}
      <p class="lead">${esc(a.summary ?? a.description ?? "")}</p>
      <div class="actions"><a class="btn" href="${esc(a.url)}" target="_blank" rel="noopener">Open on GitHub</a>
        ${body ? '<button type="button" class="btn secondary" data-copy>Copy content</button>' : ""}
        <a class="btn secondary" href="${esc(href({ tab: "repos", open: a.repo, q: "" }))}">View repo</a></div>
    </header>
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
      ["Last edit", a.last_modified ? `${relTime(a.last_modified)} by ${esc(a.last_author)} · ${a.commit_count ?? 0} commit(s)` : null],
      ["Detected by", `${esc(a.detector)} · ${esc(a.confidence)} confidence`],
    ]))}
    ${section(`Quality · ${a.quality_score}/100`, a.quality_notes.length ? `<ul class="checks">${a.quality_notes.map((n) => `<li class="fail"><span aria-hidden="true">!</span> ${esc(n)}</li>`).join("")}</ul>` : "<p class=\"muted\">No issues found by the heuristics.</p>")}
    ${a.files.length ? section(`Bundled files (${a.files.length})`, `<ul class="mini-list">${a.files.map((f) => `<li><code>${esc(f.path)}</code> <span class="muted small">${fmtNum(f.size)} B</span></li>`).join("")}</ul>`) : ""}
    ${dupes.length ? section("Identical copies", `<ul class="mini-list">${dupes.map((d) => `<li><a href="${esc(href({ open: d.id }))}">${esc(d.repo)} · ${esc(d.path)}</a></li>`).join("")}</ul>`) : ""}
    ${section("Content", `${a.content_truncated ? '<p class="muted small">Truncated; open on GitHub for the full file.</p>' : ""}${fm}${body ? rendered : '<p class="muted">No content captured.</p>'}`)}`;
}

// ------------------------------------------------------------------------------- insights

function bars(title: string, entries: [string, number][], link: (v: string) => string, total: number, limit = 10): string {
  const rows = entries.slice(0, limit);
  if (!rows.length) return "";
  const max = rows[0]![1];
  return `<figure class="panel"><figcaption>${esc(title)}</figcaption><ul class="bars">
    ${rows.map(([label, n]) => `<li><a href="${esc(link(label))}" title="${esc(label)}: ${n} (${Math.round((100 * n) / Math.max(total, 1))}%)">
      <span class="bar-label">${esc(label)}</span>
      <span class="bar-track"><span class="bar" style="width:${Math.max(2, (100 * n) / max)}%"></span></span>
      <span class="bar-value">${fmtNum(n)}</span></a></li>`).join("")}
  </ul></figure>`;
}

function renderInsights(): void {
  const rs = catalog.repos;
  const as = catalog.assets;
  const active = rs.filter((r) => !r.archived);
  const pct = (n: number) => `${Math.round((100 * n) / Math.max(active.length, 1))}%`;
  const passing = (id: string) => active.filter((r) => r.practices.checks.some((c) => c.id === id && c.passed)).length;
  const avg = Math.round(active.reduce((s, r) => s + r.practices.score, 0) / Math.max(active.length, 1));
  const repoQ = (q: string) => href({ tab: "repos", q, open: null });
  const assetQ = (q: string) => href({ tab: "assets", q, open: null });
  const quote = (v: string) => (/\s/.test(v) ? `"${v}"` : v);
  const failCounts = countBy(active, (r) => r.practices.checks.filter((c) => !c.passed).map((c) => c.label));
  const labelToId = new Map(active.flatMap((r) => r.practices.checks.map((c) => [c.label, c.id] as const)));

  $main.innerHTML = `
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
        ${bars("Frameworks", countBy(rs, (r) => r.stack.frameworks), (v) => repoQ(`tech:${quote(v)}`), rs.length)}
        ${bars("Repo types", countBy(rs, (r) => r.structure.repo_type), (v) => repoQ(`type:${v}`), rs.length)}
        ${bars("Data stores", countBy(rs, (r) => r.stack.databases), (v) => repoQ(`tech:${quote(v)}`), rs.length)}
        ${bars("Cloud & infrastructure", countBy(rs, (r) => [...r.stack.cloud, ...r.stack.infrastructure]), (v) => repoQ(`tech:${quote(v)}`), rs.length)}
        ${bars("Most common gaps (active repos)", failCounts, (v) => repoQ(`missing:${labelToId.get(v) ?? v} -is:archived`), active.length)}
        ${bars("AI assets by kind", countBy(as, (a) => KIND_LABEL[a.kind] ?? a.kind), (v) => assetQ(`kind:${Object.entries(KIND_LABEL).find(([, l]) => l === v)?.[0] ?? v}`), as.length)}
        ${bars("AI ecosystems", countBy(as, (a) => a.ecosystem), (v) => assetQ(`eco:${v}`), as.length)}
        ${bars("LLM SDKs (repos)", countBy(rs, (r) => r.ai.sdks), (v) => repoQ(`uses:${quote(v)}`), rs.length)}
        ${bars("Models referenced (repos)", countBy(rs, (r) => r.ai.models), (v) => repoQ(`uses:${quote(v)}`), rs.length)}
        ${bars("Capabilities", countBy(rs, (r) => r.capabilities), (v) => repoQ(`cap:${quote(v)}`), rs.length, 14)}
        ${bars("Practices grade", countBy(rs, (r) => r.practices.grade).sort((a, b) => a[0].localeCompare(b[0])), (v) => repoQ(`grade:${v}`), rs.length)}
      </div>
      <p class="muted small">Catalog generated ${relTime(catalog.meta.generated_at)} from ${esc(catalog.meta.source)} · scanner ${esc(catalog.meta.scanner_version)}${catalog.meta.llm_enriched ? " · summaries by Claude" : ""}. Click any bar to see the matching repos or assets.</p>
    </section>`;
}

// ---------------------------------------------------------------------------------- export

function repoRow(r: Repo): Record<string, unknown> {
  return {
    repo: r.id, url: r.url, type: r.structure.repo_type, lifecycle: r.lifecycle,
    language: r.stack.primary_language, frameworks: r.stack.frameworks.join("; "),
    databases: r.stack.databases.join("; "), cloud: r.stack.cloud.join("; "),
    capabilities: r.capabilities.join("; "), practices_score: r.practices.score,
    grade: r.practices.grade, ai_assets: r.ai.asset_count, owner: r.declared.owner ?? r.ownership.codeowners.join("; "),
    last_commit: r.ownership.last_commit ?? r.pushed_at, summary: r.summary.purpose ?? r.summary.one_liner,
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

window.addEventListener("hashchange", () => { shown = PAGE; render(); });
window.addEventListener("popstate", render);
$scrim.addEventListener("click", closeDrawer);
document.addEventListener("keydown", (e) => {
  const typing = e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement;
  if (e.key === "/" && !typing) { e.preventDefault(); document.getElementById("q")?.focus(); }
  if (e.key === "Escape" && readState().open) closeDrawer();
});

const THEME_KEY = "repo-catalog-theme";
function applyTheme(t: string | null): void {
  if (t) document.documentElement.dataset.theme = t;
  else delete document.documentElement.dataset.theme;
}
try { applyTheme(localStorage.getItem(THEME_KEY)); } catch { /* storage unavailable */ }
document.getElementById("theme")!.addEventListener("click", () => {
  const dark = document.documentElement.dataset.theme
    ? document.documentElement.dataset.theme === "dark"
    : matchMedia("(prefers-color-scheme: dark)").matches;
  const next = dark ? "light" : "dark";
  applyTheme(next);
  try { localStorage.setItem(THEME_KEY, next); } catch { /* ignore */ }
});

void load();
