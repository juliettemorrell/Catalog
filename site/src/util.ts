import DOMPurify from "dompurify";
import { marked } from "marked";

const ESC: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

/** Escape any value for safe interpolation into HTML text or attributes. */
export function esc(value: unknown): string {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ESC[c] ?? c);
}

/** A finite number for display (catalog JSON is data, never trusted markup). */
export function num(value: unknown): number {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

/** Only http(s)/mailto links are rendered as links; anything else becomes inert. */
export function safeUrl(value: unknown): string {
  const s = String(value ?? "").trim();
  return /^(https?:\/\/|mailto:)/i.test(s) ? s : "#";
}

// Content comes from arbitrary repositories: render structure only. No forms, inline
// styles (which could overlay the page), ids/names (DOM clobbering) or remote images.
const PURIFY: Parameters<typeof DOMPurify.sanitize>[1] = {
  FORBID_TAGS: ["form", "input", "button", "textarea", "select", "option", "style", "iframe",
    "object", "embed", "link", "meta", "base", "img", "picture", "video", "audio", "source", "svg", "math"],
  FORBID_ATTR: ["style", "id", "name", "class", "srcset", "formaction", "background"],
  ALLOW_DATA_ATTR: false,
};

DOMPurify.addHook("afterSanitizeAttributes", (node) => {
  if (node.tagName === "A") {
    const href = node.getAttribute("href") ?? "";
    if (!/^(https?:\/\/|mailto:|#)/i.test(href)) node.removeAttribute("href");
    node.setAttribute("rel", "noopener noreferrer nofollow");
    node.setAttribute("target", "_blank");
  }
});

export function markdown(src: string): string {
  return DOMPurify.sanitize(marked.parse(src, { async: false, gfm: true }) as string, PURIFY) as string;
}

export function relTime(iso: string | null): string {
  if (!iso) return "never";
  const t = new Date(iso).getTime();
  if (!Number.isFinite(t)) return "unknown";
  const days = Math.round((Date.now() - t) / 86_400_000);
  if (days < 1) return "today";
  if (days < 30) return `${days}d ago`;
  if (days < 365) return `${Math.round(days / 30)}mo ago`;
  return `${(days / 365).toFixed(1)}y ago`;
}

export function fmtNum(n: number): string {
  return new Intl.NumberFormat("en", { notation: n >= 10_000 ? "compact" : "standard" }).format(num(n));
}

export function chips(values: string[], cls = "chip", max = 99): string {
  const shown = values.slice(0, max).map((v) => `<span class="${cls}">${esc(v)}</span>`).join("");
  const more = values.length > max ? `<span class="${cls} more">+${values.length - max}</span>` : "";
  return shown + more;
}

export function countBy<T>(items: T[], key: (t: T) => string | string[] | null | undefined): [string, number][] {
  const counts = new Map<string, number>();
  for (const item of items) {
    const k = key(item);
    for (const v of new Set(Array.isArray(k) ? k : k ? [k] : [])) counts.set(v, (counts.get(v) ?? 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}

/** CSV cell safe for spreadsheets: quotes doubled and formula triggers neutralised. */
export function csvCell(value: unknown): string {
  let s = String(value ?? "");
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
}

export function downloadCsv(filename: string, rows: Record<string, unknown>[]): boolean {
  if (!rows.length) return false;
  const cols = Object.keys(rows[0]!);
  const csv = [cols.join(","), ...rows.map((r) => cols.map((c) => csvCell(r[c])).join(","))].join("\r\n");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob(["﻿" + csv], { type: "text/csv;charset=utf-8" }));
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  return true;
}

/** Clipboard write that also works on plain-http intranet hosts (no Clipboard API). */
export async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    /* fall through to the legacy path */
  }
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("readonly", "");
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try {
    ok = document.execCommand("copy");
  } catch {
    ok = false;
  }
  ta.remove();
  return ok;
}
