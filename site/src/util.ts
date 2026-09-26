import DOMPurify from "dompurify";
import { marked } from "marked";

const ESC: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

/** Escape any value for safe interpolation into HTML text or attributes. */
export function esc(value: unknown): string {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ESC[c] ?? c);
}

export function markdown(src: string): string {
  return DOMPurify.sanitize(marked.parse(src, { async: false, gfm: true }) as string);
}

export function relTime(iso: string | null): string {
  if (!iso) return "never";
  const days = Math.round((Date.now() - new Date(iso).getTime()) / 86_400_000);
  if (days < 1) return "today";
  if (days < 30) return `${days}d ago`;
  if (days < 365) return `${Math.round(days / 30)}mo ago`;
  return `${(days / 365).toFixed(1)}y ago`;
}

export function fmtNum(n: number): string {
  return new Intl.NumberFormat("en", { notation: n >= 10_000 ? "compact" : "standard" }).format(n);
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
    for (const v of Array.isArray(k) ? k : k ? [k] : []) counts.set(v, (counts.get(v) ?? 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}

export function downloadCsv(filename: string, rows: Record<string, unknown>[]): void {
  if (!rows.length) return;
  const cols = Object.keys(rows[0]!);
  const cell = (v: unknown) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  const csv = [cols.join(","), ...rows.map((r) => cols.map((c) => cell(r[c])).join(","))].join("\n");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}
