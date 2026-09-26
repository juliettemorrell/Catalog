// @vitest-environment jsdom
import { describe, expect, it } from "vitest";
import { csvCell, esc, markdown, num, safeUrl } from "../util";

describe("output safety", () => {
  it("escapes HTML", () => {
    expect(esc(`<img src=x onerror="a">'`)).toBe("&lt;img src=x onerror=&quot;a&quot;&gt;&#39;");
    expect(esc(null)).toBe("");
  });
  it("coerces untrusted numbers", () => {
    expect(num("<b>")).toBe(0);
    expect(num("42")).toBe(42);
  });
  it("only allows http(s)/mailto links", () => {
    expect(safeUrl("javascript:alert(1)")).toBe("#");
    expect(safeUrl(" JAVASCRIPT:alert(1)")).toBe("#");
    expect(safeUrl("data:text/html,x")).toBe("#");
    expect(safeUrl("https://github.com/a")).toBe("https://github.com/a");
  });
  it("neutralises CSV formula injection", () => {
    expect(csvCell("=cmd|' /C calc'!A0")).toBe(`"'=cmd|' /C calc'!A0"`);
    expect(csvCell("@SUM(A1)")).toBe(`"'@SUM(A1)"`);
    expect(csvCell('say "hi"')).toBe(`"say ""hi"""`);
  });
});

describe("markdown sanitisation", () => {
  const html = markdown(`# Title
<div style="position:fixed;inset:0">overlay</div>
<form action="https://evil.example"><input type="password"></form>
<img src="https://tracker.example/x.png" onerror="alert(1)">
<script>alert(1)</script>

[bad](javascript:alert(1)) [good](https://example.com) <a href="data:text/html,x">data</a>`);

  it("keeps structure", () => {
    expect(html).toContain("<h1>Title</h1>");
    expect(html).toContain('href="https://example.com"');
  });
  it("drops scripts, forms, inputs, inline styles, images and unsafe links", () => {
    for (const bad of ["<script", "<form", "<input", "style=", "<img", "onerror", 'href="javascript:', 'href="data:']) {
      expect(html).not.toContain(bad);
    }
  });
  it("opens links safely", () => {
    expect(html).toContain('rel="noopener noreferrer nofollow"');
  });
});
