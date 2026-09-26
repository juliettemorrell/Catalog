import { cpSync, createReadStream, existsSync, mkdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig, type Plugin } from "vite";

// The scanner writes JSON into ../data (override with CATALOG_DATA). In dev we serve
// that folder at /data; on build we copy only the files the site needs into dist/data.
const here = fileURLToPath(new URL(".", import.meta.url));
const dataDir = resolve(process.env.CATALOG_DATA ?? join(here, "..", "data"));
const SITE_FILES = ["catalog.json", "ai-assets.json"]; // nothing else is ever served/copied

function catalogData(): Plugin {
  let outDir = join(here, "dist");
  return {
    name: "catalog-data",
    configResolved(config) {
      outDir = resolve(config.root, config.build.outDir);
    },
    configureServer(server) {
      server.middlewares.use("/data", (req, res, next) => {
        const name = decodeURIComponent((req.url ?? "").split("?")[0] ?? "").replace(/^\/+/, "");
        if (!SITE_FILES.includes(name)) return next(); // allow-list: no traversal, no catalog.db
        const file = join(dataDir, name);
        if (!existsSync(file) || !statSync(file).isFile()) return next();
        res.setHeader("Content-Type", "application/json");
        createReadStream(file).pipe(res);
      });
    },
    closeBundle() {
      mkdirSync(join(outDir, "data"), { recursive: true });
      for (const name of SITE_FILES) {
        const src = join(dataDir, name);
        if (existsSync(src)) cpSync(src, join(outDir, "data", name));
        else this.warn(`${src} missing: run \`repo-catalog scan\` before building the site`);
      }
    },
  };
}

export default defineConfig({
  base: "./",
  plugins: process.env.VITEST ? [] : [catalogData()],
  build: { target: "es2022", sourcemap: true },
});
