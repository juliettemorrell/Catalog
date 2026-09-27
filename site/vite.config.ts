import { cpSync, createReadStream, existsSync, mkdirSync, statSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig, type Plugin } from "vite";

// The scanner writes JSON into ../data (override with CATALOG_DATA). In dev we serve
// that folder at /data; on build we copy only the files the site needs into dist/data.
const here = fileURLToPath(new URL(".", import.meta.url));
const dataDir = resolve(process.env.CATALOG_DATA ?? join(here, "..", "data"));
const SITE_FILES = ["catalog.json", "ai-assets.json"];
// Detail files loaded on demand (store.py write_site_details). With the two files above,
// nothing else in the data folder is ever served or copied (no catalog.db, no raw records).
const SITE_DIR = "site";
const DETAIL = /^site\/(?:(?:repos|assets)\/[A-Za-z0-9_-][A-Za-z0-9._-]*|insights)\.json$/;

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
        if (!SITE_FILES.includes(name) && !DETAIL.test(name)) return next(); // allow-list: no traversal
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
      const site = join(dataDir, SITE_DIR);
      if (existsSync(site)) {
        cpSync(site, join(outDir, "data", SITE_DIR), {
          recursive: true,
          filter: (src) => statSync(src).isDirectory() || DETAIL.test(relative(dataDir, src).split(sep).join("/")),
        });
      } else this.warn(`${site} missing: rebuild with \`repo-catalog build\` (drawers will show summaries only)`);
    },
  };
}

export default defineConfig({
  base: "./",
  plugins: process.env.VITEST ? [] : [catalogData()],
  // no sourcemaps: they embed the build machine's absolute paths and double the download
  build: { target: "es2022", sourcemap: false },
});
