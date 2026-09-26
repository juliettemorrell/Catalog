import { cpSync, createReadStream, existsSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig, type Plugin } from "vite";

// The scanner writes JSON into ../data (override with CATALOG_DATA). In dev we serve
// that folder at /data; on build we copy only the files the site needs into dist/data.
const here = fileURLToPath(new URL(".", import.meta.url));
const dataDir = resolve(process.env.CATALOG_DATA ?? join(here, "..", "data"));
const SITE_FILES = ["catalog.json", "ai-assets.json"];

function catalogData(): Plugin {
  return {
    name: "catalog-data",
    configureServer(server) {
      server.middlewares.use("/data", (req, res, next) => {
        const file = join(dataDir, (req.url ?? "").split("?")[0] ?? "");
        if (!file.startsWith(dataDir) || !existsSync(file) || !statSync(file).isFile()) {
          return next();
        }
        res.setHeader("Content-Type", "application/json");
        createReadStream(file).pipe(res);
      });
    },
    closeBundle() {
      for (const name of SITE_FILES) {
        const src = join(dataDir, name);
        if (existsSync(src)) cpSync(src, join(here, "dist", "data", name));
        else this.warn(`${src} missing: run \`repo-catalog scan\` before building the site`);
      }
    },
  };
}

export default defineConfig({
  base: "./",
  plugins: [catalogData()],
  build: { target: "es2022", sourcemap: true },
});
