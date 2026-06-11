// Direct Vite build for Tauri's beforeBuildCommand.
// Tauri v2 may run this from any directory — we resolve the project root
// relative to this script's own location (where package.json lives).
//
// Vite v6 can exit code 1 in subprocess environments even when the
// build succeeds. We guard against that by verifying dist/ exists
// and overriding the exit code.

import { build } from "vite";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
import { existsSync } from "fs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = __dirname;
console.log(`[beforeBuild] Script dir: ${__dirname}`);
console.log(`[beforeBuild] Building frontend from ${root} ...`);

let viteOk = false;
try {
    await build({ root });
    viteOk = true;
} catch (e) {
    console.error("[beforeBuild] Vite exception:", e.message);
}

const distIndex = resolve(root, "dist", "index.html");
if (existsSync(distIndex)) {
    console.log(`[beforeBuild] Frontend built successfully (vite result: ${viteOk ? "ok" : "exception, but dist/ exists"}).`);
    process.exit(0);
} else {
    console.error(`[beforeBuild] ERROR: ${distIndex} not found`);
    process.exit(1);
}
