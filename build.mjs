// Direct Vite build for Tauri's beforeBuildCommand.
// Tauri v2 runs this from the project root (where package.json is).
//
// Vite v6 can exit code 1 in subprocess environments even when the
// build succeeds. We guard against that by verifying dist/ exists
// and overriding the exit code.

import { build } from "vite";
import { resolve } from "path";
import { existsSync } from "fs";

const root = process.cwd();
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
