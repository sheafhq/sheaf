// Build the single-file browser verifier. No CDN, no module imports at runtime:
// esbuild inlines @sheafhq/verify's dispute verifier into the HTML.

import { build } from "esbuild";
import { readFileSync, writeFileSync } from "node:fs";

const result = await build({
  entryPoints: ["scripts/dispute-verifier-entry.ts"],
  bundle: true,
  write: false,
  format: "iife",
  platform: "browser",
  target: "es2022",
  minify: true,
  legalComments: "none",
  sourcemap: false,
});

const js = result.outputFiles[0].text.replace(/<\/script/gi, "<\\/script");
const template = readFileSync("scripts/dispute-verify.template.html", "utf8");
if (!template.includes("/*__VERIFIER_JS__*/")) {
  throw new Error("template placeholder missing");
}
// Replacer FUNCTION, not a string: a string replacement expands `$&`, `` $` ``
// and `$'` patterns that minified JS can contain, which splices template text
// into the script (seen 2026-11-17). Same as inline-dispute-verifier.mjs.
const html = template.replace("/*__VERIFIER_JS__*/", () => js);
writeFileSync("dispute-verify.html", html);
console.log(`wrote dispute-verify.html (${html.length} bytes)`);
