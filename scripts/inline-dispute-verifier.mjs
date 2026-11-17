// Inline the esbuild output into the single-file verifier template.
// No child processes are spawned here; the esbuild step is separate.

import { readFileSync, writeFileSync } from "node:fs";

const js = readFileSync(".test-dist/dispute-verifier.js", "utf8").replace(
  /<\/script/gi,
  "<\\/script",
);
const template = readFileSync("scripts/dispute-verify.template.html", "utf8");
if (!template.includes("/*__VERIFIER_JS__*/")) {
  throw new Error("template placeholder missing");
}
// Use a replacer function: esbuild output contains `$` sequences (regexes and
// template literals) that String.replace would interpret as substitution
// patterns, corrupting the inlined verifier.
const html = template.replace("/*__VERIFIER_JS__*/", () => js);
writeFileSync("dispute-verify.html", html);
console.log(`wrote dispute-verify.html (${html.length} bytes)`);
