// Browser verifier parity test.
//
// Prefers a Chrome launched separately with:
//   chrome --headless=new --remote-debugging-port=9333 ...
// that Playwright connects to over CDP, then falls back to CHROME_PATH,
// installed Google Chrome, and Playwright's own Chromium.

import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";

import { chromium } from "playwright-core";
import { runCli } from "../dist-cli/cli.js";

const CDP = process.env.CHROME_CDP ?? "http://127.0.0.1:9333";
const BUNDLE = "test/fixtures/dispute-walking/bundle.sheaf";
const HTML = resolve("dispute-verify.html");

let browser;
let context;

test.before(async () => {
  // 1. an already-running Chrome on CHROME_CDP; 2. CHROME_PATH; 3. installed
  // Google Chrome; 4. Playwright's own Chromium (npx playwright install chromium).
  const attempts = [
    () => chromium.connectOverCDP(CDP),
    ...(process.env.CHROME_PATH
      ? [() => chromium.launch({ headless: true, executablePath: process.env.CHROME_PATH })]
      : []),
    () => chromium.launch({ headless: true, channel: "chrome" }),
    () => chromium.launch({ headless: true }),
  ];
  const errors = [];
  for (const attempt of attempts) {
    try {
      browser = await attempt();
      break;
    } catch (err) {
      errors.push(String(err?.message ?? err).split("\n")[0]);
    }
  }
  if (!browser) {
    throw new Error(
      "no browser for the parity test. Install Google Chrome, set CHROME_PATH, " +
        "or run `npx playwright install chromium`.\n  " + errors.join("\n  "),
    );
  }
  context = await browser.newContext();
});

test.after(async () => {
  await context?.close();
  await browser?.close();
});

async function captureCli(args) {
  const original = process.stdout.write;
  let text = "";
  process.stdout.write = (chunk) => {
    text += String(chunk);
    return true;
  };
  try {
    const code = await runCli(args);
    return { code, text };
  } finally {
    process.stdout.write = original;
  }
}

async function dropBundle(page, bundleText) {
  await page.evaluate((text) => {
    const dt = new DataTransfer();
    dt.items.add(new File([text], "bundle.sheaf", { type: "application/json" }));
    const drop = document.getElementById("drop");
    drop.dispatchEvent(
      new DragEvent("drop", {
        bubbles: true,
        cancelable: true,
        dataTransfer: dt,
      }),
    );
  }, bundleText);
  await page.waitForFunction(() => {
    const text = document.getElementById("output")?.textContent ?? "";
    return text && !text.startsWith("No bundle loaded");
  });
  return page.textContent("#output");
}

test("browser output is byte-for-byte identical to the CLI in offline mode", async () => {
  assert.ok(existsSync(BUNDLE), `missing ${BUNDLE}`);
  const bundleText = readFileSync(BUNDLE, "utf8");
  const cli = await captureCli(["dispute", "verify", BUNDLE, "--offline"]);
  assert.equal(cli.code, 3, "offline verify should exit 3 without --allow-unconfirmed-anchor");
  assert.match(cli.text, /^VALID \(integrity only; anchor unconfirmed\)/);

  const page = await context.newPage();
  try {
    await page.goto(pathToFileURL(HTML).href + "?offline=1");
    const browserText = await dropBundle(page, bundleText);
    assert.equal(browserText, cli.text);
  } finally {
    await page.close();
  }
});

// S1-6: the browser build (esbuild bundle + WebCrypto) must downgrade a
// recorder-signed legacy bundle exactly like the CLI. The production page has
// no trust input (pinned trust only), so drive the bundled verifier directly.
const LEGACY = "test/fixtures/s1/legacy-recorder-signed.sheaf";
const LEGACY_TRUST = "test/fixtures/s1/legacy-recorder-signed.trust.json";

test("S1-6 legacy recorder-signed bundle: browser build output == CLI output", async () => {
  // Real CLI in a child process: isolated stdout (the in-process capture can
  // also catch the test reporter's own output).
  const run = spawnSync(
    process.execPath,
    ["dist-cli/cli.js", "dispute", "verify", LEGACY, "--offline", "--allow-unconfirmed-anchor", "--trust", LEGACY_TRUST],
    { encoding: "utf8" },
  );
  const cli = { code: run.status, text: run.stdout };
  assert.equal(cli.code, 0, cli.text + run.stderr);
  assert.match(cli.text, /^VALID \(partial\)/m);
  assert.match(cli.text, /^warning: RECORDER_SIGNED_NOT_PRINCIPAL/m);

  const page = await context.newPage();
  try {
    await page.goto(pathToFileURL(HTML).href + "?offline=1");
    const browserText = await page.evaluate(
      async ({ bundleText, trustText }) => {
        const api = window.SheafDispute;
        const result = await api.verifyDisputeBundle(JSON.parse(bundleText), {
          trust: JSON.parse(trustText),
        });
        return api.formatDisputeVerification(result);
      },
      {
        bundleText: readFileSync(LEGACY, "utf8"),
        trustText: readFileSync(LEGACY_TRUST, "utf8"),
      },
    );
    assert.equal(browserText, cli.text);
  } finally {
    await page.close();
  }
});

test("S1 review: every adversarial variant (incl. strict-Ed25519 and signer pins) is identical in browser and CLI", async () => {
  const { buildVariants, variantFiles, cliArgs } = await import("./s1-variants.mjs");
  const { mkdirSync, rmSync, writeFileSync } = await import("node:fs");
  const { join } = await import("node:path");
  const dir = "test/tmp-s1-browser";
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  const page = await context.newPage();
  try {
    await page.goto(pathToFileURL(HTML).href + "?offline=1");
    for (const v of variantFiles(dir, await buildVariants(), writeFileSync, join)) {
      const run = spawnSync(process.execPath, cliArgs(v), { encoding: "utf8" });
      const browserText = await page.evaluate(
        async ({ bundle, opts }) => {
          const api = window.SheafDispute;
          return api.formatDisputeVerification(await api.verifyDisputeBundle(bundle, opts));
        },
        { bundle: v.bundle, opts: v.opts },
      );
      assert.equal(browserText, run.stdout, v.name);
    }
  } finally {
    await page.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("S1 strict Ed25519 in the browser: keyless signature rejected for every message", async () => {
  const page = await context.newPage();
  try {
    await page.goto(pathToFileURL(HTML).href + "?offline=1");
    // The page exposes only the dispute API; exercise strictness through it
    // via the KEYLESS variant, and confirm the NATIVE browser verify accepts
    // the same signature (which is why the strict profile exists).
    const { buildVariants } = await import("./s1-variants.mjs");
    const keyless = (await buildVariants()).find((v) => v.name.startsWith("KEYLESS: identity public key"));
    const result = await page.evaluate(async ({ bundle, opts }) => {
      const r = await window.SheafDispute.verifyDisputeBundle(bundle, opts);
      const spki = new Uint8Array([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 1, ...new Array(31).fill(0)]);
      const key = await crypto.subtle.importKey("spki", spki, { name: "Ed25519" }, false, ["verify"]);
      const sig = new Uint8Array(64); sig[0] = 1;
      const nativeAccepts = await crypto.subtle.verify("Ed25519", key, sig, new TextEncoder().encode("anything"));
      return { valid: r.valid, code: r.code, nativeAccepts };
    }, { bundle: keyless.bundle, opts: keyless.opts });
    assert.equal(result.valid, false);
    assert.equal(result.code, "EVIDENCE_DOC_SIGNATURE_INVALID");
    assert.equal(typeof result.nativeAccepts, "boolean"); // recorded, not asserted (platform behaviour)
  } finally {
    await page.close();
  }
});

// S2: claims are derived from signed data in the browser build too.
test("S2 claim mismatch and evidence gap: browser output == CLI output", async () => {
  const { mkdirSync, rmSync, writeFileSync } = await import("node:fs");
  const { computeDisputeBundleId } = await import("../packages/verify/dist/index.js");
  const dir = "test/tmp-s2-browser";
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  const variants = [
    ["understated", (b) => { b.subject.claims.amount_minor.value = 1; }, /^code: CLAIM_MISMATCH$/m],
    ["amount-deleted", (b) => { delete b.subject.claims.amount_minor; }, /^code: EVIDENCE_GAP$/m],
  ];
  const page = await context.newPage();
  try {
    for (const [name, mutate, expected] of variants) {
      const bundle = JSON.parse(readFileSync(BUNDLE, "utf8"));
      mutate(bundle);
      bundle.bundle_id = await computeDisputeBundleId(bundle);
      const path = `${dir}/${name}.sheaf`;
      writeFileSync(path, JSON.stringify(bundle, null, 2));
      const run = spawnSync(process.execPath, ["dist-cli/cli.js", "dispute", "verify", path, "--offline"], { encoding: "utf8" });
      assert.match(run.stdout, expected, `${name}: ${run.stdout}${run.stderr}`);
      await page.goto(pathToFileURL(HTML).href + "?offline=1");
      const browserText = await dropBundle(page, JSON.stringify(bundle));
      assert.equal(browserText, run.stdout, name);
    }
  } finally {
    await page.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("S1-6 walking bundle in the browser: unauthenticated, no warnings", async () => {
  const page = await context.newPage();
  try {
    await page.goto(pathToFileURL(HTML).href + "?offline=1");
    const text = await dropBundle(page, readFileSync(BUNDLE, "utf8"));
    assert.match(text, /^authorisation: unauthenticated — /m);
    assert.doesNotMatch(text, /warning:|AUTHENTICATED/);
  } finally {
    await page.close();
  }
});

test("browser online mode only contacts ?rpc= and shows the CORS caveat", async () => {
  assert.ok(existsSync(BUNDLE), `missing ${BUNDLE}`);
  const bundle = JSON.parse(readFileSync(BUNDLE, "utf8"));
  const epochs = new Map(
    (bundle.anchor?.epochs ?? []).map((e) => [String(e.tx_hash).toLowerCase(), e]),
  );
  const page = await context.newPage();
  const hosts = new Set();

  page.on("request", (request) => {
    const url = request.url();
    if (url.startsWith("http://") || url.startsWith("https://")) {
      hosts.add(new URL(url).host);
    }
  });

  await page.route(
    (url) => url.hostname === "rpc.invalid",
    async (route) => {
    const request = route.request();
    if (request.method() === "OPTIONS") {
      await route.fulfill({
        status: 204,
        headers: {
          "access-control-allow-origin": "*",
          "access-control-allow-methods": "POST, OPTIONS",
          "access-control-allow-headers": "content-type",
        },
      });
      return;
    }
    const body = JSON.parse(request.postData() || "{}");
    let result;
    if (body.method === "eth_chainId") {
      result = "0x2105";
    } else {
      const epoch = epochs.get(String(body.params?.[0] ?? "").toLowerCase());
      if (!epoch) {
        await route.fulfill({
          status: 200,
          headers: {
            "content-type": "application/json",
            "access-control-allow-origin": "*",
          },
          body: JSON.stringify({
            jsonrpc: "2.0",
            id: 1,
            error: { message: `unexpected tx hash ${String(body.params?.[0])}` },
          }),
        });
        return;
      }
      result = {
        from: bundle.anchor.anchorer,
        to: bundle.anchor.anchorer,
        input: epoch.calldata,
        blockNumber: "0x" + Number(epoch.block_number).toString(16),
        hash: epoch.tx_hash,
      };
    }
    await route.fulfill({
      status: 200,
      headers: {
        "content-type": "application/json",
        "access-control-allow-origin": "*",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, result }),
    });
  });

  try {
    await page.goto(pathToFileURL(HTML).href + "?rpc=https://rpc.invalid", {
      waitUntil: "domcontentloaded",
    });
    const caveat = await page.textContent("#cors");
    assert.match(caveat, /CORS caveat/);
    const text = await dropBundle(page, readFileSync(BUNDLE, "utf8"));
    assert.match(text, /^VALID \(complete\)/);
    assert.match(text, /anchor_confirmed: true/);
    assert.deepEqual([...hosts], ["rpc.invalid"]);
  } finally {
    await page.close();
  }
});
