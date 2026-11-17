// Browser verifier parity test.
//
// Chrome is launched separately with:
//   chrome --headless=new --remote-debugging-port=9333 ...
// and Playwright connects over CDP. This avoids relying on Playwright's
// browser download and keeps the test's network boundary explicit.

import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { chromium } from "playwright-core";
import { runCli } from "../dist-cli/cli.js";

const CDP = process.env.CHROME_CDP ?? "http://127.0.0.1:9333";
const BUNDLE = "test/fixtures/dispute-walking/bundle.sheaf";
const HTML = resolve("dispute-verify.html");

let browser;
let context;

test.before(async () => {
  try {
    browser = await chromium.connectOverCDP(CDP);
  } catch {
    browser = await chromium.launch({ headless: true, channel: "chrome" });
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
