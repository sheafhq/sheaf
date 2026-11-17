// C: merchant workflow end-to-end.
// init-case -> fill template -> validate -> export -> verify.

import test from "node:test";
import assert from "node:assert/strict";
import {
  copyFileSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { runCli } from "../dist-cli/cli.js";

const WALK = "test/fixtures/dispute-walking";

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

async function capture(fn) {
  const original = process.stdout.write;
  let text = "";
  process.stdout.write = (chunk) => {
    text += String(chunk);
    return true;
  };
  try {
    const code = await fn();
    return { code, text };
  } finally {
    process.stdout.write = original;
  }
}

function fillTemplate(dir) {
  const manifest = readJson(join(WALK, "case.json"));
  manifest.schema = "sheaf.dispute-bundle/1";
  manifest.manifest_version = "sheaf.dispute-case/1";
  manifest.case.card_network = "visa";
  manifest.case.reason_code = {
    schema: "2026 Visa Claims Resolution guide",
    value: "10.4",
    label: "unit test",
  };
  manifest.evidence.mandate.status = "included";
  manifest.evidence.mandate.document = "documents/mandate.json";
  manifest.evidence.delegation.status = "included";
  manifest.evidence.delegation.chain[0].document = "documents/delegation.json";
  manifest.evidence.consent.status = "included";
  manifest.evidence.consent.document = "documents/consent.json";
  for (const payload of manifest.payloads) {
    payload.path = `payloads/${payload.path.replace(/^payloads\//, "")}`;
  }
  writeFileSync(join(dir, "case.json"), JSON.stringify(manifest, null, 2) + "\n");

  for (const name of ["mandate.json", "delegation.json", "consent.json"]) {
    copyFileSync(join(WALK, name), join(dir, "documents", name));
  }
  for (const name of [
    "3-args.json",
    "3-result.json",
    "4-args.json",
    "4-result.json",
  ]) {
    copyFileSync(join(WALK, "payloads", name), join(dir, "payloads", name));
  }
}

test("merchant workflow: init-case -> fill -> validate -> export -> verify", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sheaf-authoring-"));
  try {
    const init = await capture(() =>
      runCli(["dispute", "init-case", dir]),
    );
    assert.equal(init.code, 0, init.text);
    assert.match(init.text, /INITIALIZED /);
    assert.ok(existsSync(join(dir, "case.json")));
    assert.ok(existsSync(join(dir, "documents")));
    assert.ok(existsSync(join(dir, "payloads")));
    assert.ok(existsSync(join(dir, "MAPPING.md")));

    const template = await capture(() =>
      runCli(["dispute", "validate", "--case", join(dir, "case.json")]),
    );
    assert.equal(template.code, 1);
    assert.match(template.text, /INVALID /);
    assert.match(template.text, /replace the placeholder value/);

    fillTemplate(dir);

    const validate = await capture(() =>
      runCli([
        "dispute",
        "validate",
        "--case",
        join(dir, "case.json"),
        "--archive",
        join(WALK, "events.jsonl"),
      ]),
    );
    assert.equal(validate.code, 0, validate.text);
    assert.match(validate.text, /VALID /);

    const out = join(dir, "bundle.sheaf");
    const exported = await capture(() =>
      runCli([
        "dispute",
        "export",
        "--archive",
        join(WALK, "events.jsonl"),
        "--case",
        join(dir, "case.json"),
        "--out",
        out,
        "--self-check",
        "--offline",
      ]),
    );
    assert.equal(exported.code, 0, exported.text);
    assert.match(exported.text, /WROTE /);
    assert.ok(existsSync(out));

    const verified = await capture(() =>
      runCli([
        "dispute",
        "verify",
        out,
        "--offline",
        "--allow-unconfirmed-anchor",
      ]),
    );
    assert.equal(verified.code, 0, verified.text);
    assert.match(verified.text, /VALID \(integrity only; anchor unconfirmed\)/);
    assert.match(verified.text, /evidence_gaps: none/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("validate catches a document hash mismatch before export", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sheaf-authoring-bad-"));
  try {
    await capture(() => runCli(["dispute", "init-case", dir]));
    fillTemplate(dir);

    const docPath = join(dir, "documents", "mandate.json");
    const doc = readJson(docPath);
    doc.nonce = "mutated-after-recording";
    writeFileSync(docPath, JSON.stringify(doc, null, 2));

    const validate = await capture(() =>
      runCli([
        "dispute",
        "validate",
        "--case",
        join(dir, "case.json"),
        "--archive",
        join(WALK, "events.jsonl"),
      ]),
    );
    assert.equal(validate.code, 1);
    assert.match(validate.text, /EVIDENCE_DOC_HASH_MISMATCH/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("--payload flags can supply payloads without a case.json payload list", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sheaf-authoring-payload-"));
  try {
    await capture(() => runCli(["dispute", "init-case", dir]));
    fillTemplate(dir);
    const manifest = readJson(join(dir, "case.json"));
    manifest.payloads = [];
    writeFileSync(join(dir, "case.json"), JSON.stringify(manifest, null, 2));

    const out = join(dir, "bundle-flags.sheaf");
    const exported = await capture(() =>
      runCli([
        "dispute",
        "export",
        "--archive",
        join(WALK, "events.jsonl"),
        "--case",
        join(dir, "case.json"),
        "--out",
        out,
        "--payload",
        `3:tool_arguments=${join(dir, "payloads", "3-args.json")}`,
        "--payload",
        `3:tool_result=${join(dir, "payloads", "3-result.json")}`,
        "--payload",
        `4:tool_arguments=${join(dir, "payloads", "4-args.json")}`,
        "--payload",
        `4:tool_result=${join(dir, "payloads", "4-result.json")}`,
        "--self-check",
        "--offline",
      ]),
    );
    assert.equal(exported.code, 0, exported.text);
    assert.match(exported.text, /WROTE /);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
