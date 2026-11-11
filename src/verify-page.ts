// Static HTML served at /verify. Drag-drop a .sheaf bundle; verification
// runs client-side via @sheafhq/verify loaded from esm.sh. No server-side
// trust: the browser talks to a public Base RPC directly to confirm the
// anchor tx. We just serve the HTML.
//
// Kept as a template string (not a bundled site) because it has no build
// step, no node_modules in the Worker tree, and the whole artifact is one
// file reviewers can audit in <5 minutes.

export const VERIFY_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sheaf verifier — check a .sheaf bundle in your browser</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="Drop a Sheaf bundle (.sheaf file) to verify its signature, Merkle inclusion proof, and on-chain anchor on Base mainnet — entirely in your browser.">
<meta property="og:title" content="Sheaf verifier">
<meta property="og:description" content="Verify a Sheaf receipt in your browser. No install. No account. No trust in the recorder.">
<meta name="twitter:card" content="summary">
<style>
:root {
  --fg: #0a0a0a;
  --bg: #fafafa;
  --muted: #666;
  --border: #d4d4d4;
  --accent: #0b5cff;
  --ok: #00824d;
  --fail: #c81e24;
  --mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
}
* { box-sizing: border-box; }
body {
  font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  color: var(--fg); background: var(--bg);
  margin: 0; padding: 32px 20px;
  max-width: 720px; margin-inline: auto;
}
h1 { font-size: 24px; margin: 0 0 6px; letter-spacing: -0.01em; }
.subtitle { color: var(--muted); margin: 0 0 24px; }
code, pre { font-family: var(--mono); font-size: 13px; }
#drop {
  border: 2px dashed var(--border); border-radius: 12px;
  padding: 48px 20px; text-align: center; cursor: pointer;
  transition: all 120ms;
  background: #fff;
}
#drop.hover { border-color: var(--accent); background: #f0f6ff; }
#drop p { margin: 0 0 4px; }
#drop .hint { color: var(--muted); font-size: 13px; }
#result { margin-top: 24px; }
.verdict {
  padding: 16px 20px; border-radius: 10px; margin-bottom: 16px;
  font-size: 17px; font-weight: 600;
}
.verdict.ok { background: #e6f7ef; color: var(--ok); border: 1px solid #b7e4cc; }
.verdict.fail { background: #fdeeef; color: var(--fail); border: 1px solid #f5c1c4; }
.verdict .reason {
  display: block; font-weight: 400; font-size: 14px; margin-top: 6px;
  color: inherit; opacity: 0.85;
}
.summary { background: #fff; border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; margin-bottom: 16px; }
.summary dl { margin: 0; display: grid; grid-template-columns: 170px 1fr; gap: 6px 12px; font-size: 14px; }
.summary dt { color: var(--muted); }
.summary dd { margin: 0; font-family: var(--mono); font-size: 13px; overflow-wrap: anywhere; }
.summary a { color: var(--accent); text-decoration: none; }
.summary a:hover { text-decoration: underline; }
.checks { list-style: none; padding: 0; margin: 0; background: #fff; border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
.checks li { display: flex; align-items: center; padding: 10px 16px; border-bottom: 1px solid var(--border); font-size: 14px; }
.checks li:last-child { border-bottom: none; }
.checks .mark { width: 22px; font-weight: 700; flex-shrink: 0; }
.checks .mark.ok { color: var(--ok); }
.checks .mark.fail { color: var(--fail); }
.checks .mark.skip { color: var(--muted); }
.checks .label { flex: 1; }
.checks .label .sub { display: block; color: var(--muted); font-size: 12px; margin-top: 2px; }
footer { margin-top: 48px; color: var(--muted); font-size: 13px; }
footer a { color: var(--muted); }
details { margin-top: 16px; background: #fff; border: 1px solid var(--border); border-radius: 10px; padding: 12px 16px; }
details summary { cursor: pointer; color: var(--muted); font-size: 13px; }
details pre { max-height: 300px; overflow: auto; margin: 10px 0 0; padding: 12px; background: #f5f5f5; border-radius: 6px; }
.btn {
  display: inline-block; background: var(--accent); color: #fff;
  text-decoration: none; padding: 8px 14px; border-radius: 6px;
  font-size: 13px; margin-top: 10px;
}
.hidden { display: none !important; }
</style>
</head>
<body>

<h1>Sheaf verifier</h1>
<p class="subtitle">Drop a <code>.sheaf</code> bundle to verify its signature, Merkle inclusion proof, and on-chain anchor. Runs entirely in your browser.</p>

<div id="drop" tabindex="0" role="button" aria-label="Drop a .sheaf file or click to pick">
  <p><strong>Drop a .sheaf bundle here</strong></p>
  <p class="hint">or click to pick a file. Nothing is uploaded — verification runs client-side.</p>
</div>
<input type="file" id="picker" accept=".sheaf,.json,application/json" hidden>

<div id="result"></div>

<footer>
  <p>
    <a href="https://github.com/sheafhq/sheaf">github.com/sheafhq/sheaf</a> ·
    <a href="https://www.npmjs.com/package/@sheafhq/verify">@sheafhq/verify</a> ·
    <a href="https://www.npmjs.com/package/@sheafhq/mcp-tools">@sheafhq/mcp-tools</a>
  </p>
  <p>Don't have a bundle? Paid endpoint: <code>GET /bundle/&lt;chain&gt;/&lt;seq&gt;</code> ($0.001 USDC on Base via x402).</p>
</footer>

<script type="module">
import { verify } from "https://esm.sh/@sheafhq/verify@0.1.0";

const ANCHORER = "0x08A22c6899a8b2eccA4b2B752a89eD498d7b2100";
const BASE_RPC = "https://mainnet.base.org";

const drop = document.getElementById("drop");
const picker = document.getElementById("picker");
const result = document.getElementById("result");

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}

drop.addEventListener("click", () => picker.click());
drop.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") { e.preventDefault(); picker.click(); }
});
["dragenter","dragover"].forEach(ev =>
  drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("hover"); })
);
["dragleave","drop"].forEach(ev =>
  drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("hover"); })
);
drop.addEventListener("drop", (e) => {
  e.preventDefault();
  const f = e.dataTransfer?.files?.[0];
  if (f) handleFile(f);
});
picker.addEventListener("change", () => {
  const f = picker.files?.[0];
  if (f) handleFile(f);
});

async function handleFile(file) {
  result.innerHTML = '<div class="verdict ok" style="background:#f0f6ff;color:var(--accent);border-color:#cfe0ff">Verifying…</div>';
  let bundle;
  try {
    const text = await file.text();
    bundle = JSON.parse(text);
  } catch (err) {
    result.innerHTML = '<div class="verdict fail">Could not parse file<span class="reason">' + escapeHtml(err.message) + '</span></div>';
    return;
  }
  renderBundle(bundle);
  try {
    const verifyInput = normalize(bundle);
    const recorderKey = bundle.issuer?.public_key_base64;
    if (!recorderKey) {
      result.insertAdjacentHTML("beforeend",
        '<div class="verdict fail">Bundle is missing <code>issuer.public_key_base64</code>; cannot verify signature.</div>');
      return;
    }
    const res = await verify(verifyInput, {
      base_rpc: BASE_RPC,
      recorder_public_key_base64: recorderKey,
      expected_anchorer_address: ANCHORER,
    });
    renderResult(bundle, res);
  } catch (err) {
    result.insertAdjacentHTML("beforeend",
      '<div class="verdict fail">Verification threw an error<span class="reason">' + escapeHtml(err.message) + '</span></div>');
  }
}

function normalize(b) {
  if (b.version === "sheaf-bundle/1" && b.envelope && b.anchor && b.envelope_hash) {
    return {
      envelope: b.envelope,
      inclusion_proof: {
        leaf: b.envelope_hash,
        leaf_index: b.anchor.leaf_index ?? 0,
        merkle_root: b.anchor.merkle_root ?? "",
        siblings: b.anchor.siblings ?? [],
      },
      anchor_tx_hash: b.anchor.tx_hash ?? "",
    };
  }
  if (b.envelope && b.inclusion_proof && b.anchor_tx_hash) return b;
  throw new Error("bundle shape not recognized (expected sheaf-bundle/1 or legacy)");
}

function renderBundle(b) {
  const envelope = b.envelope ?? {};
  const event = envelope.event ?? {};
  const chain = b.chain ?? envelope.chain ?? {};
  const anchor = b.anchor ?? {};
  result.innerHTML = '';
  const html = [
    '<div class="summary"><dl>',
    '<dt>Bundle version</dt><dd>' + escapeHtml(b.version ?? '(legacy)') + '</dd>',
    '<dt>Chain / seq</dt><dd>' + escapeHtml(chain.chain_id ?? '?') + ' / ' + escapeHtml(String(chain.seq ?? '?')) + '</dd>',
    '<dt>Tool / intent</dt><dd>' + escapeHtml(event.tool ?? '?') + '<br><span style="color:var(--muted)">' + escapeHtml(event.intent ?? '') + '</span></dd>',
    '<dt>Actor</dt><dd>' + escapeHtml(event.actor ?? '?') + '</dd>',
    '<dt>Timestamp</dt><dd>' + escapeHtml(event.ts ?? '?') + '</dd>',
    '<dt>Epoch / leaf</dt><dd>#' + escapeHtml(anchor.epoch_id ?? '?') + ', leaf ' + escapeHtml(anchor.leaf_index ?? '?') + '</dd>',
    anchor.tx_hash
      ? '<dt>Anchor tx</dt><dd><a href="https://basescan.org/tx/' + escapeHtml(anchor.tx_hash) + '" target="_blank" rel="noopener">' + escapeHtml(anchor.tx_hash) + '</a></dd>'
      : '',
    '</dl></div>',
  ].join('');
  result.innerHTML = html + '<div class="verdict" style="background:#f0f6ff;color:var(--accent);border-color:#cfe0ff">Verifying on-chain…</div>';
}

const CHECK_LABELS = {
  anchor_on_chain: ["Anchor tx exists on Base", "Fetched the transaction from a public Base RPC"],
  anchor_from_authorized_wallet: ["Anchor tx sent by the issuer", "tx.from and tx.to both equal the published anchorer address"],
  merkle_root_matches_on_chain: ["Merkle root in bundle = root on-chain", "32 bytes after the ARCA magic prefix in tx calldata"],
  inclusion_proof_reproduces_root: ["Inclusion proof reproduces the root", "Hashing leaf + siblings bottom-up reaches the Merkle root"],
  envelope_hash_matches_leaf: ["Envelope hash equals the leaf", "SHA-256 of canonical({v, event, chain}) matches the stated leaf"],
  recorder_signature_verifies: ["Recorder Ed25519 signature verifies", "Signed by the recorder key published in /.well-known/sheaf-public-key"],
  chain_prev_hash_matches: ["Chain prev_hash matches previous envelope", "Only checked when a prior envelope is supplied in the bundle"],
};

function renderResult(bundle, res) {
  const verdict = res.valid
    ? '<div class="verdict ok">Valid Sheaf receipt<span class="reason">All invariants hold. Anchor block: ' + escapeHtml(res.anchor_block ?? '?') + '</span></div>'
    : '<div class="verdict fail">Not valid<span class="reason">' + escapeHtml(res.reason ?? 'one or more checks failed') + '</span></div>';
  const items = Object.entries(res.checks).map(([k, v]) => {
    const [title, sub] = CHECK_LABELS[k] ?? [k, ''];
    const mark = v === true ? '<span class="mark ok">✓</span>' :
                  v === false ? '<span class="mark fail">✗</span>' :
                  '<span class="mark skip">–</span>';
    return '<li>' + mark + '<div class="label">' + escapeHtml(title) + '<span class="sub">' + escapeHtml(sub) + '</span></div></li>';
  }).join('');
  result.querySelector('.verdict')?.remove();
  const html = verdict +
    '<ul class="checks">' + items + '</ul>' +
    '<details><summary>Raw bundle JSON</summary><pre>' + escapeHtml(JSON.stringify(bundle, null, 2)) + '</pre></details>' +
    '<details><summary>Verification response</summary><pre>' + escapeHtml(JSON.stringify(res, null, 2)) + '</pre></details>';
  result.insertAdjacentHTML('beforeend', html);
}
</script>

</body>
</html>`;
