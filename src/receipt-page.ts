// Public proof-of-existence receipt page at /r/:chain_id/:seq.
//
// Default posture is "proof only": the page confirms a receipt exists,
// how many events are in its chain, that it is signed by the recorder,
// and (if anchored) which Base tx committed its Merkle root. It does NOT
// render tool names, actors, intents, arguments, outputs, or exact
// timestamps — those are chain content the operator never asked us to
// publish just because the receipt is linked.
//
// Operators who explicitly want content-public rendering can flip a
// per-chain flag (not yet implemented; add visibility column when first
// customer asks). Proof-only is tier 1 and the virality default.
//
// The point: a receipt URL is shareable (an agent can link one in its
// response to an end user to prove "I did something"), the end user can
// click + verify independently, and nothing content-level leaks.

type ChainMeta = {
  exists: boolean;
  event_count: number;
  issuer: string;
  issuer_key_id: string;
  recorder_public_key: string;
};

type ReceiptMeta = {
  exists: boolean;
  envelope_hash: string | null;
  seq: number;
  coarse_window_utc_date: string | null; // YYYY-MM-DD only (day granularity)
  epoch_id: number | null;
  anchor_tx: string | null;
  anchor_block: number | null;
  merkle_root: string | null;
};

export type ReceiptPageData = {
  chain_id: string;
  seq: number;
  chain: ChainMeta;
  receipt: ReceiptMeta;
};

function esc(s: unknown): string {
  return String(s).replace(/[&<>"']/g, (c) => {
    switch (c) {
      case "&": return "&amp;";
      case "<": return "&lt;";
      case ">": return "&gt;";
      case '"': return "&quot;";
      case "'": return "&#39;";
      default: return c;
    }
  });
}

export function renderReceiptPage(d: ReceiptPageData, baseUrl: string): string {
  const title = `Receipt ${d.chain_id}/${d.seq} — Sheaf`;
  const anchored = d.receipt.anchor_tx !== null;
  const notFoundChain = !d.chain.exists;
  const notFoundReceipt = d.chain.exists && !d.receipt.exists;
  const basescan = d.receipt.anchor_tx
    ? `https://basescan.org/tx/${d.receipt.anchor_tx}`
    : null;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>${esc(title)}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="Cryptographic receipt — exists, is part of a hash-chain, and (when anchored) commits to Base mainnet. Public proof-of-existence; content is not disclosed.">
<meta property="og:title" content="Sheaf receipt ${esc(d.chain_id)}/${esc(d.seq)}">
<meta property="og:description" content="Cryptographic proof-of-existence. Verify in the browser; contents not disclosed.">
<meta name="twitter:card" content="summary">
<style>
:root {
  --fg: #0a0a0a; --bg: #fafafa; --muted: #666; --border: #d4d4d4;
  --accent: #0b5cff; --ok: #00824d; --warn: #c88a00; --fail: #c81e24;
  --anchor: #5b4bff; --mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
}
* { box-sizing: border-box; }
body {
  font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  color: var(--fg); background: var(--bg);
  margin: 0; padding: 32px 20px;
  max-width: 700px; margin-inline: auto;
}
h1 { font-size: 22px; margin: 0 0 4px; font-family: var(--mono); letter-spacing: -0.02em; overflow-wrap: anywhere; }
.subtitle { color: var(--muted); font-size: 13px; margin: 0 0 24px; }
.card {
  background: #fff; border: 1px solid var(--border); border-radius: 10px;
  padding: 18px 20px; margin-bottom: 16px;
}
.card h2 { font-size: 12px; margin: 0 0 14px; letter-spacing: 0.05em; text-transform: uppercase; color: var(--muted); font-weight: 600; }
dl { margin: 0; display: grid; grid-template-columns: 160px 1fr; gap: 10px 14px; font-size: 14px; }
dt { color: var(--muted); }
dd { margin: 0; font-family: var(--mono); font-size: 13px; overflow-wrap: anywhere; }
dd a { color: var(--accent); text-decoration: none; }
dd a:hover { text-decoration: underline; }
.badge {
  display: inline-block; font-size: 11px; font-weight: 600;
  padding: 3px 9px; border-radius: 999px; letter-spacing: 0.03em;
}
.badge-ok { background: #e6f7ef; color: var(--ok); }
.badge-pending { background: #fdf4e3; color: var(--warn); }
.badge-fail { background: #fdeeef; color: var(--fail); }
.badge-privacy { background: #ecebff; color: var(--anchor); font-weight: 500; }
.btn {
  display: inline-block; background: var(--accent); color: #fff;
  text-decoration: none; padding: 10px 18px; border-radius: 6px; border: 0;
  font-size: 14px; font-weight: 500; cursor: pointer; font-family: inherit;
}
.btn:hover { background: #0947d1; }
.btn:disabled { opacity: 0.5; cursor: wait; }
#verify-result { margin-top: 14px; font-size: 14px; }
#verify-result.ok { color: var(--ok); }
#verify-result.fail { color: var(--fail); }
.verify-checks { list-style: none; padding: 0; margin: 10px 0 0; font-size: 13px; }
.verify-checks li { padding: 2px 0; }
.verify-checks .mark { display: inline-block; width: 22px; font-weight: 600; }
.verify-checks .ok { color: var(--ok); }
.verify-checks .fail { color: var(--fail); }
.verify-checks .skip { color: var(--muted); }
footer { margin-top: 40px; color: var(--muted); font-size: 12px; text-align: center; }
footer a { color: var(--muted); }
.privacy-note { color: var(--muted); font-size: 12px; margin-top: 10px; font-style: italic; }
.empty { text-align: center; padding: 48px 20px; color: var(--muted); }
</style>
</head>
<body>

<h1>${esc(d.chain_id)} &nbsp;<span style="color:#aaa">/</span>&nbsp; ${esc(d.seq)}</h1>
<p class="subtitle">
  Sheaf receipt · proof-of-existence
  &nbsp;·&nbsp;
  <span class="badge badge-privacy">content hidden</span>
</p>

${notFoundChain ? `
<div class="card empty">
  <p><strong>This chain does not exist on the Sheaf recorder.</strong></p>
  <p>Either the chain ID is wrong or the receipt was created on a different recorder.</p>
</div>
` : notFoundReceipt ? `
<div class="card empty">
  <p><strong>No receipt at seq ${esc(d.seq)}.</strong></p>
  <p>The chain exists (${esc(d.chain.event_count)} event${d.chain.event_count === 1 ? "" : "s"}) but this sequence number was never written.</p>
</div>
` : `

<div class="card">
  <h2>Proof</h2>
  <dl>
    <dt>Exists</dt>
    <dd><span class="badge badge-ok">yes</span>  &nbsp;envelope hash: ${esc((d.receipt.envelope_hash ?? "").slice(0, 16))}…</dd>
    <dt>In a chain of</dt>
    <dd>${esc(d.chain.event_count)} event${d.chain.event_count === 1 ? "" : "s"}</dd>
    <dt>Window (UTC day)</dt>
    <dd>${esc(d.receipt.coarse_window_utc_date ?? "—")}</dd>
    <dt>Signed by</dt>
    <dd>${esc(d.chain.issuer)} · key ${esc(d.chain.issuer_key_id)}</dd>
    <dt>On-chain anchor</dt>
    <dd>${anchored
      ? `<span class="badge badge-ok">anchored</span> &nbsp;epoch #${esc(d.receipt.epoch_id)} &nbsp;<a href="${esc(basescan ?? "")}" target="_blank" rel="noopener">${esc((d.receipt.anchor_tx ?? "").slice(0, 16))}…</a>${d.receipt.anchor_block ? ` (block ${esc(d.receipt.anchor_block)})` : ""}`
      : `<span class="badge badge-pending">pending</span> &nbsp;next cron epoch (~15 min)`}
    </dd>
  </dl>
  <p class="privacy-note">
    The receipt's intent, tool, arguments, actor, authority, and exact timestamp
    are deliberately not shown on this page. The cryptographic proof of
    existence does not require them.
  </p>
</div>

${anchored ? `
<div class="card">
  <h2>Verify in your browser</h2>
  <p style="font-size:13px; color:var(--muted); margin:0 0 12px">
    Runs <code>@sheafhq/verify</code> against Base mainnet using only this page and a public Base RPC. Nothing contacts the Sheaf recorder for the verification itself.
  </p>
  <button id="verify-btn" class="btn">Verify receipt ${esc(d.chain_id)}/${esc(d.seq)}</button>
  <div id="verify-result"></div>
</div>
` : ""}

<div class="card">
  <h2>What this proves</h2>
  <ul style="margin:0; padding-left:20px; font-size:14px; line-height:1.7">
    <li>A specific recorder issued and signed this receipt.</li>
    <li>It was included in a hash chain of events immutable from this point forward.</li>
    ${anchored ? `<li>The chain's root was committed to Base mainnet by the issuer's authorized anchor address.</li>` : `<li>The chain's root is pending commit to Base mainnet in the next epoch.</li>`}
    <li>Nobody — including the operator who created this chain — can alter this receipt or its position in the chain without the on-chain anchor detecting it.</li>
  </ul>
</div>
`}

<footer>
  <p>
    <a href="${esc(baseUrl)}/c/${esc(d.chain_id)}">chain overview</a> ·
    <a href="${esc(baseUrl)}/verify">drag-drop verifier</a> ·
    <a href="https://github.com/sheafhq/sheaf">sheafhq/sheaf</a>
  </p>
</footer>

${anchored ? `
<script type="module">
import { verify } from "https://esm.sh/@sheafhq/verify@0.1.2";
const base = ${JSON.stringify(baseUrl)};
const chainId = ${JSON.stringify(d.chain_id)};
const seq = ${d.seq};
const anchorer = "0x08A22c6899a8b2eccA4b2B752a89eD498d7b2100";
const recorderKey = ${JSON.stringify(d.chain.recorder_public_key)};
const btn = document.getElementById("verify-btn");
const out = document.getElementById("verify-result");
btn.addEventListener("click", async () => {
  btn.disabled = true; out.className = ""; out.textContent = "Fetching event + proof…";
  try {
    const ev = await (await fetch(base + "/events/" + encodeURIComponent(chainId) + "/" + seq)).json();
    const proof = await (await fetch(base + "/epoch/" + ev.epoch_id + "/proof/" + encodeURIComponent(chainId) + "/" + seq)).json();
    out.textContent = "Checking against Base mainnet…";
    const bundle = {
      envelope: ev.envelope,
      inclusion_proof: {
        leaf: proof.leaf,
        leaf_index: proof.leaf_index,
        merkle_root: proof.merkle_root,
        siblings: proof.siblings,
      },
      anchor_tx_hash: proof.anchor.tx_hash,
    };
    const res = await verify(bundle, {
      base_rpc: "https://mainnet.base.org",
      recorder_public_key_base64: recorderKey,
      expected_anchorer_address: anchorer,
    });
    if (res.valid) {
      out.className = "ok";
      out.innerHTML = "<strong>✓ Verified on-chain.</strong> Block " + res.anchor_block + "." +
        "<ul class='verify-checks'>" +
        Object.entries(res.checks).map(([k,v]) => "<li><span class='mark " + (v===true?"ok":v===false?"fail":"skip") + "'>" + (v===true?"✓":v===false?"✗":"–") + "</span>" + k + "</li>").join("") +
        "</ul>";
    } else {
      out.className = "fail"; out.textContent = "✗ " + (res.reason || "verification failed");
    }
  } catch (err) {
    out.className = "fail"; out.textContent = "Error: " + err.message;
  } finally { btn.disabled = false; }
});
</script>
` : ""}

</body>
</html>`;
}
