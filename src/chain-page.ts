// Public verification page for one chain. Server-renders the chain's
// current state and seeds a browser-side verifier so anyone can prove the
// latest anchored event without paying or signing up.
//
// This is Sheaf's distribution primitive — the page a badge links to.
// It must be fast, correct, and useful to someone who has never heard of
// Sheaf (per the self-serve brief, rev 2).

type ChainSummary = {
  chain_id: string;
  head_seq: number | null;
  head_hash: string | null;
  event_count: number;
  created_at: number | null;
  updated_at: number | null;
  account_id: string;
  anchor_count: number;
  latest_anchor: {
    epoch_id: number;
    merkle_root: string;
    anchor_tx_hash: string | null;
    anchor_block: number | null;
    sealed_at: number;
  } | null;
  recent_events: Array<{
    seq: number;
    tool: string;
    result: string;
    ts: number;
    epoch_id: number | null;
  }>;
};

function escapeHtml(s: unknown): string {
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

function fmtTime(unix: number | null): string {
  if (!unix) return "—";
  return new Date(unix * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC";
}

function fmtRelative(unix: number | null, nowSec: number): string {
  if (!unix) return "—";
  const d = nowSec - unix;
  if (d < 60) return `${d}s ago`;
  if (d < 3600) return `${Math.floor(d / 60)}m ago`;
  if (d < 86400) return `${Math.floor(d / 3600)}h ago`;
  return `${Math.floor(d / 86400)}d ago`;
}

export function renderChainPage(s: ChainSummary, baseUrl: string): string {
  const notFound = s.head_seq === null;
  const nowSec = Math.floor(Date.now() / 1000);
  const anchorTxUrl = s.latest_anchor?.anchor_tx_hash
    ? `https://basescan.org/tx/${s.latest_anchor.anchor_tx_hash}`
    : null;
  const title = `${s.chain_id} — Sheaf`;
  const ogDesc = notFound
    ? "No events recorded on this chain."
    : `${s.event_count} events, ${s.anchor_count} on-chain anchors.`;

  const recentRows = s.recent_events
    .map((e) => {
      const anchored = e.epoch_id !== null;
      return `<tr>
        <td class="mono">${e.seq}</td>
        <td class="mono">${escapeHtml(e.tool).slice(0, 48)}</td>
        <td><span class="pill pill-${e.result === "ok" ? "ok" : "warn"}">${escapeHtml(e.result)}</span></td>
        <td class="mono dim">${fmtRelative(e.ts, nowSec)}</td>
        <td>${anchored ? `<span class="pill pill-anchor">#${e.epoch_id}</span>` : `<span class="pill pill-pending">pending</span>`}</td>
      </tr>`;
    })
    .join("\n");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>${escapeHtml(title)}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="${escapeHtml(ogDesc)}">
<meta property="og:title" content="${escapeHtml(s.chain_id)} on Sheaf">
<meta property="og:description" content="${escapeHtml(ogDesc)}">
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
  max-width: 820px; margin-inline: auto;
}
h1 {
  font-size: 22px; margin: 0 0 4px; font-family: var(--mono);
  letter-spacing: -0.02em; overflow-wrap: anywhere;
}
.subtitle { color: var(--muted); font-size: 13px; margin: 0 0 24px; }
.card {
  background: #fff; border: 1px solid var(--border); border-radius: 10px;
  padding: 16px 18px; margin-bottom: 16px;
}
.card h2 { font-size: 14px; margin: 0 0 12px; letter-spacing: 0.04em; text-transform: uppercase; color: var(--muted); font-weight: 600; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; }
.stat { background: #f5f5f5; border-radius: 8px; padding: 10px 12px; }
.stat .label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; margin: 0 0 2px; }
.stat .value { font-size: 20px; font-weight: 600; font-family: var(--mono); }
.stat .sub { font-size: 12px; color: var(--muted); margin-top: 2px; }
dl { margin: 0; display: grid; grid-template-columns: 180px 1fr; gap: 8px 14px; font-size: 14px; }
dt { color: var(--muted); }
dd { margin: 0; font-family: var(--mono); overflow-wrap: anywhere; font-size: 13px; }
dd a { color: var(--accent); text-decoration: none; }
dd a:hover { text-decoration: underline; }
.mono { font-family: var(--mono); font-size: 13px; }
.dim { color: var(--muted); }
table { width: 100%; border-collapse: collapse; margin-top: 4px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); font-size: 13px; }
th { font-size: 11px; text-transform: uppercase; color: var(--muted); font-weight: 600; letter-spacing: 0.04em; }
.pill { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 11px; font-family: var(--mono); font-weight: 500; }
.pill-ok { background: #e6f7ef; color: var(--ok); }
.pill-warn { background: #fdf4e3; color: var(--warn); }
.pill-anchor { background: #ecebff; color: var(--anchor); }
.pill-pending { background: #f5f5f5; color: var(--muted); }
.btn {
  display: inline-block; background: var(--accent); color: #fff;
  text-decoration: none; padding: 9px 16px; border-radius: 6px; border: 0;
  font-size: 14px; font-weight: 500; cursor: pointer; font-family: inherit;
}
.btn:hover { background: #0947d1; }
.btn:disabled { opacity: 0.5; cursor: wait; }
#verify-result { margin-top: 14px; font-size: 14px; }
#verify-result.ok { color: var(--ok); }
#verify-result.fail { color: var(--fail); }
.verify-checks { list-style: none; padding: 0; margin: 8px 0 0; font-size: 13px; }
.verify-checks li { padding: 2px 0; }
.verify-checks .mark { display: inline-block; width: 20px; font-weight: 600; }
.verify-checks .ok { color: var(--ok); }
.verify-checks .fail { color: var(--fail); }
.verify-checks .skip { color: var(--muted); }
.badge-code {
  background: #f5f5f5; border-radius: 6px; padding: 10px 12px;
  font-family: var(--mono); font-size: 12px; overflow-x: auto; user-select: all;
}
.empty { text-align: center; padding: 48px 20px; color: var(--muted); }
footer { margin-top: 48px; color: var(--muted); font-size: 13px; text-align: center; }
footer a { color: var(--muted); }
</style>
</head>
<body>

<h1>${escapeHtml(s.chain_id)}</h1>
<p class="subtitle">Sheaf chain · anchored on <a href="https://basescan.org/" target="_blank" rel="noopener">Base mainnet</a></p>

${
  notFound
    ? `<div class="card empty">
         <p><strong>No events recorded on this chain yet.</strong></p>
         <p>Chain IDs are user-chosen. If this is yours, start recording with <code>@sheafhq/mcp-recorder</code>.</p>
         <p><a href="https://github.com/sheafhq/sheaf" class="btn" style="margin-top:12px">Get started</a></p>
       </div>`
    : `
<div class="card">
  <h2>Status</h2>
  <div class="stats">
    <div class="stat">
      <p class="label">Events</p>
      <p class="value">${s.event_count}</p>
      <p class="sub">${fmtRelative(s.updated_at, nowSec)} · latest seq ${s.head_seq}</p>
    </div>
    <div class="stat">
      <p class="label">On-chain anchors</p>
      <p class="value">${s.anchor_count}</p>
      <p class="sub">${s.latest_anchor ? `latest #${s.latest_anchor.epoch_id} · ${fmtRelative(s.latest_anchor.sealed_at, nowSec)}` : "none yet"}</p>
    </div>
    <div class="stat">
      <p class="label">Account</p>
      <p class="value" style="font-size:13px; overflow-wrap:anywhere">${escapeHtml(s.account_id)}</p>
      <p class="sub">${s.account_id === "legacy-public" ? "public legacy chain" : "owned"}</p>
    </div>
  </div>
</div>

<div class="card">
  <h2>Latest anchor</h2>
  ${
    s.latest_anchor && anchorTxUrl
      ? `<dl>
           <dt>Epoch</dt><dd>#${s.latest_anchor.epoch_id}</dd>
           <dt>Merkle root</dt><dd>${escapeHtml(s.latest_anchor.merkle_root)}</dd>
           <dt>Base tx</dt><dd><a href="${escapeHtml(anchorTxUrl)}" target="_blank" rel="noopener">${escapeHtml(s.latest_anchor.anchor_tx_hash)}</a></dd>
           <dt>Base block</dt><dd>${s.latest_anchor.anchor_block ?? "—"}</dd>
           <dt>Sealed at</dt><dd>${fmtTime(s.latest_anchor.sealed_at)}</dd>
         </dl>
         <button id="verify-btn" class="btn" style="margin-top:14px">Verify latest anchored event in your browser</button>
         <div id="verify-result"></div>`
      : `<p class="dim">No anchor yet. Chains are anchored by the recorder cron every 15 minutes; if events exist but no anchor is shown, the next epoch will include them.</p>`
  }
</div>

${
  s.recent_events.length
    ? `<div class="card">
         <h2>Recent events</h2>
         <table>
           <thead><tr><th>seq</th><th>tool</th><th>result</th><th>when</th><th>anchor</th></tr></thead>
           <tbody>${recentRows}</tbody>
         </table>
       </div>`
    : ""
}

<div class="card">
  <h2>Badge markdown</h2>
  <div class="badge-code">[![Sheaf](${baseUrl}/badge/${encodeURIComponent(s.chain_id)}.svg)](${baseUrl}/c/${encodeURIComponent(s.chain_id)})</div>
  <p class="dim" style="font-size:12px;margin-top:8px">Paste into your README to show the chain is anchoring tool calls.</p>
</div>
`
}

<footer>
  <p>
    <a href="https://github.com/sheafhq/sheaf">github.com/sheafhq/sheaf</a> ·
    <a href="${baseUrl}/verify">drag-drop verifier</a> ·
    <a href="${baseUrl}/">API docs</a>
  </p>
  <p>Don't have a chain? <a href="https://www.npmjs.com/package/@sheafhq/mcp-recorder">npm i -g @sheafhq/mcp-recorder</a> → records every tool call your agent makes.</p>
</footer>

${
  s.latest_anchor && anchorTxUrl && s.head_seq !== null
    ? `<script type="module">
import { verify } from "https://esm.sh/@sheafhq/verify@0.1.2";
const base = ${JSON.stringify(baseUrl)};
const chainId = ${JSON.stringify(s.chain_id)};
const headSeq = ${s.head_seq};
const anchorer = "0x08A22c6899a8b2eccA4b2B752a89eD498d7b2100";
const btn = document.getElementById("verify-btn");
const out = document.getElementById("verify-result");
btn.addEventListener("click", async () => {
  btn.disabled = true;
  out.className = "";
  out.textContent = "Fetching proof…";
  try {
    // Walk back from head until we find an anchored seq.
    let targetSeq = headSeq;
    let ev, proof;
    while (targetSeq >= 0) {
      const er = await fetch(base + "/events/" + encodeURIComponent(chainId) + "/" + targetSeq);
      if (!er.ok) throw new Error("event " + targetSeq + " fetch " + er.status);
      ev = await er.json();
      if (ev.epoch_id !== null && ev.epoch_id !== undefined) {
        const pr = await fetch(base + "/epoch/" + ev.epoch_id + "/proof/" + encodeURIComponent(chainId) + "/" + targetSeq);
        if (!pr.ok) throw new Error("proof fetch " + pr.status);
        proof = await pr.json();
        break;
      }
      targetSeq--;
    }
    if (!ev || !proof) throw new Error("no anchored event found on this chain");
    const kr = await fetch(base + "/.well-known/sheaf-public-key");
    const pk = await kr.json();
    const active = pk.keys.find((k) => k.key_id === pk.active_key_id);
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
    out.textContent = "Verifying against Base mainnet…";
    const res = await verify(bundle, {
      base_rpc: "https://mainnet.base.org",
      recorder_public_key_base64: active.public_key_base64,
      expected_anchorer_address: anchorer,
    });
    if (res.valid) {
      out.className = "ok";
      out.innerHTML = "<strong>✓ Verified seq " + targetSeq + " on-chain.</strong> All seven invariants hold against Base block " + res.anchor_block + ".<ul class='verify-checks'>" +
        Object.entries(res.checks).map(([k,v]) => "<li><span class='mark " + (v===true?"ok":v===false?"fail":"skip") + "'>" + (v===true?"✓":v===false?"✗":"–") + "</span>" + k + "</li>").join("") +
        "</ul>";
    } else {
      out.className = "fail";
      out.textContent = "✗ Verification failed: " + (res.reason || "unknown");
    }
  } catch (err) {
    out.className = "fail";
    out.textContent = "Error: " + err.message;
  } finally {
    btn.disabled = false;
  }
});
</script>`
    : ""
}

</body>
</html>`;
}

export type { ChainSummary };
