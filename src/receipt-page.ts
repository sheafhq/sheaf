// Public receipt page. This is a distribution surface: every shared receipt
// carries the "Verified by Sheaf" footer and a link back to the landing page.

function escapeHtml(value: unknown): string {
  return String(value).replace(/[&<>"']/g, (char) => {
    switch (char) {
      case "&":
        return "&amp;";
      case "<":
        return "&lt;";
      case ">":
        return "&gt;";
      case '"':
        return "&quot;";
      case "'":
        return "&#39;";
      default:
        return char;
    }
  });
}

export type ReceiptPageInput = {
  chain_id: string;
  seq: number;
  tool: string;
  result: string;
  ts: number;
  epoch_id: number | null;
  envelope_hash: string;
  anchor_tx_hash: string | null;
};

export function renderReceiptPage(input: ReceiptPageInput): string {
  const time = new Date(input.ts * 1000).toISOString();
  const anchor = input.anchor_tx_hash
    ? `<a href="https://basescan.org/tx/${escapeHtml(input.anchor_tx_hash)}">${escapeHtml(input.anchor_tx_hash)}</a>`
    : "pending";
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(input.chain_id)} / ${input.seq} — Sheaf receipt</title>
<style>
:root{--bg:#0a0b0d;--panel:#101216;--line:#252830;--text:#ecebe4;--muted:#8d9098;--acid:#c8ff6a;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;--sans:Inter,ui-sans-serif,system-ui,sans-serif}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:linear-gradient(rgba(255,255,255,.025) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.025) 1px,transparent 1px),var(--bg);background-size:48px 48px;color:var(--text);font:16px/1.6 var(--sans)}
main{max-width:780px;margin:0 auto;padding:56px 24px 32px}
.eyebrow{font:11px/1 var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--acid)}
h1{margin:16px 0 8px;font-size:clamp(28px,5vw,44px);line-height:1.05;letter-spacing:-.04em;overflow-wrap:anywhere}
.sub{color:var(--muted);font:12px/1.5 var(--mono);overflow-wrap:anywhere}
.card{margin:28px 0;border:1px solid var(--line);background:var(--panel)}
.row{display:grid;grid-template-columns:150px 1fr;gap:16px;padding:14px 16px;border-bottom:1px solid var(--line)}
.row:last-child{border-bottom:0}
.k{color:var(--muted);font:11px/1.5 var(--mono);text-transform:uppercase;letter-spacing:.05em}
.v{font:13px/1.6 var(--mono);overflow-wrap:anywhere}
.ok{color:var(--acid)}
a{color:var(--acid)}
.viral{margin-top:42px;padding-top:18px;border-top:1px solid var(--line);color:var(--muted);font:11px/1.6 var(--mono)}
.viral a{color:var(--muted);text-decoration:none;border-bottom:1px solid var(--line)}
.preview{border:1px solid #4d4a2a;border-left:2px solid var(--acid);background:rgba(200,255,106,.05);padding:11px 14px;margin:0 0 24px;color:#c5c3ba;font:12px/1.6 var(--mono)}
.preview a{color:var(--acid)}
@media(max-width:600px){.row{grid-template-columns:1fr;gap:4px}}
</style>
</head>
<body>
<main>
  <div class="preview">Sheaf is currently in Developer Preview. All paid features are free until further notice. <a href="https://news.ycombinator.com/submit" target="_blank" rel="noopener">Join the Hacker News discussion.</a></div>
  <div class="eyebrow">SHEAF / RECEIPT</div>
  <h1>${escapeHtml(input.chain_id)} <span class="sub">/ seq ${input.seq}</span></h1>
  <div class="sub">Signed, hash-chained event. Verify the full chain at <a href="/c/${encodeURIComponent(input.chain_id)}">/c/${escapeHtml(input.chain_id)}</a>.</div>
  <div class="card">
    <div class="row"><div class="k">Tool</div><div class="v">${escapeHtml(input.tool)}</div></div>
    <div class="row"><div class="k">Result</div><div class="v ok">${escapeHtml(input.result)}</div></div>
    <div class="row"><div class="k">Timestamp</div><div class="v">${time}</div></div>
    <div class="row"><div class="k">Envelope hash</div><div class="v">${escapeHtml(input.envelope_hash)}</div></div>
    <div class="row"><div class="k">Anchor</div><div class="v">${anchor}</div></div>
  </div>
  <div class="viral"><a href="https://sheafhq.io/">Verified by Sheaf. Cryptographic evidence for AI agents.</a></div>
</main>
</body>
</html>`;
}
