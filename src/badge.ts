// Flat SVG badge for a chain. Format: [ sheaf | 42 anchors ].
// Readable from any image renderer; GitHub's camo proxy passes SVG through.
// Keep this self-contained (no external fonts) so the badge works anywhere.
//
// Design matches shields.io flat style: left slate label, right teal value.
// Corner radius 3, height 20px. Variable width based on value text length.

function escapeXml(s: unknown): string {
  return String(s).replace(/[&<>"']/g, (c) => {
    switch (c) {
      case "&": return "&amp;";
      case "<": return "&lt;";
      case ">": return "&gt;";
      case '"': return "&quot;";
      case "'": return "&apos;";
      default: return c;
    }
  });
}

// Approximate glyph widths for the Verdana-like fallback. Not perfect but
// avoids embedding a font. Overestimates by ~1px which pads nicely.
function textWidth(s: string): number {
  let w = 0;
  for (const ch of s) {
    if (ch === " ") w += 4;
    else if (/[iIl1.,:;!|]/.test(ch)) w += 3;
    else if (/[tfrj]/.test(ch)) w += 4;
    else if (/[a-z0-9]/.test(ch)) w += 6.5;
    else if (/[A-Z]/.test(ch)) w += 7.5;
    else w += 6;
  }
  return Math.ceil(w);
}

export function renderBadge(opts: {
  label?: string;
  value: string;
  anchored?: boolean;
}): string {
  const label = opts.label ?? "sheaf";
  const value = opts.value;
  const PAD = 7;
  const lw = textWidth(label) + PAD * 2;
  const vw = textWidth(value) + PAD * 2;
  const total = lw + vw;
  const H = 20;
  // Colors
  const labelBg = "#555";
  const valueBg = opts.anchored === false ? "#9f9f9f" : "#4bb543";
  const textColor = "#fff";

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${total}" height="${H}" role="img" aria-label="${escapeXml(label)}: ${escapeXml(value)}">
  <title>${escapeXml(label)}: ${escapeXml(value)}</title>
  <linearGradient id="g" x2="0" y2="100%">
    <stop offset="0" stop-color="#fff" stop-opacity=".15"/>
    <stop offset="1" stop-opacity=".15"/>
  </linearGradient>
  <mask id="m"><rect width="${total}" height="${H}" rx="3" fill="#fff"/></mask>
  <g mask="url(#m)">
    <rect width="${lw}" height="${H}" fill="${labelBg}"/>
    <rect x="${lw}" width="${vw}" height="${H}" fill="${valueBg}"/>
    <rect width="${total}" height="${H}" fill="url(#g)"/>
  </g>
  <g fill="${textColor}" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="${lw / 2}" y="15" fill="#010101" fill-opacity=".3">${escapeXml(label)}</text>
    <text x="${lw / 2}" y="14">${escapeXml(label)}</text>
    <text x="${lw + vw / 2}" y="15" fill="#010101" fill-opacity=".3">${escapeXml(value)}</text>
    <text x="${lw + vw / 2}" y="14">${escapeXml(value)}</text>
  </g>
</svg>`;
}
