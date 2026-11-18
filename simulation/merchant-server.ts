// Mock Merchant MCP server (stdio transport, newline-delimited JSON-RPC 2.0).
//
// Tools:
//   buy_premium_data     EUR 100
//   buy_enterprise_data  EUR 200
//
// The buyer must state the amount and currency it is paying. The merchant
// rejects any call whose amount does not equal the list price. That is what
// makes an amount-based firewall meaningful: the agent cannot under-declare
// the amount to slip past the buyer's budget cap, because the merchant would
// then refuse the sale.
//
// Logs go to stderr; stdout carries only JSON-RPC.

import { createInterface } from "node:readline";

type Product = {
  tool: string;
  sku: string;
  price_eur: number;
  title: string;
  dataset: Record<string, unknown>;
};

const CATALOG: Product[] = [
  {
    tool: "buy_premium_data",
    sku: "PREMIUM-DATA-2026Q4",
    price_eur: 100,
    title: "Premium market data",
    dataset: {
      tier: "premium",
      series: "eu-energy-spot-daily",
      window: "2026-10-01/2026-10-31",
      rows: 31,
      sample: [
        { date: "2026-10-01", eur_mwh: 84.12 },
        { date: "2026-10-02", eur_mwh: 81.77 },
        { date: "2026-10-03", eur_mwh: 79.4 },
      ],
    },
  },
  {
    tool: "buy_enterprise_data",
    sku: "ENTERPRISE-DATA-2026Q4",
    price_eur: 200,
    title: "Enterprise market data",
    dataset: {
      tier: "enterprise",
      series: "eu-energy-spot-hourly+forwards",
      window: "2026-01-01/2026-10-31",
      rows: 7296,
      sample: [{ ts: "2026-10-31T23:00:00Z", eur_mwh: 77.03, fwd_q1: 92.5 }],
    },
  },
];

const PROTOCOL_VERSION = "2025-03-26";
let orderCounter = 0;

function send(msg: unknown): void {
  process.stdout.write(JSON.stringify(msg) + "\n");
}

function log(...args: unknown[]): void {
  console.error("[merchant]", ...args);
}

function toolList() {
  return CATALOG.map((p) => ({
    name: p.tool,
    description: `Buy ${p.title} (SKU ${p.sku}). Costs €${p.price_eur} (EUR). Pass amount=${p.price_eur} and currency="EUR".`,
    inputSchema: {
      type: "object",
      properties: {
        amount: {
          type: "number",
          description: `Amount you are paying, in EUR. Must equal the list price (${p.price_eur}).`,
        },
        currency: { type: "string", enum: ["EUR"] },
      },
      required: ["amount", "currency"],
      additionalProperties: false,
    },
  }));
}

function callTool(name: string, args: Record<string, unknown>) {
  const product = CATALOG.find((p) => p.tool === name);
  if (!product) {
    return {
      content: [{ type: "text", text: `Unknown tool: ${name}` }],
      isError: true,
    };
  }
  if (args.currency !== "EUR" || args.amount !== product.price_eur) {
    log(`rejected ${name}: offered ${String(args.amount)} ${String(args.currency)}`);
    return {
      content: [
        {
          type: "text",
          text: `Payment rejected: ${product.title} costs €${product.price_eur} EUR; you offered ${String(args.amount)} ${String(args.currency)}.`,
        },
      ],
      isError: true,
    };
  }
  orderCounter += 1;
  const order = {
    order_id: `ORD-${String(orderCounter).padStart(4, "0")}`,
    sku: product.sku,
    charged: { amount: product.price_eur, currency: "EUR" },
    data: product.dataset,
  };
  log(`SOLD ${product.sku} for €${product.price_eur} (${order.order_id})`);
  return {
    content: [
      {
        type: "text",
        text: `Purchase successful: ${product.title} for €${product.price_eur}. Order ${order.order_id}.\n${JSON.stringify(order)}`,
      },
    ],
    structuredContent: order,
    isError: false,
  };
}

const rl = createInterface({ input: process.stdin });
rl.on("line", (line) => {
  if (!line.trim()) return;
  let req: { id?: number | string; method?: string; params?: Record<string, unknown> };
  try {
    req = JSON.parse(line);
  } catch {
    send({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } });
    return;
  }
  const { id, method, params } = req;
  // Notifications (no id) get no response.
  if (id === undefined || id === null) return;

  switch (method) {
    case "initialize":
      send({
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: PROTOCOL_VERSION,
          capabilities: { tools: {} },
          serverInfo: { name: "mock-merchant", version: "0.1.0" },
        },
      });
      return;
    case "ping":
      send({ jsonrpc: "2.0", id, result: {} });
      return;
    case "tools/list":
      send({ jsonrpc: "2.0", id, result: { tools: toolList() } });
      return;
    case "tools/call": {
      const name = String(params?.name ?? "");
      const args = (params?.arguments ?? {}) as Record<string, unknown>;
      send({ jsonrpc: "2.0", id, result: callTool(name, args) });
      return;
    }
    default:
      send({ jsonrpc: "2.0", id, error: { code: -32601, message: `Method not found: ${method}` } });
  }
});
rl.on("close", () => process.exit(0));
log("ready (stdio)");
