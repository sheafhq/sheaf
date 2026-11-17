import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:http";

import { startGateway } from "../dist/gateway.js";

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(server.address().port));
  });
}

function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

test("S3 PUT is forwarded, hashed, and recorded as a Sheaf event", async () => {
  const s3Writes = [];
  const s3 = createServer((req, res) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      s3Writes.push({
        method: req.method,
        url: req.url,
        body: Buffer.concat(chunks).toString("utf8"),
      });
      res.writeHead(200, { ETag: '"etag-1"', "content-length": "0" });
      res.end();
    });
  });
  const s3Port = await listen(s3);

  const events = [];
  const worker = createServer((req, res) => {
    if (req.method === "GET" && req.url === "/chains/test-chain/head") {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "not found" }));
      return;
    }
    if (req.method === "POST" && req.url === "/events") {
      if (req.headers.authorization !== "Bearer test-key") {
        res.writeHead(401, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "unauthorized" }));
        return;
      }
      const chunks = [];
      req.on("data", (chunk) => chunks.push(chunk));
      req.on("end", () => {
        const envelope = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        events.push(envelope);
        res.writeHead(201, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            ok: true,
            seq: envelope.chain.seq,
            envelope_hash: `hash-${envelope.chain.seq}`,
          }),
        );
      });
      return;
    }
    res.writeHead(404).end();
  });
  const workerPort = await listen(worker);

  const cfg = {
    port: 0,
    upstreamEndpoint: `http://127.0.0.1:${s3Port}`,
    upstreamAccessKey: "test-access",
    upstreamSecretKey: "test-secret",
    upstreamBucket: "compliance-archive",
    upstreamRegion: "us-east-1",
    sheafBaseUrl: `http://127.0.0.1:${workerPort}`,
    sheafApiKey: "test-key",
    chainId: "test-chain",
    actor: "s3-gateway",
    authority: "sheaf://test-chain/0",
    maxUploadBytes: 1024 * 1024,
  };

  const gateway = await startGateway(cfg);
  const gatewayPort = gateway.address().port;
  try {
    const firstBody = "hello vault";
    const first = await fetch(
      `http://127.0.0.1:${gatewayPort}/compliance-archive/path/file.txt`,
      {
        method: "PUT",
        headers: { "content-type": "text/plain" },
        body: firstBody,
      },
    );
    assert.equal(first.status, 200);
    assert.equal(first.headers.get("x-sheaf-chain-id"), "test-chain");
    assert.equal(first.headers.get("x-sheaf-seq"), "0");
    assert.equal(
      first.headers.get("x-sheaf-file-sha256"),
      createHash("sha256").update(firstBody).digest("hex"),
    );

    assert.equal(s3Writes.length, 1);
    assert.equal(s3Writes[0].method, "PUT");
    assert.match(s3Writes[0].url, /compliance-archive\/path\/file\.txt/);
    assert.equal(s3Writes[0].body, firstBody);

    assert.equal(events.length, 1);
    assert.equal(events[0].chain.chain_id, "test-chain");
    assert.equal(events[0].chain.seq, 0);
    assert.equal(events[0].chain.prev_hash, null);
    assert.equal(events[0].event.kind, "tool_call");
    assert.equal(events[0].event.intent, "storage.write");
    assert.equal(events[0].event.tool, "s3.put");
    assert.equal(
      events[0].event.inputs_hash,
      "sha256:" + createHash("sha256").update(firstBody).digest("hex"),
    );
    assert.equal(events[0].event.authority, "sheaf://test-chain/0");
    assert.equal(events[0].event.result, "ok");

    const secondBody = "second object";
    const second = await fetch(
      `http://127.0.0.1:${gatewayPort}/compliance-archive/path/second.txt`,
      { method: "PUT", body: secondBody },
    );
    assert.equal(second.status, 200);
    assert.equal(second.headers.get("x-sheaf-seq"), "1");
    assert.equal(events[1].chain.seq, 1);
    assert.equal(events[1].chain.prev_hash, "hash-0");
  } finally {
    await close(gateway);
    await close(worker);
    await close(s3);
  }
});
