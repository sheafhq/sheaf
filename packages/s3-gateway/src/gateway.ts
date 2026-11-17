import { createHash } from "node:crypto";
import type { Server } from "node:http";
import express, { type Request, type Response } from "express";
import {
  PutObjectCommand,
  S3Client,
  type PutObjectCommandOutput,
} from "@aws-sdk/client-s3";

import type { GatewayConfig } from "./config.js";
import { SheafReceiptClient } from "./sheaf.js";

export type GatewayDependencies = {
  s3?: S3Client;
  sheaf?: SheafReceiptClient;
};

function s3Client(cfg: GatewayConfig): S3Client {
  return new S3Client({
    region: cfg.upstreamRegion,
    endpoint: cfg.upstreamEndpoint,
    forcePathStyle: true,
    credentials: {
      accessKeyId: cfg.upstreamAccessKey,
      secretAccessKey: cfg.upstreamSecretKey,
    },
  });
}

async function readBody(
  req: Request,
  maxBytes: number,
): Promise<{ body: Buffer; sha256: string }> {
  const declared = Number(req.headers["content-length"] ?? 0);
  if (Number.isFinite(declared) && declared > maxBytes) {
    throw Object.assign(new Error("upload exceeds MAX_UPLOAD_BYTES"), {
      statusCode: 413,
    });
  }
  const hash = createHash("sha256");
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += buffer.length;
    if (total > maxBytes) {
      throw Object.assign(new Error("upload exceeds MAX_UPLOAD_BYTES"), {
        statusCode: 413,
      });
    }
    hash.update(buffer);
    chunks.push(buffer);
  }
  return {
    body: Buffer.concat(chunks),
    sha256: hash.digest("hex"),
  };
}

function upstreamStatus(err: unknown): number {
  const status = (err as { $metadata?: { httpStatusCode?: number } })?.$metadata
    ?.httpStatusCode;
  return typeof status === "number" ? status : 502;
}

export function createGateway(
  cfg: GatewayConfig,
  deps: GatewayDependencies = {},
): express.Express {
  const app = express();
  app.disable("x-powered-by");
  const s3 = deps.s3 ?? s3Client(cfg);
  const sheaf = deps.sheaf ?? new SheafReceiptClient(cfg);

  app.get("/health", (_req, res) => {
    res.json({ ok: true, chain_id: cfg.chainId });
  });

  app.put("/:bucket/*", async (req: Request, res: Response) => {
    const bucket = cfg.upstreamBucket ?? req.params.bucket;
    const key = req.params[0];
    if (!bucket || !key) {
      res.status(400).json({ error: "bucket and key are required" });
      return;
    }

    let file: { body: Buffer; sha256: string };
    try {
      file = await readBody(req, cfg.maxUploadBytes);
    } catch (err) {
      const status = (err as { statusCode?: number }).statusCode ?? 400;
      res.status(status).json({ error: (err as Error).message });
      return;
    }

    let upstream: PutObjectCommandOutput;
    try {
      upstream = await s3.send(
        new PutObjectCommand({
          Bucket: bucket,
          Key: key,
          Body: file.body,
          ContentLength: file.body.length,
          ContentType:
            typeof req.headers["content-type"] === "string"
              ? req.headers["content-type"]
              : undefined,
        }),
      );
    } catch (err) {
      const status = upstreamStatus(err);
      res.status(status >= 400 && status < 600 ? status : 502).json({
        error: "upstream_s3_write_failed",
        message: (err as Error).message,
      });
      return;
    }

    let receipt;
    try {
      receipt = await sheaf.record(file.sha256);
    } catch (err) {
      res.status(502).json({
        error: "sheaf_receipt_failed",
        stored: true,
        bucket,
        key,
        sha256: file.sha256,
        message: (err as Error).message,
      });
      return;
    }

    if (upstream.ETag) res.setHeader("ETag", upstream.ETag);
    res.setHeader("x-sheaf-chain-id", receipt.chain_id);
    res.setHeader("x-sheaf-seq", String(receipt.seq));
    res.setHeader("x-sheaf-envelope-hash", receipt.envelope_hash);
    res.setHeader("x-sheaf-file-sha256", file.sha256);
    res.status(200).end();
  });

  app.use(
    (
      err: unknown,
      _req: Request,
      res: Response,
      _next: express.NextFunction,
    ) => {
      res.status(500).json({ error: (err as Error).message });
    },
  );

  return app;
}

export function startGateway(cfg: GatewayConfig): Promise<Server> {
  const app = createGateway(cfg);
  return new Promise((resolve, reject) => {
    const server = app.listen(cfg.port, () => resolve(server));
    server.on("error", reject);
  });
}
