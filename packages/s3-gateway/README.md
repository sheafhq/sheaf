# @sheafhq/s3-gateway

S3-compatible write gateway that emits a Sheaf receipt for every successful
`PUT`.

```
S3 client ──PUT /:bucket/:key──▶ gateway ──SigV4 PUT──▶ R2 / MinIO / S3
                                    │
                                    ├─ SHA-256 of body
                                    └─ POST /events ──▶ Sheaf chain
```

The gateway buffers the request body to hash it and to set the signed
`Content-Length`/payload hash. This is an MVP; `MAX_UPLOAD_BYTES` defaults to
100 MiB. Stream-to-temp for larger objects later.

## Run

```bash
cd packages/s3-gateway
cp .env.example .env
npm install
npm run build
npm start
```

`PUT /:bucket/:key` forwards to `UPSTREAM_BUCKET` (falling back to the route
bucket) and returns the upstream status. On success it also returns:

```text
x-sheaf-chain-id
x-sheaf-seq
x-sheaf-envelope-hash
x-sheaf-file-sha256
```

The recorded event is:

```json
{
  "kind": "tool_call",
  "intent": "storage.write",
  "actor": "s3-gateway",
  "authority": "sheaf://s3-gateway-production/0",
  "tool": "s3.put",
  "inputs_hash": "sha256:<file_hash>",
  "outputs_hash": null,
  "result": "ok",
  "ts": "2026-11-13T21:00:00.000Z"
}
```

The `inputs_hash` is the SHA-256 of the exact uploaded bytes. The Worker signs
and chains the event; `SHEAF_API_KEY` is required.

If the upstream write succeeds but the Sheaf receipt fails, the gateway returns
`502` with `{ "error": "sheaf_receipt_failed", "stored": true }`. It does not
pretend a receipt exists. Use the upstream object's checksum/ETag for recovery.

## Test

```bash
npm test
```

The test starts an in-process fake S3 endpoint and a fake Worker, then verifies:

- the upstream receives the exact PUT body;
- the recorded `inputs_hash` is the SHA-256 of the body;
- the event has `tool: "s3.put"`, `intent: "storage.write"`, and the configured
  authority;
- the response carries the Sheaf chain/seq/hash headers.
