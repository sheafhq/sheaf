# @sheafhq/coherence

Cohomological coherence certificate for CI/CD pipelines. **Zero deps, Node ≥18.**

```bash
npx @sheafhq/coherence fixtures/coherent.json              # exit 0
npx @sheafhq/coherence fixtures/incoherent_artifact_drift.json   # exit 1
```

Reads a JSON describing your pipeline (commit → build → test → deploy events). Constructs a cellular sheaf over it. Computes H¹. Writes a certificate stating whether the evidence glues into one consistent global story — and if not, exactly which edge is the seam.

## What it catches

The failure mode SBOMs and attestation tools don't explicitly check: **the artifact your tests observed is not the artifact you deployed**. Typical cause: a cache layer resolved to a stale artifact between the test step and the deploy step. All stage-level signatures are valid. Nobody checks `test.artifact_hash == deploy.artifact_hash`.

Sheaf coherence reframes "does this pipeline hold together" as "does H¹ = 0 for this cellular sheaf?" If not, the certificate names the exact edge where the story breaks.

## Evidence format

See the reference fixtures at [github.com/sheafhq/sheaf/tree/main/packages/coherence/fixtures](https://github.com/sheafhq/sheaf/tree/main/packages/coherence/fixtures).

Minimal shape:

```json
{
  "fixture_name": "my-pipeline-run",
  "events": [
    { "id": "c1", "type": "Commit", "ts": 1794428400, "sha": "a1b2c3..." },
    { "id": "b1", "type": "Build", "ts": 1794428460, "parent_id": "c1",
      "commit_sha": "a1b2c3...", "artifact_hash": "sha256:b00bee5..." },
    { "id": "t1", "type": "Test", "ts": 1794428520, "parent_id": "b1",
      "artifact_hash": "sha256:b00bee5...", "result": "pass" },
    { "id": "d1", "type": "Deploy", "ts": 1794428580, "parent_id": "t1",
      "artifact_hash": "sha256:b00bee5...", "environment": "production" }
  ]
}
```

## GitHub Actions

Pair with [sheafhq/sheaf-coherence-action](https://github.com/sheafhq/sheaf-coherence-action):

```yaml
- uses: sheafhq/sheaf-coherence-action@v0.1.0
  with:
    evidence: evidence.json
    fail-on-incoherent: 'true'
```

## Scope honesty

- **Linear pipelines (tree-shaped graphs) have H¹ = 0.** For a linear build→test→deploy, residual-per-edge equals the sheaf check. The framework becomes genuinely diagnostic for **DAGs with fan-in** (parallel-arch builds, pre-flight checks, forked remerging pipelines). Fan-in fixture in v0.2.
- Timestamp monotonicity (`ts_u < ts_v`) is checked as a DAG property separately — equality constraints and inequality constraints live in different frames.
- Hash collisions in the scalar encoding are cryptographically irrelevant here (only equality comparisons matter).

Pure TypeScript port of the reference Python [cert.py](https://github.com/sheafhq/sheaf/blob/main/packages/coherence/cert.py). ~400 lines, zero runtime deps.

## License

MIT.
