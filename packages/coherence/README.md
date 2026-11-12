# Sheaf coherence — cohomological certificate for CI/CD pipelines

A weekend experiment. Reads a JSON describing a CI/CD pipeline run (commit, build, test, deploy). Constructs a cellular sheaf over the pipeline. Computes H¹. Writes a certificate stating whether the evidence glues into one consistent global story — and if not, exactly which edge is the seam.

Pure Python. ~250 lines. Zero dependencies.

## What this catches that SBOMs and attestation tools don't

Existing provenance tooling (SLSA, in-toto, Sigstore) proves **each stage is signed by the right party**. It proves "this artifact was built from this commit" and "this test ran on this artifact." Nothing in the standard provenance stack explicitly checks that **the artifact your test observed is the same hash that your deploy pushed** — that cross-stage coherence is left implicit.

Typical failure mode: a cache layer resolves to a stale artifact between the test step and the deploy step. All stage-level attestations are valid individually. The artifact hashes diverge. Prod breaks with "tests passed, prod died." This is a *coherence* failure, not a *provenance* failure.

Sheaf coherence reframes the question as: "do the restriction maps between adjacent stages agree?" The answer is a mathematical object — the first cohomology group H¹ — whose dimension counts independent obstructions, and whose support names the exact edges where the pipeline's story breaks.

## Try it

```bash
# clone
git clone https://github.com/sheafhq/sheaf
cd sheaf/packages/coherence

# coherent pipeline → exit 0, OK
python3 cert.py fixtures/coherent.json
# → OK coherent: 3 edge(s), 0 seams...

# pipeline with artifact-hash drift between test and deploy → exit 1, FAIL with named seam
python3 cert.py fixtures/incoherent_artifact_drift.json
# → FAIL incoherent: 1 edge-level invariant violation(s).
#   sheaf seam at e_t1_d1 (Test->Deploy): I2_artifact_hash_mismatch
```

## Use in GitHub Actions

```yaml
- uses: sheafhq/sheaf/packages/coherence@main
  with:
    evidence: path/to/your/evidence.json
    fail-on-incoherent: 'true'
```

See [example-workflow.yml](./example-workflow.yml) for a complete drop-in.

## The math, briefly

Given a graph `G = (V, E)` with:

- a **stalk** `𝓔(v) ∈ ℝ^dᵥ` per vertex — the data at each pipeline stage,
- a **restriction map** `ρ_{u→e}: 𝓔(u) → 𝓔(e)` per edge endpoint — what each vertex contributes to the shared edge view,

the cellular sheaf `𝓔` on `G` has a cochain complex:

```
C⁰ = ⊕ 𝓔(v)         (vertex data)
δ⁰: C⁰ → C¹          (coboundary)
C¹ = ⊕ 𝓔(e)         (edge data)
```

with `(δ⁰ s)_e = ρ_{u→e}(s_u) − ρ_{v→e}(s_v)` for edge `e = (u,v)`.

For a graph (no 2-cells), `H¹ = C¹ / im(δ⁰)`. Non-zero H¹ means: *there exists a consistent edge assignment that cannot be obtained as the coboundary of any vertex assignment* — the pipeline cannot be globally consistent, no matter how you choose vertex data.

In our setting, the vertex stalks encode `[ts, commit_sha, artifact_hash, …]` and restriction maps project onto the shared field at each edge (artifact hash across build→test→deploy, commit SHA across commit→build). An edge seam means the two endpoints disagree on the shared field; an H¹ class means a set of seams that cannot be resolved by adjusting vertex data alone.

### Scope honesty

- **Linear pipelines (tree-shaped graphs) have H¹ = 0.** For a linear build→test→deploy, residual-per-edge is sufficient and sheaf cohomology is overkill. The framework becomes meaningfully diagnostic for **DAGs with fan-in** — e.g., parallel-arch builds that must agree, pre-flight checks that read the same artifact a deploy writes, forked pipelines that remerge. Fan-in fixture in v0.2.
- Timestamp monotonicity (`ts_u < ts_v`) is checked as a DAG property separately from the sheaf. Sheaf cohomology measures **equality** constraints; inequality constraints sit beside it.
- Hash collisions in the scalar encoding (first 64 bits of SHA-256) are cryptographically irrelevant here — we only check equality. For production, use the full 256-bit hash with integer arithmetic.
- This is a v0.1 pure-Python reference. A production engine would stream events, use sparse SVD, and handle multi-hundred-stage pipelines.

## Non-goals

- Not a replacement for SBOM / attestation tooling. Complementary.
- Not a blockchain anchor. For hash-chained + on-chain-anchored agent tool-call evidence, see the [parent Sheaf project](https://github.com/sheafhq/sheaf).
- Not a GRC platform.

## License

MIT.
