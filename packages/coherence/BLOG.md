# Your CI proves provenance. It doesn't prove the artifact you deployed is the one you tested.

*A weekend experiment in cohomological coherence for CI/CD.*

---

Your pipeline signs every stage. The commit is signed by you. The build artifact is signed by the builder. The test result is signed by the runner. The deployment is signed by the deploy agent. SLSA, in-toto, Sigstore — every link in the chain has provenance.

Provenance proves **each stage is authentic**. It does not prove **the stages agree on what they are talking about**.

Here is the failure mode nobody writes a check for:

```
commit c1    → build b1 produces artifact H1
build b1     → test t1 runs on artifact H1, all green
test t1      → deploy d1 reads artifact from cache, pushes H3
```

Every signature is valid. SLSA level 3. Full provenance. And the thing you pushed to production is not the thing your tests observed. Someone's cache layer resolved to a stale artifact between test and deploy, and nothing in the standard attestation stack explicitly checks that `test.artifact_hash == deploy.artifact_hash`.

This is a *coherence* failure, not a *provenance* failure. It's the kind of bug that produces an incident report titled "all tests passed, prod was down for four hours, root cause: deployment used a different artifact than the one we tested."

### The question in the right shape

The question isn't "was each stage signed." The question is: **do the stages' stories glue together into one consistent global history?**

That turns out to be a question algebraic topologists have been answering for fifty years, for a different reason. It is the question of whether a *section* of a *sheaf* exists on a given topological space. Translating:

- the pipeline is a graph
- each stage's data is a stalk on a vertex of that graph
- each adjacency between stages carries a restriction map that says "these two stages must agree on this specific field"
- a globally consistent pipeline is a **global section** — an assignment of data to each vertex such that all adjacencies are satisfied

The first cohomology group **H¹** of this sheaf measures the obstructions. Non-zero H¹ means: no global section exists. There is literally no assignment of values to stages that satisfies all the adjacencies at once. The *support* of a non-zero H¹ class names the exact edges where the stories disagree.

### The weekend experiment

I wrote 250 lines of pure Python that:

1. Reads a pipeline evidence JSON (commit → build → test → deploy events, each carrying a few fields).
2. Builds the cell complex: vertices are events, edges are workflow transitions, stalks are `[ts, commit_sha_scalar, artifact_hash_scalar, …]`.
3. Encodes the restriction maps as simple projections: Build→Test agrees on `artifact_hash`, Commit→Build agrees on `commit_sha`.
4. Constructs the coboundary `δ⁰`, computes its rank, reports `dim H¹`.
5. On the observed section, computes the residual on each edge. Non-zero residual = seam. Reports which edges are seams and which invariants broke.
6. Writes a `coherence-certificate.json` and a human summary.

The incoherent fixture (shipping a stale artifact to deploy while passing tests) produces:

```
FAIL incoherent: 1 edge-level invariant violation(s).
   sheaf seam at e_t1_d1 (Test->Deploy): I2_artifact_hash_mismatch
     residual = [-6.884e+17]
   H¹ dim = 0, coboundary rank = 3
```

The certificate names the exact edge (`Test → Deploy`) and the exact invariant that broke (`I2_artifact_hash_mismatch`). A deploy automation can block on this. An audit log can archive it. An incident retrospective can start from it instead of from grep.

### What the math buys and what it doesn't

For a **linear pipeline** — commit → build → test → deploy with no fan-in — H¹ is always 0 (trees have no cycles, so there are no cycle-level obstructions). Residual-per-edge is sufficient and the sheaf framework is technically overkill. The incoherent case above still flags cleanly via residual, but calling it "cohomological" is slightly oversold for this shape.

Where sheaf cohomology **starts to matter**: **DAGs with fan-in**. Parallel-architecture builds that must agree. Two independent test suites reading the same artifact. A pre-flight check that re-hashes the deploy target and claims it matches the build output. Forked pipelines that remerge. In those cases, dim H¹ counts the number of **independent** obstructions — a single mismatched artifact in a fan-in creates one H¹ class, but residual-per-edge would report it as two, three, or more seams depending on how many paths reach the merge point.

The v0.1 fixture is linear because it is the one everyone recognizes. v0.2 will add a parallel-arch fan-in fixture where dim H¹ > 0 is diagnostically distinct from pairwise checks.

### Why not "just compare hashes"

You could absolutely write a bespoke check: "fail if `test.artifact_hash != deploy.artifact_hash`." People do. Then they write another one for commit SHA. Another for the environment tag. Another for the config bundle. Another for SBOM lineage. At some point the ad-hoc check registry becomes the thing you cannot audit, and adding a new coherence constraint is a code review instead of a configuration change.

The sheaf framework makes the invariants **declarative**: name the restriction map, the system computes the obstruction. Adding a new invariant is a two-line addition, not a new check function. And the certificate output is uniform — same JSON schema regardless of which invariant tripped — so downstream consumers (dashboards, auditors, alerting) don't have to be re-coded per invariant.

### Try it

```bash
git clone https://github.com/sheafhq/sheaf
cd sheaf/packages/coherence
python3 cert.py fixtures/coherent.json              # exit 0, OK
python3 cert.py fixtures/incoherent_artifact_drift.json   # exit 1, named seam
```

Or drop into any GitHub Actions workflow:

```yaml
- uses: sheafhq/sheaf/packages/coherence@main
  with:
    evidence: path/to/your/evidence.json
    fail-on-incoherent: 'true'
```

Full code and math in [github.com/sheafhq/sheaf/tree/main/packages/coherence](https://github.com/sheafhq/sheaf/tree/main/packages/coherence). MIT. ~250 lines, no deps.

### The larger project

This is an experiment under [Sheaf](https://github.com/sheafhq/sheaf) — a broader toolkit for cryptographic + mathematical coherence of agent and pipeline evidence. The main product today is an on-chain-anchored audit layer for AI agent tool calls. This coherence check is a different vertical under the same primitive.

The question I actually want to answer with this experiment: does a declarative coherence primitive matter to anyone who runs CI/CD? If this post gets forks, stars, or the GitHub Action gets installed on any public repo, that's signal. If not, the vertical is wrong. Either way, I'd rather know after a weekend than after three months.

Try the fixtures. Open an issue if you break the math. Star the repo if this would have saved you a 2am page.

— *2026-11-12*
