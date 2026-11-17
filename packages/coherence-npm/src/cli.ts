#!/usr/bin/env node
// Cohomological coherence check for CI/CD pipelines — TypeScript port of
// the reference cert.py. Zero runtime deps beyond Node ≥18 stdlib.
//
// Usage:
//   sheaf-coherence <evidence.json> [--out cert.json]
//
// Exits 0 if the pipeline's evidence glues into one consistent global
// story; 1 if a sheaf seam or DAG violation is detected.

import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const PRIME = 2n ** 61n - 1n;

function hashScalar(s: string): number {
  if (s.startsWith("sha256:")) s = s.slice(7);
  const head = s.slice(0, 16);
  let n = 0n;
  try {
    n = BigInt("0x" + head);
  } catch {
    // Non-hex: fall back to simple char-sum. Cryptographically irrelevant;
    // only equality comparisons matter here.
    for (const c of s) n = (n * 31n + BigInt(c.charCodeAt(0))) & ((1n << 61n) - 1n);
  }
  return Number(n % PRIME);
}

type Event = {
  id: string;
  type: "Commit" | "Build" | "Test" | "Deploy";
  ts: number;
  parent_id?: string;
  sha?: string;
  commit_sha?: string;
  artifact_hash?: string;
  result?: string;
  environment?: string;
};

type Fixture = { fixture_name?: string; events: Event[] };

const STALK_SHAPE: Record<Event["type"], string[]> = {
  Commit: ["ts", "sha_scalar"],
  Build: ["ts", "commit_sha_scalar", "artifact_hash_scalar"],
  Test: ["ts", "artifact_hash_scalar", "result_code"],
  Deploy: ["ts", "artifact_hash_scalar", "env_code"],
};

function stalkVector(ev: Event): number[] {
  const ts = ev.ts;
  switch (ev.type) {
    case "Commit":
      return [ts, hashScalar(ev.sha ?? "")];
    case "Build":
      return [ts, hashScalar(ev.commit_sha ?? ""), hashScalar(ev.artifact_hash ?? "")];
    case "Test":
      return [ts, hashScalar(ev.artifact_hash ?? ""), ev.result === "pass" ? 1 : 0];
    case "Deploy":
      return [ts, hashScalar(ev.artifact_hash ?? ""), hashScalar(ev.environment ?? "")];
  }
}

// Linear algebra primitives (pure TS).
function matVec(M: number[][], v: number[]): number[] {
  return M.map((row) => row.reduce((acc, x, i) => acc + x * v[i]!, 0));
}
function vecSub(a: number[], b: number[]): number[] {
  return a.map((x, i) => x - b[i]!);
}
function vecNorm(v: number[]): number {
  return Math.sqrt(v.reduce((a, x) => a + x * x, 0));
}
function matrixRank(M: number[][], tol = 1e-8): number {
  if (M.length === 0 || M[0]!.length === 0) return 0;
  const A = M.map((row) => row.slice());
  const rows = A.length;
  const cols = A[0]!.length;
  let rank = 0;
  for (let c = 0; c < cols; c++) {
    let pivot = -1;
    let pmax = tol;
    for (let r = rank; r < rows; r++) {
      if (Math.abs(A[r]![c]!) > pmax) {
        pmax = Math.abs(A[r]![c]!);
        pivot = r;
      }
    }
    if (pivot < 0) continue;
    [A[rank], A[pivot]] = [A[pivot]!, A[rank]!];
    const pv = A[rank]![c]!;
    for (let r = 0; r < rows; r++) {
      if (r !== rank && Math.abs(A[r]![c]!) > tol) {
        const factor = A[r]![c]! / pv;
        for (let cc = c; cc < cols; cc++) A[r]![cc]! -= factor * A[rank]![cc]!;
      }
    }
    rank++;
    if (rank === rows) break;
  }
  return rank;
}

type EdgeSpec = { invariants: string[]; edgeDim: number; rhoSrc: number[][]; rhoDst: number[][] };
function edgeSpec(srcType: Event["type"], dstType: Event["type"]): EdgeSpec {
  if (srcType === "Commit" && dstType === "Build") {
    return {
      invariants: ["I3_lineage"],
      edgeDim: 1,
      rhoSrc: [[0, 1]],
      rhoDst: [[0, 1, 0]],
    };
  }
  if (srcType === "Build" && dstType === "Test") {
    return {
      invariants: ["I2_artifact_coherence"],
      edgeDim: 1,
      rhoSrc: [[0, 0, 1]],
      rhoDst: [[0, 1, 0]],
    };
  }
  if (srcType === "Test" && dstType === "Deploy") {
    return {
      invariants: ["I2_artifact_coherence"],
      edgeDim: 1,
      rhoSrc: [[0, 1, 0]],
      rhoDst: [[0, 1, 0]],
    };
  }
  throw new Error(`no restriction map for edge ${srcType} -> ${dstType}`);
}

type Edge = {
  id: string;
  src: string;
  dst: string;
  srcType: Event["type"];
  dstType: Event["type"];
  invariants: string[];
  edgeDim: number;
  rhoSrc: number[][];
  rhoDst: number[][];
};

function buildEdges(events: Event[]): Edge[] {
  const byId = new Map(events.map((e) => [e.id, e]));
  const edges: Edge[] = [];
  for (const ev of events) {
    if (!ev.parent_id) continue;
    const parent = byId.get(ev.parent_id);
    if (!parent) continue;
    const spec = edgeSpec(parent.type, ev.type);
    edges.push({
      id: `e_${parent.id}_${ev.id}`,
      src: parent.id,
      dst: ev.id,
      srcType: parent.type,
      dstType: ev.type,
      invariants: spec.invariants,
      edgeDim: spec.edgeDim,
      rhoSrc: spec.rhoSrc,
      rhoDst: spec.rhoDst,
    });
  }
  return edges;
}

type Seam = {
  edge_id: string;
  from: string;
  to: string;
  edge_type: string;
  residual_norm: number;
  residual: number[];
  invariants_broken: string[];
};

function computeCohomology(
  events: Event[],
  edges: Edge[],
  section: Map<string, number[]>,
): {
  H0_dim: number;
  H1_dim: number;
  coboundary_rank: number;
  coboundary_shape: [number, number];
  seams: Seam[];
} {
  const vDims = new Map(events.map((e) => [e.id, STALK_SHAPE[e.type].length]));
  const vOffset = new Map<string, number>();
  let off = 0;
  for (const ev of events) {
    vOffset.set(ev.id, off);
    off += vDims.get(ev.id)!;
  }
  const totalV = off;
  const totalE = edges.reduce((a, e) => a + e.edgeDim, 0);

  const delta0: number[][] = Array.from({ length: totalE }, () =>
    Array(totalV).fill(0),
  );
  let row = 0;
  for (const e of edges) {
    const srcOff = vOffset.get(e.src)!;
    const dstOff = vOffset.get(e.dst)!;
    const srcD = vDims.get(e.src)!;
    const dstD = vDims.get(e.dst)!;
    for (let i = 0; i < e.edgeDim; i++) {
      for (let j = 0; j < srcD; j++) delta0[row + i]![srcOff + j] = e.rhoSrc[i]![j]!;
      for (let j = 0; j < dstD; j++) delta0[row + i]![dstOff + j] = -e.rhoDst[i]![j]!;
    }
    row += e.edgeDim;
  }

  const seams: Seam[] = [];
  for (const e of edges) {
    const sSrc = section.get(e.src)!;
    const sDst = section.get(e.dst)!;
    const rs = matVec(e.rhoSrc, sSrc);
    const rd = matVec(e.rhoDst, sDst);
    const residual = vecSub(rs, rd);
    const norm = vecNorm(residual);
    if (norm > 1e-6) {
      const broken: string[] = [];
      for (let i = 0; i < residual.length; i++) {
        if (Math.abs(residual[i]!) > 1e-6) {
          if (e.invariants.includes("I2_artifact_coherence")) broken.push("I2_artifact_hash_mismatch");
          else if (e.invariants.includes("I3_lineage")) broken.push("I3_commit_sha_mismatch");
          else broken.push(`coord_${i}_nonzero`);
        }
      }
      seams.push({
        edge_id: e.id,
        from: e.src,
        to: e.dst,
        edge_type: `${e.srcType}->${e.dstType}`,
        residual_norm: norm,
        residual,
        invariants_broken: broken,
      });
    }
  }

  const rank = matrixRank(delta0);
  return {
    H0_dim: totalV - rank,
    H1_dim: totalE - rank,
    coboundary_rank: rank,
    coboundary_shape: [totalE, totalV],
    seams,
  };
}

type TemporalViolation = {
  edge_id: string;
  from: string;
  to: string;
  edge_type: string;
  src_ts: number;
  dst_ts: number;
  violation: "temporal_non_monotone";
};

function checkTemporal(events: Event[], edges: Edge[]): TemporalViolation[] {
  const byId = new Map(events.map((e) => [e.id, e]));
  const out: TemporalViolation[] = [];
  for (const e of edges) {
    const srcTs = byId.get(e.src)!.ts;
    const dstTs = byId.get(e.dst)!.ts;
    if (dstTs <= srcTs) {
      out.push({
        edge_id: e.id,
        from: e.src,
        to: e.dst,
        edge_type: `${e.srcType}->${e.dstType}`,
        src_ts: srcTs,
        dst_ts: dstTs,
        violation: "temporal_non_monotone",
      });
    }
  }
  return out;
}

function main(argv: string[]): never {
  if (argv.length < 1) {
    console.error("usage: sheaf-coherence <evidence.json> [--out cert.json]");
    process.exit(2);
  }
  const fixturePath = resolve(argv[0]!);
  let outPath = "cert.json";
  const outIdx = argv.indexOf("--out");
  if (outIdx >= 0) outPath = argv[outIdx + 1] ?? outPath;

  const fixture = JSON.parse(readFileSync(fixturePath, "utf8")) as Fixture;
  const events = fixture.events;
  const section = new Map(events.map((e) => [e.id, stalkVector(e)]));
  const edges = buildEdges(events);
  const cohom = computeCohomology(events, edges, section);
  const temporal = checkTemporal(events, edges);
  const verdict = cohom.seams.length === 0 && temporal.length === 0 ? "coherent" : "incoherent";

  const lines: string[] = [];
  if (verdict === "coherent") {
    lines.push(`OK coherent: ${edges.length} edge(s), 0 seams. Evidence glues into a single consistent story.`);
    lines.push(`   H^0 dim = ${cohom.H0_dim} (dimension of consistent global sections)`);
    lines.push(`   H^1 dim = ${cohom.H1_dim} (zero sheaf obstructions)`);
  } else {
    const n = cohom.seams.length + temporal.length;
    lines.push(`FAIL incoherent: ${n} edge-level invariant violation(s). Evidence cannot all be true at once.`);
    for (const s of cohom.seams) {
      lines.push(`   sheaf seam at ${s.edge_id} (${s.edge_type}): ${s.invariants_broken.join(", ")}`);
      lines.push(`     residual = [${s.residual.map((x) => x.toExponential(3)).join(", ")}]`);
    }
    for (const v of temporal) {
      lines.push(`   DAG violation at ${v.edge_id} (${v.edge_type}): dst_ts ${v.dst_ts} <= src_ts ${v.src_ts}`);
    }
    lines.push(`   H^1 dim = ${cohom.H1_dim}, coboundary rank = ${cohom.coboundary_rank}, temporal violations = ${temporal.length}`);
  }

  const certificate = {
    version: "sheaf-cert/1",
    generated_at: new Date().toISOString(),
    vertical: "ci-cd-coherence",
    fixture: fixture.fixture_name,
    cell_complex: {
      vertices: events.map((e) => ({
        id: e.id,
        type: e.type,
        stalk_dim: STALK_SHAPE[e.type].length,
        stalk_fields: STALK_SHAPE[e.type],
      })),
      edges: edges.map((e) => ({
        id: e.id,
        from: e.src,
        to: e.dst,
        type: `${e.srcType}->${e.dstType}`,
        invariants: e.invariants,
        edge_dim: e.edgeDim,
      })),
    },
    cohomology: {
      H0_dim: cohom.H0_dim,
      H1_dim: cohom.H1_dim,
      coboundary_rank: cohom.coboundary_rank,
      coboundary_shape: cohom.coboundary_shape,
    },
    verdict,
    sheaf_obstructions: cohom.seams,
    temporal_violations: temporal,
    human_readable: { summary: lines.join("\n") },
  };

  writeFileSync(outPath, JSON.stringify(certificate, null, 2));
  console.log(lines.join("\n"));
  console.log(`\ncertificate: ${outPath}`);
  process.exit(verdict === "coherent" ? 0 : 1);
}

main(process.argv.slice(2));
