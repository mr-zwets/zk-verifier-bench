// Emit the benchmark as the structured results.json the competition website reads.
// The website never runs the harness directly; it renders this artifact. Usage:
//   pnpm benchmark:json [outfile]      (default: results.json in the cwd)
//
// Schema (v1): a flat list of entries the site groups by `category`:
//   - "full"    -> a full Groth16 verifier        (the MAIN leaderboard)
//   - "partial" -> a checkpoint/sub-step (e.g. vk_x; a SECONDARY leaderboard)
//   - "demo"    -> harness self-test (hidden by default)
// Score = total on-chain bytes (lower = cheaper fees). op-cost / steps are
// secondary. BCH compatibility is a multi-dimensional cell, not a yes/no: a huge
// BSV singleton is a correct, listed submission that simply does not fit BCH.
import { existsSync, readFileSync, writeFileSync } from 'node:fs';

import type { BenchmarkResult } from './types.js';
import { computeResults } from './benchmark.js';
import { STANDARD_UNLOCKING_CAP } from './vm.js';

const SCHEMA_VERSION = 1;
const SIZE_CAP = STANDARD_UNLOCKING_CAP; // 10,000 B per locking/unlocking script

// Accumulating time-series for the score-history chart, ONE file holding two interleaved
// series tagged by `fits`: the best BCH-native (fitting) full verifier, and the smallest
// NON-fitting single-tx "singleton" ideal — their gap over time is the chunking tax.
const HISTORY_FILE = 'score-history.json';
interface HistoryPoint { t: string; score: number; id: string; steps: number; fits: boolean }
const loadHistory = (): HistoryPoint[] => {
  if (!existsSync(HISTORY_FILE)) return [];
  try {
    const arr = JSON.parse(readFileSync(HISTORY_FILE, 'utf8')) as HistoryPoint[];
    // legacy points predate the `fits` flag; they only ever recorded the fitting series.
    return arr.map((p) => ({ ...p, fits: p.fits ?? true }));
  } catch {
    return [];
  }
};
// append best-per-curve points, deduped per (curve, fits) so each curve+series forms its
// own independent line against that track's most recent point.
type Best = { score: number; id: string; steps: number; curve: string; fits: boolean };
const recordHistory = (bests: Best[], curveOfId: (id: string) => string, t: string): HistoryPoint[] => {
  const series = loadHistory();
  let changed = false;
  for (const best of bests) {
    let last: HistoryPoint | undefined;
    for (let i = series.length - 1; i >= 0; i--) {
      if (series[i].fits === best.fits && curveOfId(series[i].id) === best.curve) { last = series[i]; break; }
    }
    if (last === undefined || last.score !== best.score) {
      series.push({ t, score: best.score, id: best.id, steps: best.steps, fits: best.fits });
      changed = true;
    }
  }
  if (changed) writeFileSync(HISTORY_FILE, JSON.stringify(series, null, 2) + '\n');
  return series;
};

type Category = 'full' | 'partial' | 'demo';

// Entries the harness still benchmarks (e.g. for the normalized vs-sCrypt op-cost
// comparison) but the website should not list. bch-vkx-scalarmult is a single
// scalarMult sub-step on the old EC codegen — a fraction of vk_x, so it muddies the
// monolith-vs-chunked milestone story.
const SITE_EXCLUDE = new Set(['bch-vkx-scalarmult']);

const categoryOf = (r: BenchmarkResult): Category => {
  if (r.impl.demo === true) return 'demo';
  return r.impl.proofSystem === 'Groth16' ? 'full' : 'partial';
};

// The real BCH blockers, computed independently (the benchmark records only the
// FIRST failing reason, but nchain/scrypt trip both walls). script-size: any
// step's locking OR unlocking exceeds the 10,000-byte cap. op-cost: the heaviest
// step needs more than one standard input's budget.
const bchCell = (r: BenchmarkResult) => {
  const scriptSize = r.steps.some((s) => s.lockingBytes > SIZE_CAP || s.unlockingBytes > SIZE_CAP);
  const opCost = r.inputsForHeaviestStep > 1;
  const blockers = [...(scriptSize ? ['script-size'] : []), ...(opCost ? ['op-cost'] : [])];
  const overByBytes = r.steps.filter((s) => s.lockingBytes > SIZE_CAP || s.unlockingBytes > SIZE_CAP).length;
  const detail = r.bchCompatible
    ? 'every step fits BCH per-tx limits'
    : [
        scriptSize ? `${overByBytes}/${r.stepCount} step(s) over the ${SIZE_CAP.toLocaleString('en-US')} B script cap` : null,
        opCost ? `heaviest step ~${r.inputsForHeaviestStep}× one input's op-cost budget` : null,
      ]
        .filter(Boolean)
        .join('; ');
  return { compatible: r.bchCompatible, blockers, detail };
};

const isBsvSeed = (r: BenchmarkResult): boolean =>
  r.impl.reference === true || /BSV mainnet/.test(r.impl.source);

const entryOf = (r: BenchmarkResult) => ({
  id: r.impl.id,
  name: r.impl.name,
  category: categoryOf(r),
  official: isBsvSeed(r), // seeded baseline, not a community submission
  solver: isBsvSeed(r) ? { handle: r.impl.id, model: null, official: true } : null,
  curve: r.impl.field,
  structure: r.impl.structure,
  proofSystem: r.impl.proofSystem,
  // headline score = full on-chain footprint (lower is better): the verifier scripts PLUS
  // the serialized transaction overhead (envelope + outpoints + CashToken prefixes + varints).
  // Folding tx overhead in makes structures comparable — a covenant chain pays it once PER
  // STEP (its real recurring cost), a single-tx verifier pays it once. `size` breaks it down.
  score: r.totalBytes + r.totalTxOverheadBytes,
  size: {
    scriptBytes: r.totalBytes,
    txOverheadBytes: r.totalTxOverheadBytes,
    transactions: r.txCount,
    total: r.totalBytes + r.totalTxOverheadBytes,
  },
  // dead-weight zero-padding: bytes appended to unlockings purely to buy op-cost budget,
  // and their share of the SCRIPT bytes. A big slice of the chunking overhead; 0 for unpadded
  // singletons (proof in the witness, no covenant padding).
  padding: { bytes: r.totalPadBytes, fraction: r.totalBytes > 0 ? r.totalPadBytes / r.totalBytes : 0 },
  // op-cost benchmarks, keyed by the PROOF SCENARIO actually RUN. Even though the
  // chunked covenant lockings are now worst-case SIZED (the fixed step graph can
  // verify ANY public input < r), the measured op-cost still depends on the specific
  // proof executed: a sparse/small input skips most doublings+adds, a dense full-width
  // input pays for all of them. So one number is misleading — we key by the proof run.
  // 'smallProof' is the committed small public inputs the vectors ship with; a
  // 'worstCase' run (dense, near-r inputs through the SAME lockings) is added per entry
  // as those vectors land. For proof-size-INDEPENDENT entries (singletons, baselines)
  // worstCase ~matches smallProof; for chunked covenants it jumps ~5-6×, which the two
  // keys make visible side by side.
  benchmarks: {
    smallProof: {
      opCost: r.totalOperationCost,
      steps: r.stepCount,
      heaviestStepOpCost: r.maxStepOperationCost,
      inputsForHeaviestStep: r.inputsForHeaviestStep,
    },
    ...(r.worstCase
      ? {
          worstCase: {
            opCost: r.worstCase.totalOperationCost,
            steps: r.worstCase.stepCount,
            heaviestStepOpCost: r.worstCase.maxStepOperationCost,
            inputsForHeaviestStep: r.worstCase.inputsForHeaviestStep,
          },
        }
      : {}),
  },
  // BSV prior art: a single huge transaction that is correct but does not fit BCH.
  // Only the seeded BSV verifiers carry this framing (not BCH-native sub-steps).
  bsvSingleton: isBsvSeed(r) && r.impl.structure === 'single-tx' && r.validPassed && !r.bchCompatible,
  // correctness was judged under BSV's post-Genesis OP_RETURN-terminator rule, which
  // BCH treats as failure (so the success case is scored differently per chain)
  bsvOpReturn: r.bsvOpReturn,
  bch: bchCell(r),
  // proof-generality: does ONE deployed program verify many proofs (runtime-general)
  // or just the one it was built for (instance-specific)? Empirically confirmed where
  // extra proofs were run (proofsTested > 1).
  generality: {
    binding: r.proofBinding, // 'runtime' | 'baked'
    runtimeGeneral: r.runtimeGeneral,
    proofsTested: r.proofsTested,
    proofsPassed: r.proofsPassed,
    detail:
      r.proofBinding === 'baked'
        ? 'instance-specific: the proof is baked into the program; a different proof needs it regenerated'
        : r.proofsTested >= 2
          ? `runtime-general: one fixed locking verifies ${r.proofsPassed}/${r.proofsTested} distinct proofs (proof in the unlocking witness)`
          : 'runtime-general by construction: proof supplied in the unlocking witness (1 reference proof available)',
  },
  // token-threading covenant safety (only meaningful for covenant entries): does the
  // covenant pin the carried token (category continuity + capability) so the threaded
  // state cannot be swapped/forged? null when the entry does not thread a token.
  tokenSafety: r.tokenThreaded
    ? {
        threaded: true,
        enforced: r.tokenSafetyEnforced === true,
        detail:
          r.tokenSafetyEnforced === true
            ? 'covenant pins category + capability and perpetuates the commitment'
            : 'state threaded through the NFT commitment, but category continuity / capability are NOT enforced — a real deployment must pin a fixed category with a perpetuated mutable commitment (or mint a fresh immutable token each step)',
      }
    : null,
  // EIP-197 input validation: does the verifier reject structurally-invalid points
  // (off-curve, or G2 off the order-r subgroup) before pairing them? Empirically
  // confirmed by running adversarial-point inputs (Scenario.invalidInputs).
  inputValidation: {
    enforced: r.inputValidation.enforced,
    tested: r.inputValidation.tested,
    rejected: r.inputValidation.rejected,
    detail:
      r.inputValidation.tested === 0
        ? 'not exercised — no adversarial-point inputs provided for this entry'
        : r.inputValidation.enforced
          ? `on-curve + G2-subgroup checks enforced: ${r.inputValidation.rejected}/${r.inputValidation.tested} adversarial points (off-curve / off-subgroup) rejected`
          : `NOT enforced: only ${r.inputValidation.rejected}/${r.inputValidation.tested} adversarial points rejected — raw points reach the pairing`,
  },
  source: r.impl.source,
});

type Entry = ReturnType<typeof entryOf>;

const anchor = (e: Entry | undefined, label: string) =>
  e === undefined
    ? null
    : { id: e.id, label, curve: e.curve, bytes: e.score, bchCompatible: e.bch.compatible };

const main = async () => {
  const outfile = process.argv[2] ?? 'results.json';
  // include demos so the artifact is complete; the site filters by category.
  const results = await computeResults(true);
  const entries = results.map(entryOf).filter((e) => !SITE_EXCLUDE.has(e.id));

  const byId = (id: string) => entries.find((e) => e.id === id);
  const full = entries.filter((e) => e.category === 'full');
  // current best GENUINE BCH-native verifier (none yet -> null): fits the per-tx limits
  // AND verifies any proof at runtime. Instance-specific (baked) artifacts fit but are
  // excluded, so neither the frontier "current" nor the score-history records them.
  const bestBchNative = full
    .filter((e) => e.bch.compatible && e.generality.runtimeGeneral)
    .sort((a, b) => a.score - b.score)[0];
  // smallest BCH-native (non-baseline) full verifier: the current frontier leader,
  // whether or not it already fits BCH per-tx limits
  const leader = full
    .filter((e) => !e.official)
    .sort((a, b) => a.score - b.score)[0];

  // accumulate the score-history time-series, per curve so each curve draws its own line.
  // Two series: the best FITTING (BCH-native) verifier, and the smallest NON-fitting
  // singleton (the single-tx ideal that busts the limits) — their gap is the chunking tax.
  const generatedAt = new Date().toISOString();
  const curveOfId = (id: string): string => entries.find((e) => e.id === id)?.curve ?? 'BN254';
  const curvesPresent = [...new Set(full.map((e) => e.curve))];
  const smallestPerCurve = (pred: (e: Entry) => boolean, fits: boolean): Best[] =>
    curvesPresent
      .map((c) => full.filter((e) => e.curve === c && pred(e)).sort((a, b) => a.score - b.score)[0])
      .filter((e): e is Entry => e !== undefined)
      .map((e) => ({ score: e.score, id: e.id, steps: e.benchmarks.smallProof.steps, curve: e.curve, fits }));

  const history = recordHistory(
    [
      ...smallestPerCurve((e) => e.bch.compatible && e.generality.runtimeGeneral, true),
      ...smallestPerCurve((e) => !e.official && !e.bch.compatible, false),
    ],
    curveOfId,
    generatedAt,
  );

  const artifact = {
    schema: SCHEMA_VERSION,
    generatedAt,
    statement: {
      proofSystem: 'Groth16',
      // the competition's pinned BN254 target (same curve as the BCH-native work)
      curve: 'BN254',
      note: 'Cross-curve totals are indicative, not apples-to-apples; filter by curve to compare.',
    },
    frontier: {
      // BSV prior art: works as one huge singleton tx, fails BCH limits
      scrypt: anchor(byId('scrypt-bn256'), 'BSV sCrypt · BN254 · huge singleton · ✗ BCH'),
      nchain: anchor(byId('nchain'), 'BSV nChain · BLS12-381 · huge singleton · ✗ BCH'),
      // the wall every BCH submission must get under (per transaction)
      bchPerTxCap: { label: 'BCH per-tx script cap', bytes: SIZE_CAP },
      // smallest BCH-native full verifier so far (the frontier leader)
      leader: leader === undefined ? null : anchor(leader, 'BCH-native full verifier'),
      // best full verifier that fits BCH, or null while the slot is open
      current: bestBchNative === undefined ? null : anchor(bestBchNative, 'Best BCH-native full verifier'),
    },
    history,
    entries,
  };

  writeFileSync(outfile, JSON.stringify(artifact, null, 2) + '\n');
  const counts = entries.reduce<Record<string, number>>((a, e) => ((a[e.category] = (a[e.category] ?? 0) + 1), a), {});
  console.log(`wrote ${outfile}: ${entries.length} entries (${JSON.stringify(counts)})`);
};

await main();
