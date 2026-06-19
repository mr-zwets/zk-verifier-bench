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

// Accumulating time-series of the best BCH-native (fitting) full verifier, for the
// score-history chart. Committed and appended to whenever that best score changes.
const HISTORY_FILE = 'score-history.json';
interface HistoryPoint { t: string; score: number; id: string; steps: number }
const loadHistory = (): HistoryPoint[] => {
  if (!existsSync(HISTORY_FILE)) return [];
  try {
    return JSON.parse(readFileSync(HISTORY_FILE, 'utf8')) as HistoryPoint[];
  } catch {
    return [];
  }
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
  // headline score = total on-chain bytes (lower is better)
  score: r.totalBytes,
  // secondary metrics (shown on hover / row expand)
  secondary: {
    opCost: r.totalOperationCost,
    steps: r.stepCount,
    heaviestStepOpCost: r.maxStepOperationCost,
    inputsForHeaviestStep: r.inputsForHeaviestStep,
  },
  // BSV prior art: a single huge transaction that is correct but does not fit BCH.
  // Only the seeded BSV verifiers carry this framing (not BCH-native sub-steps).
  bsvSingleton: isBsvSeed(r) && r.impl.structure === 'single-tx' && r.validPassed && !r.bchCompatible,
  // correctness was judged under BSV's post-Genesis OP_RETURN-terminator rule, which
  // BCH treats as failure (so the success case is scored differently per chain)
  bsvOpReturn: r.bsvOpReturn,
  bch: bchCell(r),
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
  // current best full verifier that actually runs on BCH (none yet -> null)
  const bestBchNative = full
    .filter((e) => e.bch.compatible)
    .sort((a, b) => a.score - b.score)[0];
  // smallest BCH-native (non-baseline) full verifier: the current frontier leader,
  // whether or not it already fits BCH per-tx limits
  const leader = full
    .filter((e) => !e.official)
    .sort((a, b) => a.score - b.score)[0];

  // accumulate the score-history time-series: append a point when the best fitting
  // verifier's score changes (deduped against the last recorded score).
  const generatedAt = new Date().toISOString();
  const history = loadHistory();
  if (bestBchNative !== undefined) {
    const last = history[history.length - 1];
    if (last === undefined || last.score !== bestBchNative.score) {
      history.push({ t: generatedAt, score: bestBchNative.score, id: bestBchNative.id, steps: bestBchNative.secondary.steps });
      writeFileSync(HISTORY_FILE, JSON.stringify(history, null, 2) + '\n');
    }
  }

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
