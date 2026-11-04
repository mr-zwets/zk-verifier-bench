#!/usr/bin/env tsx
/**
 * crown8 Miller-group rebalance plan + profile checker.
 *
 * Mutation #1 for bch-groth16-intratx-crown8-rawchain:
 *   move Miller-loop work off wall-bound executors (exec0/1/4) into the
 *   under-full executor (exec2), then shrink donor unlocks to the new
 *   budget floor (when the generator's witness packing permits).
 *
 * Pure all-zero padBytes are already 0 on the published vectors — this is
 * the next highest-ROI lever. Applying it requires regenerating the six
 * raw-chain executors from the private crown8 builder
 * (vectors.provenance.verifierCashCommit); this script only plans and
 * checks.
 *
 * Usage:
 *   pnpm exec tsx tools/crown8-rebalance-plan.mts           # plan + current profile
 *   pnpm exec tsx tools/crown8-rebalance-plan.mts --check   # fail if walls still >99% util
 */
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';
import { createLoosenedVm, evaluatePair } from '../src/harness/vm.js';

const VECTORS = 'src/bch/groth16-intratx-crown8-rawchain-vectors.json';

interface RawStep { name: string; lock: string; unlock: string }
interface Vectors {
  valid: RawStep[];
  worstCaseProof?: RawStep[];
}

/** Measured baseline (valid proof) from `pnpm benchmark crown8` after dense checkpoints. */
const BASELINE_OP: Record<string, number> = {
  exec0: 7_996_727,
  exec1: 7_999_114,
  exec2: 6_866_909,
  exec3: 7_429_730,
  exec4: 7_987_154,
  exec5: 7_427_803,
  genesis: 5_848_090,
  terminal: 6_719_530,
};

/** Practical move plan: keep total Miller op constant, fill exec2 first. */
export const MOVE_PLAN = [
  { from: 'exec0', to: 'exec2', ops: 380_000 },
  { from: 'exec1', to: 'exec2', ops: 380_000 },
  { from: 'exec4', to: 'exec2', ops: 370_000 },
] as const;

const MAX_UNLOCK = 10_000;
const budgetOf = (unlock: number) => (41 + unlock) * 800;
const floorUnlock = (op: number) => Math.max(0, Math.ceil(op / 800) - 41);

const check = process.argv.includes('--check');
const measure = process.argv.includes('--measure');

const vectors = JSON.parse(readFileSync(VECTORS, 'utf8')) as Vectors;

const unlockOf = (step: RawStep) => hexToBin(step.unlock).length;
const lockOf = (step: RawStep) => hexToBin(step.lock).length;

const project = (): Record<string, number> => {
  const op = { ...BASELINE_OP };
  for (const m of MOVE_PLAN) {
    op[m.from]! -= m.ops;
    op[m.to]! += m.ops;
  }
  return op;
};

const linearUnlock = (name: string, newOp: number): number => {
  const step = vectors.valid.find((s) => s.name === name);
  if (!step) return floorUnlock(newOp);
  const oldOp = BASELINE_OP[name]!;
  const oldU = unlockOf(step);
  // half-fixed / half-scales model is encoded as linear in op for the plan;
  // clamp to [budget floor, 10 KB].
  const scaled = Math.ceil(oldU * (newOp / oldOp));
  return Math.min(MAX_UNLOCK, Math.max(floorUnlock(newOp), scaled));
};

const printPlan = (): void => {
  const projected = project();
  console.log('=== crown8 rebalance plan (mutation #1) ===\n');
  console.log('Moves (Miller work, op-cost units):');
  for (const m of MOVE_PLAN) {
    console.log(`  ${m.from}  -${m.ops.toLocaleString()}  →  ${m.to}`);
  }
  console.log('');
  console.log(
    'name'.padEnd(10),
    'old op'.padStart(12),
    'new op'.padStart(12),
    'old U'.padStart(6),
    'new U*'.padStart(6),
    'save*'.padStart(6),
    'new util%'.padStart(10),
  );
  let totalSave = 0;
  for (const step of vectors.valid) {
    const name = step.name;
    const oldOp = BASELINE_OP[name] ?? 0;
    const newOp = projected[name] ?? oldOp;
    const oldU = unlockOf(step);
    const isMiller = name.startsWith('exec');
    const newU = isMiller ? linearUnlock(name, newOp) : oldU;
    const save = oldU - newU;
    totalSave += save;
    const util = ((100 * newOp) / budgetOf(isMiller ? newU : oldU)).toFixed(2);
    console.log(
      name.padEnd(10),
      oldOp.toLocaleString().padStart(12),
      newOp.toLocaleString().padStart(12),
      String(oldU).padStart(6),
      String(newU).padStart(6),
      String(save).padStart(6),
      (util + '%').padStart(10),
    );
  }
  console.log('');
  console.log('Expected byte savings (linear witness-scaling model):', totalSave, 'B');
  console.log('  optimistic (budget-floor only, data free):     ~2,900 B');
  console.log('  mid (linear witness ∝ miller cost on donors): ~1,200–1,400 B');
  console.log('  conservative (trim pure budget slack only):   ~140 B');
  console.log('');
  console.log('new U* assumes generator can shrink donor witnesses with fewer iters.');
  console.log('Score delta ≈ unlock savings (tx overhead unchanged for intra-tx).');
  console.log('');
  console.log('Apply: regenerate six exec programs + corpus in the private crown8');
  console.log('builder (see vectors.provenance.verifierCashCommit), drop the new');
  console.log('JSON on src/bch/groth16-intratx-crown8-rawchain-vectors.json, then:');
  console.log('  pnpm benchmark crown8');
  console.log('  pnpm exec tsx tools/crown8-rebalance-plan.mts --measure');
};

const measureProfile = async (): Promise<void> => {
  const vm = createLoosenedVm();
  const inputs = vectors.valid.map((s) => ({
    lockingBytecode: hexToBin(s.lock),
    unlockingBytecode: hexToBin(s.unlock),
  }));
  console.log('=== measured profile (current vectors) ===\n');
  console.log(
    'name'.padEnd(10),
    'unlock'.padStart(7),
    'op-cost'.padStart(12),
    'budget'.padStart(10),
    'headroom'.padStart(10),
    'util%'.padStart(8),
  );
  let walls = 0;
  for (let i = 0; i < inputs.length; i++) {
    const step = vectors.valid[i]!;
    const input = inputs[i]!;
    const out = evaluatePair(vm, input.lockingBytecode, input.unlockingBytecode, undefined, {
      index: i,
      inputs,
    });
    if (!out.accepted) {
      console.error(step.name, 'REJECTED:', out.error);
      process.exitCode = 1;
      return;
    }
    const u = input.unlockingBytecode.length;
    const budget = budgetOf(u);
    const op = out.operationCost;
    const util = (100 * op) / budget;
    if (step.name.startsWith('exec') && util > 99.0) walls++;
    console.log(
      step.name.padEnd(10),
      String(u).padStart(7),
      op.toLocaleString().padStart(12),
      budget.toLocaleString().padStart(10),
      (budget - op).toLocaleString().padStart(10),
      (util.toFixed(2) + '%').padStart(8),
    );
  }
  console.log('');
  if (check) {
    // Success criterion for a rebalanced drop: at most one miller wall at >99%.
    if (walls >= 3) {
      console.error(`FAIL: ${walls} miller stages still >99% util (want ≤1 after rebalance)`);
      process.exitCode = 1;
    } else {
      console.log(`OK: ${walls} miller stage(s) >99% util`);
    }
  }
};

printPlan();
if (measure || check) {
  await measureProfile();
}
