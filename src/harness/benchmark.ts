// Benchmark harness. For each registered implementation (single- or multi-tx):
//   1. correctness   - the valid run is fully ACCEPTED; invalid runs are REJECTED
//   2. size + op-cost - per-step and aggregate, on the BCH 2026 VM (limits loosened)
//   3. budget fit     - does each step fit one standard BCH input's op-cost budget?
// Results are grouped into separate leaderboards by (proofSystem, structure).
// Correctness gates the cost numbers.
import { bchMultistepDemo } from '../implementations/bch-multistep-demo.js';
import { nchain } from '../implementations/nchain.js';
import { scryptBn256 } from '../implementations/scrypt-bn256.js';

import { tamperProof } from './tamper.js';
import type { BenchmarkResult, Implementation, Step, StepMetrics } from './types.js';
import { createLoosenedVm, createRealVm, evaluatePair, standardInputBudget, type Bch2026Vm } from './vm.js';

/** Map a real-VM limit error to a short tag for the table. */
const limitReason = (error: string): string => {
  const e = error.toLowerCase();
  if (e.includes('bytecode length')) return 'script-size';
  if (e.includes('operation cost')) return 'op-cost';
  if (e.includes('stack depth')) return 'stack-depth';
  if (e.includes('hash')) return 'hashing';
  if (e.includes('number')) return 'num-length';
  if (e.includes('stack item') || e.includes('element')) return 'item-size';
  if (e.includes('signature')) return 'sigchecks';
  return 'limit';
};

const REGISTRY: Implementation[] = [nchain, scryptBn256, bchMultistepDemo];

const runStep = (vm: Bch2026Vm, step: Step, bsv: boolean): StepMetrics => {
  const o = evaluatePair(vm, step.lockingBytecode, step.unlockingBytecode);
  return {
    label: step.label,
    lockingBytes: step.lockingBytecode.length,
    unlockingBytes: step.unlockingBytecode.length,
    operationCost: o.operationCost,
    instructionCount: o.instructionCount,
    accepted: bsv ? o.bsvAccepted : o.accepted,
    error: o.error,
  };
};

/** A run is rejected if at least one of its steps does not accept. */
const runRejects = (vm: Bch2026Vm, run: Step[], bsv: boolean): boolean =>
  run.some((s) => {
    const o = evaluatePair(vm, s.lockingBytecode, s.unlockingBytecode);
    return !(bsv ? o.bsvAccepted : o.accepted);
  });

const tryTamper = (witness: Uint8Array): Uint8Array | undefined => {
  try {
    return tamperProof(witness);
  } catch {
    return undefined; // no data push to tamper
  }
};

const SCRIPT_SIZE_CAP = 10_000; // BCH maximumBytecodeLength (per locking/unlocking script)

const benchmark = (impl: Implementation, scenario: Awaited<ReturnType<Implementation['load']>>): BenchmarkResult => {
  // Profile-only: size-decidable, not executed (e.g. tx-introspection covenants
  // we cannot drive in a synthetic context). BCH compat == every script fits the cap.
  if (scenario.profileOnly) {
    const steps: StepMetrics[] = scenario.valid.map((s) => ({
      label: s.label,
      lockingBytes: s.lockingBytecode.length,
      unlockingBytes: s.unlockingBytecode.length,
      operationCost: 0,
      instructionCount: 0,
      accepted: false,
      error: undefined,
    }));
    const oversize = steps.filter((s) => s.lockingBytes > SCRIPT_SIZE_CAP || s.unlockingBytes > SCRIPT_SIZE_CAP).length;
    return {
      impl, profileOnly: true, checked: false, validPassed: false,
      invalidRejected: 0, invalidTotal: 0, pass: false, bsvOpReturn: false, steps,
      checkpointStats: [],
      stepCount: steps.length,
      totalBytes: steps.reduce((a, s) => a + s.lockingBytes + s.unlockingBytes, 0),
      totalOperationCost: 0, maxStepOperationCost: 0,
      fitsStandardBudget: false, inputsForHeaviestStep: 0,
      bchCompatible: oversize === 0,
      bchIncompatibleReason: oversize > 0 ? `script-size: ${oversize}/${steps.length} steps over ${SCRIPT_SIZE_CAP / 1000}KB` : undefined,
    };
  }

  const bsv = scenario.bsvOpReturnTerminator === true;
  const vm = createLoosenedVm();
  const steps = scenario.valid.map((s) => runStep(vm, s, bsv));
  const validPassed = steps.every((s) => s.accepted);

  // cumulative op-cost + bytes to reach each named checkpoint (in-between metrics)
  const checkpointStats: BenchmarkResult['checkpointStats'] = [];
  let cumOp = 0;
  let cumBytes = 0;
  steps.forEach((sm, i) => {
    cumOp += sm.operationCost;
    cumBytes += sm.lockingBytes + sm.unlockingBytes;
    const label = scenario.valid[i]!.checkpoint;
    if (label !== undefined) {
      checkpointStats.push({ label, atStep: i + 1, cumulativeOpCost: cumOp, cumulativeBytes: cumBytes });
    }
  });

  // BCH compatibility: replay the valid run on the REAL BCH 2026 VM (consensus limits).
  const realVm = createRealVm();
  const realOutcomes = scenario.valid.map((s) => evaluatePair(realVm, s.lockingBytecode, s.unlockingBytecode));
  const firstFail = realOutcomes.find((o) => !o.accepted);
  const bchCompatible = firstFail === undefined && validPassed;
  const bchIncompatibleReason = firstFail?.error === undefined ? undefined : limitReason(firstFail.error);

  // invalid runs: explicit, else derived by tampering each step's witness in turn
  const invalidRuns: Step[][] =
    scenario.invalid ??
    (scenario.tamperable
      ? scenario.valid.flatMap((_, idx) => {
          const t = tryTamper(scenario.valid[idx]!.unlockingBytecode);
          if (t === undefined) return [];
          return [scenario.valid.map((s, j) => (j === idx ? { ...s, unlockingBytecode: t } : s))];
        })
      : []);
  const invalidRejected = invalidRuns.filter((run) => runRejects(vm, run, bsv)).length;

  const opCosts = steps.map((s) => s.operationCost);
  const maxStepOperationCost = opCosts.length ? Math.max(...opCosts) : 0;
  const budget = standardInputBudget();
  return {
    impl,
    profileOnly: false,
    checked: invalidRuns.length > 0,
    validPassed,
    invalidRejected,
    invalidTotal: invalidRuns.length,
    pass: validPassed && invalidRuns.length > 0 && invalidRejected === invalidRuns.length,
    bsvOpReturn: bsv,
    steps,
    checkpointStats,
    stepCount: steps.length,
    totalBytes: steps.reduce((a, s) => a + s.lockingBytes + s.unlockingBytes, 0),
    totalOperationCost: opCosts.reduce((a, b) => a + b, 0),
    maxStepOperationCost,
    fitsStandardBudget: steps.every((s) => s.operationCost <= budget),
    inputsForHeaviestStep: Math.ceil(maxStepOperationCost / budget),
    bchCompatible,
    bchIncompatibleReason,
  };
};

const fmt = (n: number) => n.toLocaleString();
const padR = (s: string, w: number) => s.padEnd(w);
const padL = (s: string, w: number) => s.padStart(w);

const main = async () => {
  console.log(`benchmarking ${REGISTRY.length} implementation(s) on the BCH 2026 VM (limits loosened)\n`);
  const results: BenchmarkResult[] = [];
  for (const impl of REGISTRY) {
    process.stdout.write(`- ${impl.id} ... `);
    try {
      const scenario = await impl.load();
      const r = benchmark(impl, scenario);
      results.push(r);
      console.log(r.profileOnly ? 'profile-only (size)' : r.pass ? 'PASS' : r.validPassed ? 'valid-only (no reject test)' : 'FAIL');
    } catch (e) {
      console.log(`ERROR: ${(e as Error).message}`);
    }
  }

  // group into separate leaderboards by proof system + structure
  const tracks = new Map<string, BenchmarkResult[]>();
  for (const r of results) {
    const key = `${r.impl.proofSystem}  [${r.impl.structure}]`;
    (tracks.get(key) ?? tracks.set(key, []).get(key)!).push(r);
  }

  const cols = (c: string[]) => [
    padR(c[0]!, 22), padR(c[1]!, 11), padR(c[2]!, 28),
    padL(c[3]!, 6), padL(c[4]!, 12), padL(c[5]!, 14), padL(c[6]!, 15), padR(c[7]!, 16),
  ].join(' ');
  const header = cols(['implementation', 'field', 'correctness', 'steps', 'total B', 'total op-cost', 'max/step cost', 'BCH compatible']);

  for (const [track, rs] of tracks) {
    console.log(`\n### ${track}`);
    console.log(header);
    console.log('-'.repeat(header.length));
    for (const r of rs) {
      const correctness = r.profileOnly
        ? 'profile (size)'
        : r.pass
          ? `PASS (${r.invalidRejected}/${r.invalidTotal}✗${r.bsvOpReturn ? ', BSV OP_RETURN' : ''})`
          : r.validPassed
            ? 'valid-only'
            : 'FAIL';
      const compat = r.bchCompatible
        ? 'yes'
        : r.profileOnly
          ? `no (${r.bchIncompatibleReason ?? 'script-size'})`
          : `no (${r.bchIncompatibleReason ?? 'limit'}; ~${r.inputsForHeaviestStep} steps by op-cost)`;
      console.log(cols([
        r.impl.id, r.impl.field, correctness,
        String(r.stepCount), fmt(r.totalBytes),
        r.profileOnly ? '-' : fmt(r.totalOperationCost),
        r.profileOnly ? '-' : fmt(r.maxStepOperationCost), compat,
      ]));
      for (const c of r.checkpointStats) {
        console.log(`    > reach "${c.label}" @ step ${c.atStep}: ${fmt(c.cumulativeOpCost)} op-cost, ${fmt(c.cumulativeBytes)} B`);
      }
    }
  }

  console.log(`\nBCH compatible = every step of the valid run validates on the REAL BCH 2026 VM (consensus limits, non-standard).`);
  console.log(`"no (reason; ~N steps by op-cost)" = the heaviest step breaks that consensus limit (reason) and, by op-cost alone, would need ~N standard inputs (budget ${fmt(standardInputBudget())}).`);
};

await main();
