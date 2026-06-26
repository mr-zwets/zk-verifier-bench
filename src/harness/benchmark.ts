// Benchmark harness. For each registered implementation (single- or multi-tx):
//   1. correctness   - the valid run is fully ACCEPTED; invalid runs are REJECTED
//   2. size + op-cost - per-step and aggregate, on the BCH 2026 VM (limits loosened)
//   3. budget fit     - does each step fit one standard BCH input's op-cost budget?
// Results are grouped into separate leaderboards by (proofSystem, structure).
// Correctness gates the cost numbers.
import { bchGroth16Bls12381Chunked } from '../implementations/bch-groth16-bls12381-chunked.js';
import { bchGroth16Bls12381ChunkedCovenant } from '../implementations/bch-groth16-bls12381-chunked-covenant.js';
import { bchGroth16Bls12381ChunkedCovenantResidue } from '../implementations/bch-groth16-bls12381-chunked-covenant-residue.js';
import { bchGroth16Bls12381Singleton } from '../implementations/bch-groth16-bls12381-singleton.js';
import { bchGroth16Chunked } from '../implementations/bch-groth16-chunked.js';
import { bchGroth16ChunkedCovenant } from '../implementations/bch-groth16-chunked-covenant.js';
import { bchGroth16ChunkedCovenantResidue } from '../implementations/bch-groth16-chunked-covenant-residue.js';
import { bchGroth16Singleton } from '../implementations/bch-groth16-singleton.js';
import { bchMultistepDemo } from '../implementations/bch-multistep-demo.js';
import { bchPairingBls12381Chunked } from '../implementations/bch-pairing-bls12381-chunked.js';
import { bchPairingBls12381Singleton } from '../implementations/bch-pairing-bls12381-singleton.js';
import { bchPairingChunked } from '../implementations/bch-pairing-chunked.js';
import { bchPairingIntratx } from '../implementations/bch-pairing-intratx.js';
import { bchGroth16Intratx } from '../implementations/bch-groth16-intratx.js';
import { bchGroth16IntratxResidue } from '../implementations/bch-groth16-intratx-residue.js';
import { bchGroth16Grouped } from '../implementations/bch-groth16-grouped.js';
import { bchGroth16GroupedResidue } from '../implementations/bch-groth16-grouped-residue.js';
import { bchGroth16Bls12381Grouped } from '../implementations/bch-groth16-bls12381-grouped.js';
import { bchPairingBls12381Intratx } from '../implementations/bch-pairing-bls12381-intratx.js';
import { bchGroth16Bls12381Intratx } from '../implementations/bch-groth16-bls12381-intratx.js';
import { bchPairingSingleton } from '../implementations/bch-pairing-singleton.js';
import { bchVkxBls12381ChunkedCovenant } from '../implementations/bch-vkx-bls12381-chunked-covenant.js';
import { bchVkxChunkedCovenant } from '../implementations/bch-vkx-chunked-covenant.js';
import { bchVkxChunkedShamir } from '../implementations/bch-vkx-chunked-shamir.js';
import { bchVkxChunkedTwoloop } from '../implementations/bch-vkx-chunked-twoloop.js';
import { bchVkxBls12381Singleton } from '../implementations/bch-vkx-bls12381-singleton.js';
import { bchVkxScalarmult } from '../implementations/bch-vkx-scalarmult.js';
import { bchVkxSingleton } from '../implementations/bch-vkx-singleton.js';
import { nchain } from '../implementations/nchain.js';
import { scryptBn256 } from '../implementations/scrypt-bn256.js';

import { pathToFileURL } from 'node:url';

import { authenticationInstructionIsMalformed, decodeAuthenticationInstructions, encodeAuthenticationInstruction } from '@bitauth/libauth';

import { tamperProof } from './tamper.js';
import type { BenchmarkResult, Implementation, Step, StepMetrics } from './types.js';
import {
  createLoosenedVm,
  createRealVm,
  createStandardVm,
  evaluatePair,
  isP2sh20Locking,
  standardInputBudget,
  MAX_STANDARD_LOCKING_BYTECODE,
  MAX_STANDARD_UNLOCKING_BYTECODE,
  MAX_STANDARD_TRANSACTION_SIZE,
  type Bch2026Vm,
} from './vm.js';

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

export const REGISTRY: Implementation[] = [nchain, scryptBn256, bchGroth16Singleton, bchGroth16Bls12381Singleton, bchGroth16Chunked, bchGroth16ChunkedCovenant, bchGroth16ChunkedCovenantResidue, bchVkxScalarmult, bchVkxSingleton, bchVkxBls12381Singleton, bchVkxChunkedTwoloop, bchVkxChunkedShamir, bchVkxChunkedCovenant, bchVkxBls12381ChunkedCovenant, bchPairingSingleton, bchPairingBls12381Singleton, bchPairingChunked, bchPairingBls12381Chunked, bchGroth16Bls12381Chunked, bchGroth16Bls12381ChunkedCovenant, bchGroth16Bls12381ChunkedCovenantResidue, bchPairingIntratx, bchGroth16Intratx, bchGroth16IntratxResidue, bchGroth16Grouped, bchGroth16GroupedResidue, bchPairingBls12381Intratx, bchGroth16Bls12381Intratx, bchGroth16Bls12381Grouped, bchMultistepDemo];

// Zero-padding accounting: the chunked/intra-tx steps append one big all-zero push to each
// unlocking purely to buy op-cost budget ((41+len)*800). Its full encoded length (push
// opcode + data) is dead weight. The pad's POSITION varies by deployment:
//   - bare scripts (shamir, twoloop, bls12-381 covenant) put the pad LAST;
//   - P2SH deployments (pairing/groth16 chunked + intra-tx) push the redeem script LAST, so
//     the pad sits BEFORE it (second-to-last) — an earlier "trailing-instruction-only" check
//     missed these entirely and reported 0 padding for ~all P2SH vectors.
// So we sum every NON-EMPTY all-zero data push wherever it sits. This is unambiguous: VM
// numbers are minimally encoded, so a real arg of value 0 is OP_0 (empty data, skipped), and
// no genuine arg/blob/redeem push is all-zero with length >= 1. Returns 0 for unpadded steps
// (e.g. singletons, whose pushes are real proof limbs). Uses libauth to parse the script.
const zeroPadBytes = (script: Uint8Array): number => {
  let total = 0;
  for (const ins of decodeAuthenticationInstructions(script)) {
    if (authenticationInstructionIsMalformed(ins) || !('data' in ins)) continue;
    const data = ins.data as Uint8Array;
    if (data.length === 0 || data.some((b) => b !== 0)) continue;
    total += encodeAuthenticationInstruction(ins).length;
  }
  return total;
};

const varintLen = (n: number): number => (n < 0xfd ? 1 : n <= 0xffff ? 3 : n <= 0xffffffff ? 5 : 9);
const TXN_ENVELOPE = 4 /* version */ + 4 /* locktime */;
const INPUT_FIXED = 36 /* outpoint */ + 4 /* sequence */;

// Serialized transaction overhead this step adds that the script-byte total does NOT
// already count (locking + unlocking are counted separately). Folded into the score so
// the comparison is fair across structures: a single-tx verifier pays one tx's overhead,
// a covenant chain pays it per step (its real recurring cost). Models:
//   - covenant step  -> its own 1-in/1-out token tx; includes the CashToken output prefix
//     (category + NFT commitment carrying the threaded state); EXCLUDES the perpetuated
//     output locking (that is the next step's locking, already counted).
//   - intra-tx step  -> all steps share ONE tx; the shared envelope + single OP_RETURN
//     output are attributed to input 0, every input pays its outpoint/sequence/varint.
//   - single-tx step -> one tx, one input, one standard (P2PKH, 25 B) output.
// Number of transactions a run spans: one per group (grouped), one (intra-tx bundle),
// or one per step (covenant chain / would-be single-tx).
const txCountOf = (valid: Step[]): number =>
  valid.some((s) => s.grouped !== undefined)
    ? new Set(valid.filter((s) => s.grouped).map((s) => s.grouped!.group)).size
    : valid.some((s) => s.intraTx !== undefined)
    ? 1
    : valid.length;

const stepTxOverhead = (step: Step): number => {
  const inputOv = INPUT_FIXED + varintLen(step.unlockingBytecode.length);
  if (step.grouped !== undefined) {
    // interior inputs add only their outpoint/sequence/script-length; the FIRST input of each
    // group also carries the shared tx envelope + the single group output. The output is either
    // the perpetuated token (its locking is the next chunk's, already counted as that step's
    // locking, so excluded like the covenant model) or, for the terminal group, an OP_RETURN.
    const g = step.grouped;
    if (g.index !== 0) return inputOv;
    let outputOv: number;
    if (g.outToken !== undefined) {
      const prefix =
        1 /* PREFIX_TOKEN */ + g.category.length + 1 /* bitfield */ +
        varintLen(g.outToken.commitment.length) + g.outToken.commitment.length;
      outputOv = 8 /* value */ + varintLen(prefix + (g.outLockingBytecode?.length ?? 1)) + prefix;
    } else {
      outputOv = 8 + varintLen(1) + 1; // OP_RETURN verdict output
    }
    return TXN_ENVELOPE + varintLen(g.inputs.length) + varintLen(1) + inputOv + outputOv;
  }
  if (step.intraTx !== undefined) {
    const sharedOnFirst =
      step.intraTx.index === 0
        ? TXN_ENVELOPE + varintLen(step.intraTx.inputs.length) + varintLen(1) + (8 + varintLen(1) + 1)
        : 0;
    return sharedOnFirst + inputOv;
  }
  if (step.covenant !== undefined) {
    const prefix =
      1 /* PREFIX_TOKEN */ + step.covenant.category.length + 1 /* bitfield */ +
      varintLen(step.covenant.outCommitment.length) + step.covenant.outCommitment.length;
    const outputOv = 8 /* value */ + varintLen(prefix + step.covenant.outLockingBytecode.length) + prefix;
    return TXN_ENVELOPE + varintLen(1) + varintLen(1) + inputOv + outputOv;
  }
  const p2pkh = 25;
  return TXN_ENVELOPE + varintLen(1) + varintLen(1) + inputOv + (8 + varintLen(p2pkh) + p2pkh);
};

// Envelope-security gate: an entry that hides any step's contract behind a P2SH20 hash
// (OP_HASH160 <20B> OP_EQUAL) is DISALLOWED — the 160-bit hash is collision-vulnerable at
// ~2^80 work, cheap enough to forge a second redeem for a funded contract. This is a
// competition rule, not a protocol one (P2SH20 is consensus-valid + relayable), so it is
// scored separately from bchCompatible/standardness and folded into `pass`. P2SH32, bare,
// and P2S deployments all pass.
const packagingSecurity = (steps: Step[]): { secure: boolean; reason?: string } => {
  const n = steps.filter((s) => isP2sh20Locking(s.lockingBytecode)).length;
  return n === 0
    ? { secure: true }
    : { secure: false, reason: `${n}/${steps.length} step(s) use an insecure P2SH20 envelope (OP_HASH160, ~2^80 collision security) — use P2SH32` };
};

const runStep = (vm: Bch2026Vm, step: Step, bsv: boolean): StepMetrics => {
  const o = evaluatePair(vm, step.lockingBytecode, step.unlockingBytecode, step.covenant, step.intraTx, step.grouped);
  return {
    label: step.label,
    lockingBytes: step.lockingBytecode.length,
    unlockingBytes: step.unlockingBytecode.length,
    padBytes: zeroPadBytes(step.unlockingBytecode),
    txOverheadBytes: stepTxOverhead(step),
    operationCost: o.operationCost,
    instructionCount: o.instructionCount,
    accepted: bsv ? o.bsvAccepted : o.accepted,
    error: o.error,
  };
};

/** A run is rejected if at least one of its steps does not accept. */
const runRejects = (vm: Bch2026Vm, run: Step[], bsv: boolean): boolean =>
  run.some((s) => {
    const o = evaluatePair(vm, s.lockingBytecode, s.unlockingBytecode, s.covenant, s.intraTx, s.grouped);
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

/** BCH 2026 standard (mempool-relay) check, strictly stronger than consensus
 * (`bchCompatible`). Combines libauth's per-input standard toggle with the
 * transaction-level relay limits the VM does NOT enforce on its own:
 *   - every step validates under the STANDARD instruction set (push-only scriptSig,
 *     standard encodings, clean stack);
 *   - every locking <= 201 B and every unlocking <= 10,000 B (standard script caps);
 *   - every transaction <= 100,000 B serialized (standard max tx size).
 * The serialized tx size reuses the harness tx-overhead model: a single-tx / intra-tx
 * bundle is ONE tx (sum of scriptSigs + shared overhead — lockings live in the funding
 * UTXOs, not the spend); a covenant chain is one small tx per step. */
const standardness = (
  scenario: Awaited<ReturnType<Implementation['load']>>,
  steps: StepMetrics[],
  txCount: number,
  totalTxOverheadBytes: number,
  bsv: boolean,
): { fits: boolean; reason?: string } => {
  const overLock = steps.filter((s) => s.lockingBytes > MAX_STANDARD_LOCKING_BYTECODE).length;
  const overUnlock = steps.filter((s) => s.unlockingBytes > MAX_STANDARD_UNLOCKING_BYTECODE).length;
  // Largest single transaction in the run (the 100,000-byte standard cap applies per tx):
  //   - grouped: each group is one tx; its size = sum of its inputs' scriptSig (unlocking) +
  //     that group's tx overhead (envelope + outpoints + the single token/OP_RETURN output).
  //     Lockings live in the funding UTXOs, not the spend.
  //   - intra-tx bundle (txCount 1): the one tx = sum of all unlockings + overhead.
  //   - covenant chain: max single 1-in/1-out step tx.
  const grouped = scenario.valid.some((s) => s.grouped !== undefined);
  let txBytes: number;
  if (grouped) {
    const byGroup = new Map<number, number>();
    scenario.valid.forEach((s, i) => {
      const g = s.grouped!.group;
      byGroup.set(g, (byGroup.get(g) ?? 0) + steps[i]!.unlockingBytes + steps[i]!.txOverheadBytes);
    });
    txBytes = Math.max(0, ...byGroup.values());
  } else if (txCount === 1) {
    txBytes = steps.reduce((a, s) => a + s.unlockingBytes, 0) + totalTxOverheadBytes;
  } else {
    txBytes = Math.max(0, ...steps.map((s) => s.unlockingBytes + s.lockingBytes + s.txOverheadBytes));
  }

  const vm = createStandardVm();
  const evalRejects = scenario.valid.some((s) => {
    const o = evaluatePair(vm, s.lockingBytecode, s.unlockingBytecode, s.covenant, s.intraTx, s.grouped);
    return !(bsv ? o.bsvAccepted : o.accepted);
  });

  const reasons = [
    overLock ? `${overLock}/${steps.length} locking >${MAX_STANDARD_LOCKING_BYTECODE} B` : null,
    overUnlock ? `${overUnlock}/${steps.length} unlocking >${MAX_STANDARD_UNLOCKING_BYTECODE.toLocaleString('en-US')} B` : null,
    txBytes > MAX_STANDARD_TRANSACTION_SIZE
      ? `tx ${txBytes.toLocaleString('en-US')} B > ${MAX_STANDARD_TRANSACTION_SIZE.toLocaleString('en-US')} B standard size`
      : null,
    evalRejects ? 'a step is non-standard under the standard VM' : null,
  ].filter(Boolean);
  return { fits: reasons.length === 0, reason: reasons.length ? reasons.join('; ') : undefined };
};

/** Token-threading safety: a step that carries state through an NFT commitment
 * (Step.covenant) is only safe if the covenant pins the token (category continuity
 * + capability constraint). Default FALSE for any covenant entry until that is
 * actually enforced; null (not applicable) for non-covenant entries. */
const tokenSafetyOf = (
  scenario: Awaited<ReturnType<Implementation['load']>>,
  impl: Implementation,
): { tokenThreaded: boolean; tokenSafetyEnforced: boolean | null } => {
  // covenant steps thread state through an NFT commitment; grouped steps thread the
  // cross-group hand-off through one too (the within-group links are sibling introspection).
  const tokenThreaded = scenario.valid.some((s) => s.covenant !== undefined || s.grouped !== undefined);
  return { tokenThreaded, tokenSafetyEnforced: tokenThreaded ? impl.tokenSafetyEnforced ?? false : null };
};

export const benchmark = (impl: Implementation, scenario: Awaited<ReturnType<Implementation['load']>>): BenchmarkResult => {
  // Envelope-security gate (applies to executed AND profile-only entries): disallow P2SH20.
  const env = packagingSecurity(scenario.valid);
  // Profile-only: size-decidable, not executed (e.g. tx-introspection covenants
  // we cannot drive in a synthetic context). BCH compat == every script fits the cap.
  if (scenario.profileOnly) {
    const profileEnv = env;
    const steps: StepMetrics[] = scenario.valid.map((s) => ({
      label: s.label,
      lockingBytes: s.lockingBytecode.length,
      unlockingBytes: s.unlockingBytecode.length,
      padBytes: zeroPadBytes(s.unlockingBytecode),
      txOverheadBytes: stepTxOverhead(s),
      operationCost: 0,
      instructionCount: 0,
      accepted: false,
      error: undefined,
    }));
    const oversize = steps.filter((s) => s.lockingBytes > SCRIPT_SIZE_CAP || s.unlockingBytes > SCRIPT_SIZE_CAP).length;
    return {
      impl, profileOnly: true, checked: false, validPassed: false,
      invalidRejected: 0, invalidTotal: 0, pass: false, bsvOpReturn: false, steps,
      proofBinding: impl.proofBinding ?? 'runtime', proofsTested: 1, proofsPassed: 0, runtimeGeneral: false,
      ...tokenSafetyOf(scenario, impl),
      inputValidation: { tested: 0, rejected: 0, enforced: false },
      checkpointStats: [],
      stepCount: steps.length,
      totalBytes: steps.reduce((a, s) => a + s.lockingBytes + s.unlockingBytes, 0),
      totalPadBytes: steps.reduce((a, s) => a + s.padBytes, 0),
      totalTxOverheadBytes: steps.reduce((a, s) => a + s.txOverheadBytes, 0),
      txCount: txCountOf(scenario.valid),
      totalOperationCost: 0, maxStepOperationCost: 0,
      fitsStandardBudget: false, inputsForHeaviestStep: 0,
      bchCompatible: oversize === 0,
      bchIncompatibleReason: oversize > 0 ? `script-size: ${oversize}/${steps.length} steps over ${SCRIPT_SIZE_CAP / 1000}KB` : undefined,
      fitsBchStandardness: false,
      bchStandardnessReason: 'profile-only (not executed)',
      securePackaging: profileEnv.secure,
      insecurePackagingReason: profileEnv.reason,
    };
  }

  const bsv = scenario.bsvOpReturnTerminator === true;
  const vm = createLoosenedVm();
  const steps = scenario.valid.map((s) => runStep(vm, s, bsv));
  const validPassed = steps.every((s) => s.accepted);

  // Proof-generality: run each EXTRA distinct proof against the same locking and
  // count how many fully accept. A runtime-general verifier accepts them all; a
  // verifier with the proof baked into its program accepts only the one it was
  // built for. (The main valid run above is proof #0.)
  const extraRuns = scenario.extraValidProofs ?? [];
  const extraPassed = extraRuns.filter((run) => !runRejects(vm, run, bsv)).length;
  const proofBinding = impl.proofBinding ?? 'runtime';
  const proofsTested = 1 + extraRuns.length;
  const proofsPassed = (validPassed ? 1 : 0) + extraPassed;
  const runtimeGeneral = proofsPassed >= 2;

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
  const realOutcomes = scenario.valid.map((s) => evaluatePair(realVm, s.lockingBytecode, s.unlockingBytecode, s.covenant, s.intraTx, s.grouped));
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

  // EIP-197 input validation: adversarial-point runs (off-curve / off-subgroup) must reject.
  // ONLY counts as a demonstration when the bad point is rejected at an ISOLATED validation
  // step (a chunked g2check stage), BEFORE it can reach the pairing — that is what
  // Scenario.invalidInputs supplies. A naive point-swap in a FULL (single-tx) verifier is
  // rejected by the verification equation itself (a wrong B makes e(-A,B)·… ≠ 1) regardless
  // of whether on-curve/subgroup checks exist, so it does NOT discriminate and is NOT used
  // here (see harness/adversarial.ts). A full verifier with no isolated adversarial run is
  // reported as NOT DEMONSTRATED.
  const inputRuns = scenario.invalidInputs ?? [];
  const inputRejected = inputRuns.filter((run) => runRejects(vm, run, bsv)).length;
  const inputValidation = { tested: inputRuns.length, rejected: inputRejected, enforced: inputRuns.length > 0 && inputRejected === inputRuns.length };

  const opCosts = steps.map((s) => s.operationCost);
  const maxStepOperationCost = opCosts.length ? Math.max(...opCosts) : 0;
  const budget = standardInputBudget();

  // worst-case proof run (dense near-r inputs through the SAME lockings): measure its
  // op-cost separately so the proof-size dependence is visible. The worst-case proof is a
  // VALID proof (asserted to accept on the singleton when the vectors are generated), so
  // its acceptance is a correctness property of the verifier under test, not just a
  // profiling input — record the outcome unconditionally (including a rejection) and fold
  // it into `pass`. A worst-case proof exercises field-arithmetic edge cases (lazy-
  // reduction overflow, bias bounds, near-modulus operands), so a silent drop here would
  // hide exactly the completeness bugs it is most likely to expose.
  const wcRun = scenario.worstCaseProof ?? [];
  let worstCase: BenchmarkResult['worstCase'];
  let worstCaseAccepted = true; // vacuously true when no worst-case run was provided
  if (wcRun.length > 0) {
    const wcSteps = wcRun.map((s) => runStep(vm, s, bsv));
    worstCaseAccepted = wcSteps.every((s) => s.accepted);
    const wcOps = wcSteps.map((s) => s.operationCost);
    const wcMax = Math.max(...wcOps);
    worstCase = {
      accepted: worstCaseAccepted,
      stepCount: wcSteps.length,
      totalOperationCost: wcOps.reduce((a, b) => a + b, 0),
      maxStepOperationCost: wcMax,
      inputsForHeaviestStep: Math.ceil(wcMax / budget),
    };
  }
  const totalTxOverheadBytes = steps.reduce((a, s) => a + s.txOverheadBytes, 0);
  const txCount = txCountOf(scenario.valid);
  // BCH standard (relay) policy: stricter than the consensus `bchCompatible` above.
  const std = standardness(scenario, steps, txCount, totalTxOverheadBytes, bsv);

  return {
    impl,
    profileOnly: false,
    checked: invalidRuns.length > 0,
    validPassed,
    invalidRejected,
    invalidTotal: invalidRuns.length,
    pass: validPassed && worstCaseAccepted && invalidRuns.length > 0 && invalidRejected === invalidRuns.length && env.secure,
    proofBinding,
    proofsTested,
    proofsPassed,
    runtimeGeneral,
    ...tokenSafetyOf(scenario, impl),
    inputValidation,
    bsvOpReturn: bsv,
    steps,
    checkpointStats,
    stepCount: steps.length,
    totalBytes: steps.reduce((a, s) => a + s.lockingBytes + s.unlockingBytes, 0),
    totalPadBytes: steps.reduce((a, s) => a + s.padBytes, 0),
    totalTxOverheadBytes,
    txCount,
    totalOperationCost: opCosts.reduce((a, b) => a + b, 0),
    maxStepOperationCost,
    fitsStandardBudget: steps.every((s) => s.operationCost <= budget),
    inputsForHeaviestStep: Math.ceil(maxStepOperationCost / budget),
    worstCase,
    bchCompatible,
    bchIncompatibleReason,
    fitsBchStandardness: std.fits,
    bchStandardnessReason: std.reason,
    securePackaging: env.secure,
    insecurePackagingReason: env.reason,
  };
};

/** Run every registered implementation and return its BenchmarkResult (no printing).
 * Shared by the CLI table and the JSON exporter. Demos are excluded by default. */
export const computeResults = async (includeDemos = false): Promise<BenchmarkResult[]> => {
  const registry = includeDemos ? REGISTRY : REGISTRY.filter((i) => i.demo !== true);
  const results: BenchmarkResult[] = [];
  for (const impl of registry) {
    try {
      const scenario = await impl.load();
      results.push(benchmark(impl, scenario));
    } catch {
      // an implementation that fails to load is simply omitted from the results
    }
  }
  return results;
};

const fmt = (n: number) => n.toLocaleString();
const padR = (s: string, w: number) => s.padEnd(w);
const padL = (s: string, w: number) => s.padStart(w);

const main = async () => {
  const includeDemos = process.argv.includes('--demos');
  const registry = includeDemos ? REGISTRY : REGISTRY.filter((i) => i.demo !== true);
  console.log(
    `benchmarking ${registry.length} implementation(s) on the BCH 2026 VM (limits loosened)` +
    (includeDemos ? '' : '  [demos hidden; --demos to show]') + '\n',
  );
  const results: BenchmarkResult[] = [];
  for (const impl of registry) {
    process.stdout.write(`- ${impl.id} ... `);
    try {
      const scenario = await impl.load();
      const r = benchmark(impl, scenario);
      results.push(r);
      console.log(
        r.profileOnly ? 'profile-only (size)'
          : !r.securePackaging ? 'DISALLOWED (insecure P2SH20 envelope)'
            : r.pass ? 'PASS'
              : r.worstCase?.accepted === false ? 'FAIL (worst-case proof rejected)'
                : r.validPassed ? 'valid-only (no reject test)'
                  : 'FAIL',
      );
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
    padR(c[0]!, 20), padR(c[1]!, 9), padR(c[2]!, 26),
    padL(c[3]!, 5), padL(c[4]!, 12), padL(c[5]!, 13), padL(c[6]!, 7), c[7]!,
  ].join('  ');
  const header = cols(['implementation', 'field', 'correctness', 'steps', 'total B', 'op-cost', '@10KB', 'BCH compatible']);

  for (const [track, rs] of tracks) {
    console.log(`\n### ${track}`);
    console.log(header);
    console.log('-'.repeat(header.length));
    for (const r of rs) {
      const correctness = r.profileOnly
        ? 'profile (size)'
        : !r.securePackaging
          ? 'DISALLOWED (P2SH20)'
          : r.pass
            ? `PASS (${r.invalidRejected}/${r.invalidTotal}✗${r.bsvOpReturn ? ', BSV OP_RETURN' : ''})`
            : r.worstCase?.accepted === false
              ? 'FAIL (worst-case✗)'
              : r.validPassed
                ? 'valid-only'
                : 'FAIL';
      const compat = r.bchCompatible ? 'yes' : `no: ${r.bchIncompatibleReason ?? 'limit'}`;
      const at10kb = r.profileOnly ? '-' : r.inputsForHeaviestStep <= 1 ? '1' : `~${r.inputsForHeaviestStep}`;
      console.log(cols([
        r.impl.id, r.impl.field, correctness,
        String(r.stepCount), fmt(r.totalBytes),
        r.profileOnly ? '-' : fmt(r.totalOperationCost), at10kb, compat,
      ]));
      for (const c of r.checkpointStats) {
        console.log(`    > reach "${c.label}" @ step ${c.atStep}: ${fmt(c.cumulativeOpCost)} op-cost, ${fmt(c.cumulativeBytes)} B`);
      }
      if (!r.securePackaging) {
        console.log(`    > packaging: DISALLOWED — ${r.insecurePackagingReason}`);
      }
      if (!r.profileOnly) {
        console.log(`    > standardness: ${r.fitsBchStandardness ? 'standard — relayable under default mempool policy' : `non-standard (${r.bchStandardnessReason ?? 'relay limit'}); valid at consensus, must be mined directly`}`);
      }
      if (!r.profileOnly) {
        if (r.proofBinding === 'baked') {
          console.log(`    > proof generality: instance-specific — the proof is baked into the program; a different proof needs it regenerated (the tamper test confirms only the baked witness is accepted)`);
        } else if (r.proofsTested >= 2) {
          const tag = r.proofsPassed === r.proofsTested ? 'runtime-general' : `ONLY ${r.proofsPassed}/${r.proofsTested} — NOT general`;
          console.log(`    > proof generality: ${tag} — one fixed locking verifies ${r.proofsPassed}/${r.proofsTested} distinct proofs (proof in the unlocking witness)`);
        } else {
          console.log(`    > proof generality: runtime-general by construction — proof supplied in the unlocking witness (1 reference proof available)`);
        }
        if (r.tokenThreaded) {
          console.log(`    > token safety: ${r.tokenSafetyEnforced ? 'ENFORCED' : 'NOT enforced'} — state is threaded through the NFT commitment` +
            (r.tokenSafetyEnforced ? '' : ', but category continuity / capability are not pinned (a real deployment must enforce them)'));
        }
        const isFullGroth16 = r.impl.proofSystem === 'Groth16' && r.impl.milestone === undefined && r.impl.demo !== true;
        if (r.inputValidation.tested > 0) {
          console.log(`    > input validation: ${r.inputValidation.enforced ? 'ENFORCED' : 'NOT enforced'} — ${r.inputValidation.rejected}/${r.inputValidation.tested} adversarial points (off-curve / off-subgroup) rejected at an isolated check (EIP-197 on-curve + G2-subgroup)`);
        } else if (isFullGroth16) {
          const why = r.impl.structure === 'single-tx'
            ? 'single-tx: a swapped point is caught by the pairing equation, not a validation check, so rejection here would not prove on-curve/subgroup validation'
            : 'no isolated adversarial-point run (off-curve / off-subgroup) supplied';
          console.log(`    > input validation: NOT DEMONSTRATED — ${why}`);
        }
      }
      const ms = r.impl.milestone;
      if (ms !== undefined && !r.profileOnly) {
        const at = ms.scalar !== undefined ? ` @ scalar ${ms.scalar}` : '';
        console.log(`    > milestone "${ms.name}"${at}: ours ${fmt(ms.thisOpCost)} op-cost vs ${fmt(ms.referenceOpCost)} [${ms.referenceSource}]`);
        if (ms.normalized === true) {
          const cmp = ms.thisOpCost < ms.referenceOpCost
            ? `${(ms.referenceOpCost / ms.thisOpCost).toFixed(2)}x cheaper`
            : `${(ms.thisOpCost / ms.referenceOpCost).toFixed(2)}x costlier`;
          console.log(`        normalized (same scalar; both fixed-iteration loops): ours is ${cmp}`);
        } else if (ms.caveat !== undefined) {
          console.log(`        ${ms.caveat}`);
        }
      }
    }
  }

  // --- vs the reference implementation (size + op-cost ratios) ---
  const ref = results.find((r) => r.impl.reference === true && !r.profileOnly);
  if (ref !== undefined) {
    const ratio = (impl: number, base: number): string => {
      if (impl === base) return 'same';
      return impl < base
        ? `${(base / impl).toFixed(base / impl >= 10 ? 0 : 1)}x smaller`
        : `${(impl / base).toFixed(1)}x larger`;
    };
    // Only compare SAME-SCOPE entries (same proofSystem = a full verifier of the
    // same system). A partial/checkpoint entry (e.g. the vk_x sub-step) must not be
    // ratioed against the whole verifier, and the monolithic reference exposes no
    // isolable vk_x cost to compare a part against.
    console.log(`\n### vs reference: ${ref.impl.id} (full ${ref.impl.proofSystem} verifier; ${fmt(ref.totalBytes)} B, ${fmt(ref.totalOperationCost)} op-cost)`);
    const peers = results.filter((r) => r !== ref && !r.profileOnly && r.impl.proofSystem === ref.impl.proofSystem);
    for (const r of peers) {
      console.log(
        `  ${padR(r.impl.id, 20)} bytes ${padR(ratio(r.totalBytes, ref.totalBytes), 14)} ` +
        `op-cost ${padR(ratio(r.totalOperationCost, ref.totalOperationCost), 14)} [${r.impl.field}]`,
      );
    }
    console.log(`  (same proof system only; curves/circuits differ — see "Not every Groth16 is alike" in the README)`);
  }

  console.log(`\n@10KB = inputs needed if the unlocking is zero-padded to the 10,000-byte cap (max budget (41+10000)x800 = ${fmt(standardInputBudget())} op-cost/input); "1" fits one input.`);
  console.log(`BCH compatible = validates on the real BCH 2026 VM as-is; the blocker (script-size / op-cost) is shown.`);
};

// Only run the CLI table when invoked directly (`pnpm benchmark`), not when this
// module is imported (e.g. by the JSON exporter, which reuses computeResults).
const invokedDirectly =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) await main();
