// Benchmark harness. For each registered implementation (single- or multi-tx):
//   1. correctness   - the valid run is fully ACCEPTED; invalid runs are REJECTED
//   2. size + op-cost - per-step and aggregate, on the BCH 2026 VM (limits loosened)
//   3. budget fit     - does each step fit one standard BCH input's op-cost budget?
// Results are grouped into separate leaderboards by (proofSystem, structure).
// Correctness gates the cost numbers.
import { assertHonestRuns } from './scenario-contract.js';
import { bchGroth16Bls12381Chunked } from '../implementations/bch-groth16-bls12381-chunked.js';
import { bchGroth16Bls12381ChunkedCovenant } from '../implementations/bch-groth16-bls12381-chunked-covenant.js';
import { bchGroth16Bls12381ChunkedCovenantResidue } from '../implementations/bch-groth16-bls12381-chunked-covenant-residue.js';
import { bchGroth16Bls12381Singleton } from '../implementations/bch-groth16-bls12381-singleton.js';
import { bchGroth16Bls12381SingletonOpcodeOptimized } from '../implementations/bch-groth16-bls12381-singleton-opcode-optimized.js';
import { bchGroth16Bls12381SingletonGenpow } from '../implementations/bch-groth16-bls12381-singleton-genpow.js';
import { bchGroth16Bls12381SingletonMinOp } from '../implementations/bch-groth16-bls12381-singleton-minop.js';
import { bchGroth16Bls12381SingletonFs } from '../implementations/bch-groth16-bls12381-singleton-fs.js';
import { bchGroth16Bls12381SingletonFsSpec } from '../implementations/bch-groth16-bls12381-singleton-fs-spec.js';
import { bchGroth16Bls12381SingletonFsSpecShared } from '../implementations/bch-groth16-bls12381-singleton-fs-spec-shared.js';
import { bchGroth16Bls12381SingletonFsSpecZero } from '../implementations/bch-groth16-bls12381-singleton-fs-spec-zero.js';
import { bchGroth16Bls12381SoundNative } from '../implementations/bch-groth16-bls12381-sound-native.js';
import { bchGroth16Chunked } from '../implementations/bch-groth16-chunked.js';
import { bchGroth16ChunkedCovenant } from '../implementations/bch-groth16-chunked-covenant.js';
import { bchGroth16ChunkedCovenantResidue } from '../implementations/bch-groth16-chunked-covenant-residue.js';
import { bchGroth16Singleton } from '../implementations/bch-groth16-singleton.js';
import { bchGroth16SingletonOpcodeOptimized } from '../implementations/bch-groth16-singleton-opcode-optimized.js';
import { bchGroth16SingletonGenpow } from '../implementations/bch-groth16-singleton-genpow.js';
import { bchGroth16SingletonMinOp } from '../implementations/bch-groth16-singleton-minop.js';
import { bchMultistepDemo } from '../implementations/bch-multistep-demo.js';
import { bchPairingBls12381Chunked } from '../implementations/bch-pairing-bls12381-chunked.js';
import { bchPairingBls12381Singleton } from '../implementations/bch-pairing-bls12381-singleton.js';
import { bchPairingChunked } from '../implementations/bch-pairing-chunked.js';
import { bchGroth16IntratxDirectStatePublic } from '../implementations/bch-groth16-intratx-direct-state-public.js';
import { bchGroth16IntratxResidue } from '../implementations/bch-groth16-intratx-residue.js';
import { bchGroth16IntratxGeneral } from '../implementations/bch-groth16-intratx-general.js';
import { bchGroth16IntratxResidueLarge } from '../implementations/bch-groth16-intratx-residue-large.js';
import { bchGroth16IntratxCrown8Rawchain } from '../implementations/bch-groth16-intratx-crown8-rawchain.js';
import { bchGroth16SoundSiGlsSingle } from '../implementations/bch-groth16-sound-si-gls-single.js';
import { bchGroth16Bls12381SoundSiGlsSingle } from '../implementations/bch-groth16-bls12381-sound-si-gls-single.js';
import { bchGroth16Bn254SoundNative } from '../implementations/bch-groth16-bn254-sound-native.js';
import { bchGroth16Bls12381Grouped } from '../implementations/bch-groth16-bls12381-grouped.js';
import { bchPairingBls12381Intratx } from '../implementations/bch-pairing-bls12381-intratx.js';
import { bchGroth16Bls12381Intratx } from '../implementations/bch-groth16-bls12381-intratx.js';
import { bchGroth16Bls12381IntratxFs } from '../implementations/bch-groth16-bls12381-intratx-fs.js';
import { bchGroth16Bls12381IntratxFsCompact } from '../implementations/bch-groth16-bls12381-intratx-fs-compact.js';
import { bchGroth16Bls12381IntratxFsFusedFinal } from '../implementations/bch-groth16-bls12381-intratx-fs-fused-final.js';
import { bchGroth16Bls12381IntratxFsFusedRegular } from '../implementations/bch-groth16-bls12381-intratx-fs-fused-regular.js';
import { bchGroth16Bls12381IntratxFsFusedRegularPairs } from '../implementations/bch-groth16-bls12381-intratx-fs-fused-regular-pairs.js';
import { bchGroth16Bls12381IntratxFsFusedRegularPairsPacked } from '../implementations/bch-groth16-bls12381-intratx-fs-fused-regular-pairs-packed.js';
import { bchGroth16Bls12381IntratxFsFusedRegularTriples } from '../implementations/bch-groth16-bls12381-intratx-fs-fused-regular-triples.js';
import { bchGroth16Bls12381IntratxFsFusedCarrierPair } from '../implementations/bch-groth16-bls12381-intratx-fs-fused-carrier-pair.js';
import { bchGroth16Bls12381IntratxFsFusedMiddlePair } from '../implementations/bch-groth16-bls12381-intratx-fs-fused-middle-pair.js';
import { bchGroth16Bls12381IntratxFsRegularInitializer } from '../implementations/bch-groth16-bls12381-intratx-fs-regular-initializer.js';
import { bchGroth16Bls12381IntratxFsFusedFirstTail } from '../implementations/bch-groth16-bls12381-intratx-fs-fused-first-tail.js';
import { bchGroth16Bls12381IntratxFsFusedCoordinatorHead } from '../implementations/bch-groth16-bls12381-intratx-fs-fused-coordinator-head.js';
import { bchGroth16Bls12381IntratxFsFusedCoordinatorHeadFields } from '../implementations/bch-groth16-bls12381-intratx-fs-fused-coordinator-head-fields.js';
import { bchPairingSingleton } from '../implementations/bch-pairing-singleton.js';
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

import { layoutGate, publicInputGate } from './gates.js';
import { redTeam } from './redteam.js';
import { reviewStatusOf } from './review-status.js';
import { tamperProof } from './tamper.js';
import { txv5Grade, txv5Summary } from './txv5.js';
import type { BenchmarkResult, Implementation, PackagingType, Scenario, Step, StepMetrics } from './types.js';
import {
  createLoosenedVm,
  createRealVm,
  createRealVmSpec,
  createStandardVm,
  createStandardVmSpec,
  evaluatePair,
  isP2sh20Locking,
  lockingEnvelope,
  standardInputBudget,
  specInputBudget,
  SPEC_STANDARD_UNLOCKING_CAP,
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

export const REGISTRY: Implementation[] = [nchain, scryptBn256, bchGroth16Singleton, bchGroth16SingletonOpcodeOptimized, bchGroth16SingletonGenpow, bchGroth16SingletonMinOp, bchGroth16Bls12381Singleton, bchGroth16Bls12381SingletonOpcodeOptimized, bchGroth16Bls12381SingletonGenpow, bchGroth16Bls12381SingletonMinOp, bchGroth16Bls12381SingletonFs, bchGroth16Bls12381SingletonFsSpec, bchGroth16Bls12381SingletonFsSpecShared, bchGroth16Bls12381SingletonFsSpecZero, bchGroth16Chunked, bchGroth16ChunkedCovenant, bchGroth16ChunkedCovenantResidue, bchVkxScalarmult, bchVkxSingleton, bchVkxBls12381Singleton, bchVkxChunkedTwoloop, bchVkxChunkedShamir, bchVkxChunkedCovenant, bchPairingSingleton, bchPairingBls12381Singleton, bchPairingChunked, bchPairingBls12381Chunked, bchGroth16Bls12381Chunked, bchGroth16Bls12381ChunkedCovenant, bchGroth16Bls12381ChunkedCovenantResidue, bchGroth16IntratxDirectStatePublic, bchGroth16IntratxResidue, bchGroth16IntratxResidueLarge, bchGroth16IntratxCrown8Rawchain, bchGroth16SoundSiGlsSingle, bchGroth16Bls12381SoundSiGlsSingle, bchGroth16Bn254SoundNative, bchGroth16Bls12381SoundNative, bchGroth16IntratxGeneral, bchPairingBls12381Intratx, bchGroth16Bls12381Intratx, bchGroth16Bls12381IntratxFs, bchGroth16Bls12381IntratxFsCompact, bchGroth16Bls12381IntratxFsFusedFinal, bchGroth16Bls12381IntratxFsFusedRegular, bchGroth16Bls12381IntratxFsFusedRegularPairs, bchGroth16Bls12381IntratxFsFusedRegularPairsPacked, bchGroth16Bls12381IntratxFsFusedRegularTriples, bchGroth16Bls12381IntratxFsFusedCarrierPair, bchGroth16Bls12381IntratxFsFusedMiddlePair, bchGroth16Bls12381IntratxFsRegularInitializer, bchGroth16Bls12381IntratxFsFusedFirstTail, bchGroth16Bls12381IntratxFsFusedCoordinatorHead, bchGroth16Bls12381IntratxFsFusedCoordinatorHeadFields, bchGroth16Bls12381Grouped, bchMultistepDemo];

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
//   - covenant step  -> its own token tx; includes the CashToken output prefix
//     (category + NFT commitment carrying the threaded state); EXCLUDES the perpetuated
//     output locking (that is the next step's locking, already counted). A minting-genesis
//     step also pays the complete second output that recreates its baton.
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
    const batonPrefix = 1 /* PREFIX_TOKEN */ + step.covenant.category.length +
      1 /* bitfield */ + varintLen(0) /* empty commitment */;
    const batonOutputOv = step.covenant.secondOutputBaton
      ? 8 /* value */ + varintLen(batonPrefix + step.lockingBytecode.length) +
        batonPrefix + step.lockingBytecode.length
      : 0;
    const outputCount = step.covenant.secondOutputBaton ? 2 : 1;
    return TXN_ENVELOPE + varintLen(1) + varintLen(outputCount) + inputOv + outputOv + batonOutputOv;
  }
  const p2pkh = 25;
  return TXN_ENVELOPE + varintLen(1) + varintLen(1) + inputOv + (8 + varintLen(p2pkh) + p2pkh);
};

// Envelope-security gate: an entry that hides any step's contract behind a P2SH20 hash
// (OP_HASH160 <20B> OP_EQUAL) is DISALLOWED — the 160-bit hash is collision-vulnerable at
// ~2^80 work, cheap enough to forge a second redeem for a funded contract. This is a
// competition rule, not a protocol one (P2SH20 is consensus-valid + relayable), so it is
// scored separately from bchCompatible/standardness and folded into `pass`. P2SH32 and
// bare (P2S) deployments pass. Also classifies WHAT the entry uses (one form or 'mixed').
const packagingSecurity = (steps: Step[]): { secure: boolean; type: PackagingType; reason?: string } => {
  const forms = new Set(steps.map((s) => lockingEnvelope(s.lockingBytecode)));
  const type: PackagingType = forms.size === 1 ? [...forms][0]! : 'mixed';
  const n = steps.filter((s) => isP2sh20Locking(s.lockingBytecode)).length;
  return n === 0
    ? { secure: true, type }
    : { secure: false, type, reason: `${n}/${steps.length} step(s) use an insecure P2SH20 envelope (OP_HASH160, ~2^80 collision security) — use P2SH32` };
};

/** Score (scripts + tx overhead) and modelled serialized tx size of a run, as the headline
 * score and the standardness check compute them. Used by the TXv5 grade for padded runs. */
export const runScore = (run: Step[]): { score: number; txBytes: number } => {
  const overheads = run.map(stepTxOverhead);
  const overhead = overheads.reduce((a, b) => a + b, 0);
  const score = run.reduce((a, s) => a + s.lockingBytecode.length + s.unlockingBytecode.length, 0) + overhead;
  return { score, txBytes: largestTxBytes(run, overheads) };
};

/** Largest single transaction of a run (the 100,000-byte standard cap applies per tx), shared by
 * runScore and standardness():
 *   - grouped: each group is one tx; its size = sum of its inputs' scriptSig (unlocking) + that
 *     group's tx overhead (envelope + outpoints + the single token/OP_RETURN output). Lockings
 *     live in the funding UTXOs, not the spend.
 *   - intra-tx bundle / single tx (txCount 1): the one tx = sum of all unlockings + overhead.
 *   - covenant chain: max single 1-in/1-out step tx. */
const largestTxBytes = (run: Step[], overheads: number[] = run.map(stepTxOverhead)): number => {
  if (run.some((s) => s.grouped !== undefined)) {
    const byGroup = new Map<number, number>();
    run.forEach((s, i) => {
      const g = s.grouped!.group;
      byGroup.set(g, (byGroup.get(g) ?? 0) + s.unlockingBytecode.length + overheads[i]!);
    });
    return Math.max(0, ...byGroup.values());
  }
  if (txCountOf(run) === 1) return run.reduce((a, s) => a + s.unlockingBytecode.length, 0) + overheads.reduce((a, b) => a + b, 0);
  return Math.max(0, ...run.map((s, i) => s.unlockingBytecode.length + s.lockingBytecode.length + overheads[i]!));
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

/**
 * Cross-stage stapling invariant (a soundness gate for multi-stage verifiers).
 *
 * A chunked verifier splits one proof's verification across many inputs/stages (validate
 * inputs -> vk_x MSM -> Miller/pairing -> final-exp). Correctness of each stage in ISOLATION
 * is not enough: every stage must be bound to the SAME proof. If a stage's output is a free
 * island — nothing later reads it, or it is not byte-equal-checked against the proof the rest
 * of the run consumes — an attacker can "staple" one proof's stage onto another proof's
 * remaining stages in a single transaction (e.g. run proof #0's G2-subgroup check but proof
 * #1's Miller loop), and the verifier accepts a proof no single stage actually validated end
 * to end. The tamper test (flip one witness limb) does NOT catch this: it breaks a LOCAL
 * forward-check and is rejected regardless of whether the stages are cross-bound.
 *
 * The test needs two DISTINCT valid proofs under the SAME lockings — exactly what
 * `extraValidProofs` already provides. For each seam k it builds a hybrid run whose inputs
 * [0,k) are proof #0 and [k,n) are proof #1, and asserts the hybrid is REJECTED. A verifier
 * that binds every stage rejects at some cross-boundary check; one with an unbound seam
 * accepts the hybrid — that seam is the vulnerability.
 *
 * Scope: intra-tx bundles only (`Step.intraTx` — one shared transaction where sibling
 * introspection is LIVE, so a spliced input is really read by its neighbours at eval time).
 * Covenant / grouped runs thread state through per-proof NFT commitments the harness bakes and
 * does not enforce continuity on across steps, so a staple there cannot be evaluated soundly
 * without first modelling the token hand-off — left as N/A rather than mis-graded.
 *
 * Only proof#0-side inputs [0,k) can reject: introspection is forward (a chunk reads
 * `tx.inputs[j>idx]`), so a cross-boundary mismatch is always raised by the lower-indexed
 * (proof #0) reader. Those inputs are evaluated in reverse from the seam so a bound seam
 * short-circuits at its boundary input; only a genuinely unbound seam evaluates the whole
 * prefix.
 */
type CrossStageBinding = BenchmarkResult['crossStageBinding'];
const crossStageStaple = (vm: Bch2026Vm, scenario: Scenario, other: Step[] | undefined, bsv: boolean): CrossStageBinding => {
  const base = scenario.valid;
  const isIntraTx = base.length > 1 && base.every((s) => s.intraTx !== undefined);
  if (!isIntraTx) return { applicable: false, seamsTested: 0, unboundSeams: 0 };
  const distinctStages = new Set(base.map((s) => s.checkpoint).filter((c) => c !== undefined)).size;
  if (distinctStages < 2) {
    return { applicable: true, seamsTested: 0, unboundSeams: 0, reason: 'no declared cross-stage checkpoint boundaries' };
  }
  if (other === undefined) {
    return { applicable: true, seamsTested: 0, unboundSeams: 0, reason: 'no accepted, qualified distinct extra proof' };
  }
  let unboundSeams = 0;
  let firstUnboundSeam: string | undefined;
  for (let k = 1; k < base.length; k++) {
    const hybrid = base.map((s, i) => ({
      lockingBytecode: s.lockingBytecode,
      unlockingBytecode: (i < k ? base[i]! : other[i]!).unlockingBytecode,
    }));
    let rejected = false;
    for (let i = k - 1; i >= 0 && !rejected; i--) {
      const o = evaluatePair(vm, hybrid[i]!.lockingBytecode, hybrid[i]!.unlockingBytecode, undefined, { index: i, inputs: hybrid }, undefined);
      rejected = !(bsv ? o.bsvAccepted : o.accepted);
    }
    if (!rejected) {
      unboundSeams += 1;
      firstUnboundSeam ??= `${base[k - 1]!.label} | ${base[k]!.label}`;
    }
  }
  return { applicable: true, seamsTested: base.length - 1, unboundSeams, firstUnboundSeam };
};

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
  bsv: boolean,
  isSpec: boolean,
): { fits: boolean; reason?: string } => {
  // bch-spec raises the standard per-input unlocking cap to 100,000 B (the tx-size cap is
  // unchanged at 100,000 B); grade a spec entry against its own standard limits + VM.
  const maxStdUnlock = isSpec ? SPEC_STANDARD_UNLOCKING_CAP : MAX_STANDARD_UNLOCKING_BYTECODE;
  const overLock = steps.filter((s) => s.lockingBytes > MAX_STANDARD_LOCKING_BYTECODE).length;
  const overUnlock = steps.filter((s) => s.unlockingBytes > maxStdUnlock).length;
  const txBytes = largestTxBytes(scenario.valid);

  const vm = isSpec ? createStandardVmSpec() : createStandardVm();
  const runRejectsStd = (run: Step[]) => run.some((s) => {
    const o = evaluatePair(vm, s.lockingBytecode, s.unlockingBytecode, s.covenant, s.intraTx, s.grouped);
    return !(bsv ? o.bsvAccepted : o.accepted);
  });
  const evalRejects = runRejectsStd(scenario.valid);
  // Every shipped valid proof must be relayable, not just the primary one: a verifier whose
  // budget only fits the primary witness is not standard for the proofs users will submit.
  const otherRuns: [string, Step[]][] = [
    ...(scenario.extraValidProofs ?? []).map((run, k): [string, Step[]] => [`extra proof #${k + 1}`, run]),
    ...(scenario.worstCaseProof?.length ? [['worst-case proof', scenario.worstCaseProof] as [string, Step[]]] : []),
  ];
  const nonStandardProofs = otherRuns.filter(([, run]) => runRejectsStd(run)).map(([label]) => label);

  const reasons = [
    overLock ? `${overLock}/${steps.length} locking >${MAX_STANDARD_LOCKING_BYTECODE} B` : null,
    overUnlock ? `${overUnlock}/${steps.length} unlocking >${maxStdUnlock.toLocaleString('en-US')} B` : null,
    txBytes > MAX_STANDARD_TRANSACTION_SIZE
      ? `tx ${txBytes.toLocaleString('en-US')} B > ${MAX_STANDARD_TRANSACTION_SIZE.toLocaleString('en-US')} B standard size`
      : null,
    evalRejects ? 'a step is non-standard under the standard VM' : null,
    nonStandardProofs.length ? `shipped valid proof(s) non-standard under the standard VM: ${nonStandardProofs.join(', ')}` : null,
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
  const honestRuns = assertHonestRuns(impl, scenario);
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
      proofBinding: impl.proofBinding ?? 'runtime', proofsTested: 0, proofsPassed: 0, runtimeGeneral: false,
      proofIdentity: { ...honestRuns.proofIdentity, reason: 'profile-only: honest runs not executed' },
      ...tokenSafetyOf(scenario, impl),
      inputValidation: { tested: 0, rejected: 0, enforced: false, evidence: 'not-executed', reason: 'profile-only: not executed' },
      crossStageBinding: { applicable: false, seamsTested: 0, unboundSeams: 0 },
      redTeam: { present: false, stale: false, tested: 0, accepted: 0, kinds: [] },
      publicInputs: { declared: false, tested: 0, accepted: 0 },
      layout: { applicable: false, padsTested: 0, malleable: 0, dependencies: [] },
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
      packagingType: profileEnv.type,
      insecurePackagingReason: profileEnv.reason,
    };
  }

  const isSpec = impl.vm === 'bch-spec'; // grade against the proposed bch-spec VM + limits
  const bsv = scenario.bsvOpReturnTerminator === true;
  const vm = createLoosenedVm();
  const steps = scenario.valid.map((s) => runStep(vm, s, bsv));
  const validPassed = steps.every((s) => s.accepted);

  // Shape and declared proof identity were checked before execution. Run counts remain
  // observable even when no proof locator is declared; those counts alone earn no claim.
  const extraRuns = scenario.extraValidProofs ?? [];
  const acceptedExtras = extraRuns.filter((run) => !runRejects(vm, run, bsv));
  const proofBinding = impl.proofBinding ?? 'runtime';
  const proofsTested = 1 + extraRuns.length;
  const proofsPassed = (validPassed ? 1 : 0) + acceptedExtras.length;
  const runtimeGeneral = proofBinding === 'runtime' && honestRuns.proofIdentity.distinct
    && validPassed && acceptedExtras.length === extraRuns.length;
  const distinctAcceptedExtra = validPassed
    ? honestRuns.distinctExtraProofs.find((run) => acceptedExtras.includes(run))
    : undefined;

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

  // BCH compatibility: replay the valid run on the REAL consensus VM (BCH 2026, or the
  // proposed bch-spec VM for a spec-targeted entry). `bchCompatible` therefore means "valid
  // on the VM this entry targets" — a bch-spec entry is NOT valid on current-BCH BCH_2026.
  const realVm = isSpec ? createRealVmSpec() : createRealVm();
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

  // Whole-run rejection does not identify an on-curve/subgroup check: the equation
  // or an unrelated stage may reject. Preserve observations without awarding enforcement.
  const inputRuns = scenario.invalidInputs ?? [];
  const inputRejected = inputRuns.filter((run) => runRejects(vm, run, bsv)).length;
  const inputValidation: BenchmarkResult['inputValidation'] = {
    tested: inputRuns.length, rejected: inputRejected, enforced: false,
    evidence: 'run-rejection-only',
    reason: 'domain enforcement is not demonstrated by whole-run rejection; requires independent review',
  };

  // Preserve the existing seam sampler, requiring accepted, distinct-proof evidence first.
  // Untested applicable bundles remain valid-only; finite outcomes do not prove soundness.
  const crossStageBinding = crossStageStaple(vm, scenario, distinctAcceptedExtra, bsv);

  // Maintainer red-team runs (see harness/redteam.ts): concrete attacks on this entry's exact
  // bytes, written by the maintainers rather than the submitter. Any accepted run fails the entry.
  const redTeamResult = redTeam(vm, impl.id, scenario, bsv);
  // Generic gates (harness/gates.ts): declared public inputs must be bound; pad layout review.
  const publicInputResult = publicInputGate(vm, impl, scenario, bsv);
  const layoutResult = layoutGate(vm, scenario, bsv);

  const opCosts = steps.map((s) => s.operationCost);
  const maxStepOperationCost = opCosts.length ? Math.max(...opCosts) : 0;
  // Per-input op-cost budget at the entry's script cap: BCH_2026 (41+10000)*800 = 8,032,800,
  // or bch-spec (10000+100000)*800 = 88,000,000.
  const budget = isSpec ? specInputBudget() : standardInputBudget();

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
  const std = standardness(scenario, steps, bsv, isSpec);

  return {
    impl,
    profileOnly: false,
    checked: invalidRuns.length > 0,
    validPassed,
    invalidRejected,
    invalidTotal: invalidRuns.length,
    pass: validPassed && acceptedExtras.length === extraRuns.length && worstCaseAccepted && crossStageBinding.reason === undefined && invalidRuns.length > 0 && invalidRejected === invalidRuns.length && env.secure && crossStageBinding.unboundSeams === 0 && redTeamResult.accepted === 0 && publicInputResult.accepted === 0,
    crossStageBinding,
    redTeam: redTeamResult,
    publicInputs: publicInputResult,
    layout: layoutResult,
    proofBinding,
    proofsTested,
    proofsPassed,
    runtimeGeneral,
    proofIdentity: honestRuns.proofIdentity,
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
    packagingType: env.type,
    insecurePackagingReason: env.reason,
    // bch-spec entries: also grade on TXv5 as written (density base 41; issue #35 option 2)
    ...(isSpec ? { txv5: txv5Grade(scenario, bsv, runScore) } : {}),
  };
};

// Attach the evidence-based review status (harness/review-status.ts) to every registered
// implementation; an id missing from that table defaults to 'unreviewed'.
for (const impl of REGISTRY) impl.reviewStatus = reviewStatusOf(impl);

/** Implementations skipped in full runs because they are too slow/expensive to evaluate
 * (for now: the genpow verifiers). SKIP_IMPLS is a comma-separated, case-insensitive list
 * of id substrings; set SKIP_IMPLS='' to run everything. Explicit positive CLI filters
 * (`pnpm benchmark genpow`) bypass the skip. */
const skipFilters = (process.env.SKIP_IMPLS ?? 'genpow')
  .split(',')
  .map((s) => s.trim().toLowerCase())
  .filter((s) => s.length > 0);
export const isSkipped = (id: string): boolean => skipFilters.some((f) => id.toLowerCase().includes(f));

/** Run every registered implementation and return its BenchmarkResult (no printing).
 * Shared by the CLI table and the JSON exporter. Demos are excluded by default;
 * SKIP_IMPLS-matched implementations (default: genpow) are excluded too. */
export const computeResults = async (includeDemos = false): Promise<BenchmarkResult[]> => {
  const registry = (includeDemos ? REGISTRY : REGISTRY.filter((i) => i.demo !== true))
    .filter((i) => !isSkipped(i.id));
  const skipped = REGISTRY.filter((i) => isSkipped(i.id));
  if (skipped.length > 0) console.error(`skipping (SKIP_IMPLS): ${skipped.map((i) => i.id).join(', ')}`);
  const results: BenchmarkResult[] = [];
  for (const impl of registry) {
    let scenario: Scenario;
    try {
      scenario = await impl.load();
    } catch (error) {
      console.error(`${impl.id}: failed to load: ${String(error)}`);
      continue;
    }
    results.push(benchmark(impl, scenario));
  }
  return results;
};

/** Load and benchmark ONE implementation. Unlike computeResults, a load failure THROWS instead of
 * silently omitting the entry (the incremental exporter must never drop a row unnoticed). */
export const runImplementation = async (impl: Implementation): Promise<BenchmarkResult> =>
  benchmark(impl, await impl.load());

const fmt = (n: number) => n.toLocaleString();
const padR = (s: string, w: number) => s.padEnd(w);
const padL = (s: string, w: number) => s.padStart(w);

/**
 * The single correctness verdict for an entry, evaluated in precedence order (first match
 * wins). Both the live progress line and the results table derive their label from this, so
 * the ranking — and where a new gate like the cross-stage staple slots in — lives in ONE place.
 */
type Verdict = 'profile' | 'insecure-packaging' | 'pass' | 'extra-proof-fail' | 'worst-case-fail' | 'cross-stage-fail' | 'redteam-fail' | 'public-input-fail' | 'valid-only' | 'fail';
const verdictOf = (r: BenchmarkResult): Verdict => {
  if (r.profileOnly) return 'profile';
  if (!r.securePackaging) return 'insecure-packaging';
  if (r.pass) return 'pass';
  if (r.proofsPassed < r.proofsTested) return 'extra-proof-fail';
  if (r.worstCase?.accepted === false) return 'worst-case-fail';
  if (r.crossStageBinding.unboundSeams > 0) return 'cross-stage-fail';
  if (r.redTeam.accepted > 0) return 'redteam-fail';
  if (r.publicInputs.accepted > 0) return 'public-input-fail';
  if (r.validPassed) return 'valid-only';
  return 'fail';
};

/** One-line status printed as each entry finishes (verbose phrasing). */
const progressLabel = (r: BenchmarkResult): string => ({
  profile: 'profile-only (size)',
  'insecure-packaging': 'DISALLOWED (insecure P2SH20 envelope)',
  pass: 'PASS',
  'extra-proof-fail': 'FAIL (honest proof run rejected)',
  'worst-case-fail': 'FAIL (worst-case proof rejected)',
  'cross-stage-fail': 'FAIL (cross-stage staple accepted)',
  'redteam-fail': 'FAIL (maintainer red-team attack accepted)',
  'public-input-fail': 'FAIL (mutated public inputs accepted)',
  'valid-only': 'valid-only (required fixture evidence missing)',
  fail: 'FAIL',
}[verdictOf(r)]);

/** Compact `correctness` cell for the results table (some verdicts carry counts). */
const correctnessCell = (r: BenchmarkResult): string => {
  switch (verdictOf(r)) {
    case 'profile': return 'profile (size)';
    case 'insecure-packaging': return 'DISALLOWED (P2SH20)';
    case 'pass': return `PASS (${r.invalidRejected}/${r.invalidTotal}✗${r.bsvOpReturn ? ', BSV OP_RETURN' : ''})`;
    case 'extra-proof-fail': return `FAIL (honest runs ${r.proofsPassed}/${r.proofsTested})`;
    case 'worst-case-fail': return 'FAIL (worst-case✗)';
    case 'cross-stage-fail': return 'FAIL (cross-stage staple)';
    case 'redteam-fail': return `FAIL (red-team ${r.redTeam.accepted}/${r.redTeam.tested})`;
    case 'public-input-fail': return `FAIL (public inputs ${r.publicInputs.accepted}/${r.publicInputs.tested})`;
    case 'valid-only': return 'valid-only';
    case 'fail': return 'FAIL';
  }
};

const main = async () => {
  const cliArgs = process.argv.slice(2);
  const includeDemos = cliArgs.includes('--demos');
  // Positional args are case-insensitive substring filters on the implementation id,
  // OR'd together: `pnpm benchmark genpow`, `pnpm benchmark singleton chunked`.
  // A filter selects from the FULL registry, so explicitly matching a demo id shows
  // it without --demos; with no filter, demos stay hidden unless --demos is given.
  const filters = cliArgs.filter((a) => !a.startsWith('--')).map((a) => a.toLowerCase());
  // explicit positive filters bypass SKIP_IMPLS (so `pnpm benchmark genpow` still works)
  const registry =
    filters.length > 0
      ? REGISTRY.filter((i) => filters.some((f) => i.id.toLowerCase().includes(f)))
      : (includeDemos
        ? REGISTRY
        : REGISTRY.filter((i) => i.demo !== true)).filter((i) => !isSkipped(i.id));
  if (filters.length > 0 && registry.length === 0) {
    console.error(`no implementation id matches: ${filters.join(', ')}\navailable ids:`);
    for (const i of REGISTRY) console.error(`  ${i.id}`);
    process.exit(1);
  }
  console.log(
    `benchmarking ${registry.length} implementation(s) on the BCH 2026 VM (limits loosened)` +
    (filters.length > 0
      ? `  [filtered: ${filters.join(', ')}]`
      : includeDemos ? '' : '  [demos hidden; --demos to show]') + '\n',
  );
  const results: BenchmarkResult[] = [];
  for (const impl of registry) {
    process.stdout.write(`- ${impl.id} ... `);
    try {
      const scenario = await impl.load();
      const r = benchmark(impl, scenario);
      results.push(r);
      console.log(progressLabel(r));
    } catch (e) {
      console.log(`ERROR: ${(e as Error).message}`);
      process.exitCode = 1;
    }
  }

  // group into separate leaderboards by proof system + structure; a bch-spec (proposed-upgrade)
  // entry gets its own track so it is not ranked against current-BCH verifiers (different limits).
  const tracks = new Map<string, BenchmarkResult[]>();
  for (const r of results) {
    const key = `${r.impl.proofSystem}  [${r.impl.structure}]${r.impl.vm === 'bch-spec' ? '  · bch-spec (proposed 100 kB scripts)' : ''}`;
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
      const correctness = correctnessCell(r);
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
      if (r.impl.vm === 'bch-spec') {
        console.log(`    > VM target: PROPOSED bch-spec upgrade (100,000-byte scripts, op-cost budget (10000+len)x800 = up to 88,000,000/input) — NOT valid on current BCH (BCH_2026 caps scripts at 10,000 B). "BCH compatible" above = validates on the bch-spec VM.`);
        const t = r.txv5;
        if (t) {
          const mode = (m: { asShipped: boolean; padded?: { padBytes: number; score: number } }) =>
            m.asShipped ? 'valid as shipped' : m.padded ? `+${fmt(m.padded.padBytes)} B pad -> ${fmt(m.padded.score)}` : 'rejects';
          const tail = t.padding === 'not-paddable'
            ? `not paddable as shipped (${t.notPaddableReason})${t.estimate ? `; estimate with a pad slot ${fmt(t.estimate.score)}` : ''}`
            : `consensus ${mode(t.consensus)}, standard ${mode(t.standard)}${t.standard.fits ? '' : ` (non-standard: ${t.standard.policyReason ?? t.standard.reason})`}`;
          console.log(`    > TXv5 as written (density base 41, budget (41+len)x800): ${tail}`);
          if (t.variant) console.log(`    > TXv5 measured on the TXv5-grading variant: ${t.variant.description} (variant invalid runs rejected on TXv5, budget lifted: ${t.variant.invalidRejected}/${t.variant.invalid})`);
          const sum = txv5Summary(t, r.totalBytes + r.totalTxOverheadBytes);
          const w = sum.worst;
          console.log(`    > TXv5 over all ${sum.runs} honest runs: ${sum.standard ? 'every figure standard' : `NOT standard (${sum.nonStandard?.run}: ${sum.nonStandard?.reason ?? 'non-standard'})`}`
            + `${w ? `; worst case ${w.run} ${w.status}${w.score !== null ? ` ${w.estimated ? '~' : ''}${fmt(w.score)} (${w.mode})` : ''}` : ''}`
            + `${sum.mixed ? '; honest runs fall on both sides of the budget (some valid as shipped)' : ''}`);
        }
      }
      if (!r.profileOnly) {
        console.log(`    > standardness: ${r.fitsBchStandardness ? 'standard — relayable under default mempool policy' : `non-standard (${r.bchStandardnessReason ?? 'relay limit'}); valid at consensus, must be mined directly`}`);
      }
      if (!r.profileOnly) {
        if (r.proofBinding === 'baked') {
          console.log(`    > proof generality: instance-specific — proof binding declared baked`);
        } else {
          console.log(`    > proof generality: ${r.runtimeGeneral ? 'distinct-proof fixtures accepted' : 'NOT DEMONSTRATED'} — ${r.proofsPassed}/${r.proofsTested} supplied runs accepted; ${r.proofIdentity.reason ?? 'declared proof components differ (finite fixture evidence only)'}`);
        }
        if (r.tokenThreaded) {
          console.log(`    > token safety: ${r.tokenSafetyEnforced ? 'ENFORCED' : 'NOT enforced'} — state is threaded through the NFT commitment` +
            (r.tokenSafetyEnforced ? '' : ', but category continuity / capability are not pinned (a real deployment must enforce them)'));
        }
        if (r.impl.proofSystem === 'Groth16' || r.inputValidation.tested > 0) {
          console.log(`    > input validation: NOT DEMONSTRATED — ${r.inputValidation.rejected}/${r.inputValidation.tested} supplied runs rejected; ${r.inputValidation.reason}`);
        }
        const csb = r.crossStageBinding;
        if (csb.reason) {
          console.log(`    > cross-stage binding: NOT TESTED — ${csb.reason}`);
        } else if (csb.applicable) {
          console.log(csb.unboundSeams === 0
            ? `    > cross-stage binding: ${csb.seamsTested} sampled seams rejected with a qualified second proof (finite fixture evidence only)`
            : `    > cross-stage binding: UNBOUND — ${csb.unboundSeams}/${csb.seamsTested} seam(s) accept a spliced 2-proof hybrid (first at "${csb.firstUnboundSeam}"): one proof's stage can be stapled onto another proof's remaining stages`);
        }
        const pi = r.publicInputs;
        console.log(!pi.declared
          ? `    > public inputs: not declared (Implementation.publicInputs) - binding not mutation-tested`
          : pi.accepted === 0
            ? `    > public inputs: bound - all ${pi.tested} mutated claims rejected`
            : `    > public inputs: UNBOUND - ${pi.accepted}/${pi.tested} mutated claims ACCEPTED (first: ${pi.firstAccepted})`);
        const lay = r.layout;
        if (lay.applicable) console.log(lay.dependencies.length === 0
          ? `    > layout: ${lay.padsTested} pads checked, ${lay.malleable} free-length, no sibling depends on their layout`
          : `    > layout: REVIEW - ${lay.dependencies.map((d) => `input ${d.input} push ${d.push} (free length) breaks input(s) ${d.siblings.join(',')}`).join('; ')}: a sibling reads past a free-length push at a fixed offset, or pins the whole unlocking`);
        const rt = r.redTeam;
        if (rt.present) {
          console.log(rt.stale
            ? `    > red-team: STALE — the maintainer attack file targets lockings this entry no longer ships; regenerate it`
            : rt.accepted === 0
              ? `    > red-team: all ${rt.tested} maintainer attack run(s) rejected (${rt.kinds.join(', ')})`
              : `    > red-team: BROKEN — ${rt.accepted}/${rt.tested} maintainer attack run(s) ACCEPTED (first: "${rt.firstAccepted}"; ${rt.kinds.join(', ')})`);
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
