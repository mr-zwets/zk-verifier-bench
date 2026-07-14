// BCH-native BLS12-381 Groth16 verifier — INTRA-TRANSACTION LINKED + RESIDUE with LARGE (100 kB)
// input scripts, targeting the PROPOSED bch-spec upgrade. Identical mechanism and residue chunk
// graph to bch-groth16-bls12381-intratx-residue (OP_INPUTBYTECODE forward-checking, no NFT
// commitment, no hashing; GLV vk_x MSM + c^-|x|-FUSED batched Miller with e(alpha,beta) baked and
// the G2 on-curve+subgroup check fused into the first/last Miller chunks + witnessed-residue mu_27A
// final-exp tail), but each chunk is sized to a 100 kB unlocking instead of 10 kB.
//
// Why it needs bch-spec: current BCH (BCH_2026) caps every script at 10,000 B and grants an input
// (41 + unlockingLen) * 800 op-cost; the current 256.81M-op plan uses 39 inputs. The proposed
// bch-spec upgrade raises the per-script cap to 100,000 B and the density-control base to 10,000,
// so an input gets
// (10000 + unlockingLen) * 800 = up to 88,000,000 op — ~11x. The SAME residue verifier therefore
// collapses to ~one fat input per stage floor:
//
//   GLV vk_x MSM             1 input
//   c^-|x|-fused Miller      3 inputs   (op-bound; the G2 on-curve+subgroup check stays fused in)
//   witnessed-residue tail   1 input    (mu_27A ((w^|x|)*w)^9 walk with the finalize verdict fused in)
//                            --------
//                            5 inputs   (one non-standard <1 MB transaction)
//
// 270,713 B / 250,648,934 op over 5 inputs (vs 324,320 B / 256,806,318 op over 39 for the
// current-BCH residue build). The arithmetic is unchanged; fewer state boundaries also remove
// repeated checks and padding. Every input fits its own bch-spec budget (op-cost <= 88,000,000,
// scripts <= 100,000 B); deployed as P2SH32 so each chunk redeem rides in the scriptSig where it
// counts toward the op-cost budget. Graded against the real bch-spec VM (createVirtualMachineBchSpec).
// Its worst-case field uses the same deterministic valid all-position stress proof as the 10 kB
// builds and is separately executed against these five bch-spec lockings.
//
// Vectors: groth16_contract/chunked/intratx/build_vectors_residue_bls_large.mjs ->
// src/bch/groth16-bls12381-intratx-residue-large-vectors.json.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep { label: string; locking: string; unlocking: string; checkpoint?: string }
interface Vectors { steps: RawStep[]; extraValidProofs?: RawStep[][]; worstCaseProof?: RawStep[]; invalid?: RawStep[][] }

const v = JSON.parse(readFileSync('src/bch/groth16-bls12381-intratx-residue-large-vectors.json', 'utf8')) as Vectors;

// Turn one run (an ordered list of chunk inputs) into Step[] sharing ONE inputs array, so each
// step is evaluated against the same multi-input transaction (its tx.inputs[idx±1] introspection
// resolves to the real siblings).
const toRun = (raw: RawStep[]): Step[] => {
  const inputs = raw.map((s) => ({ lockingBytecode: hexToBin(s.locking), unlockingBytecode: hexToBin(s.unlocking) }));
  return raw.map((s, i) => ({ label: s.label, lockingBytecode: inputs[i]!.lockingBytecode, unlockingBytecode: inputs[i]!.unlockingBytecode, checkpoint: s.checkpoint, intraTx: { index: i, inputs } }));
};

export const bchGroth16Bls12381IntratxResidueLarge: Implementation = {
  id: 'bch-groth16-bls12381-intratx-residue-large',
  name: 'BCH BLS12-381 Groth16 intra-tx linked + residue, LARGE 100 kB scripts (whole verifier in 5 inputs of one transaction, PROPOSED bch-spec)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  vm: 'bch-spec',
  source:
    'BCH-native CashScript: the residue-optimized full BLS12-381 Groth16 verifier laid out as the ' +
    'INPUTS of ONE transaction, sized for the PROPOSED bch-spec upgrade (100,000-byte scripts, ' +
    'op-cost budget (10000 + unlockingLen) * 800 = up to 88,000,000 per input). Same ' +
    'forward-checking as bch-groth16-bls12381-intratx-residue (each input carries its incoming ' +
    'state as a raw 48-byte-limb blob and binds the chain via tx.inputs[idx+1].unlockingBytecode ' +
    'introspection — no NFT-commitment hand-off, no hashing, arbitrary intermediate size) and the ' +
    'same residue chunk graph (GLV vk_x MSM, c^-|x|-FUSED batched Miller with e(alpha,beta) baked ' +
    'and the G2 on-curve+prime-order-subgroup validation fused into the first/last Miller chunks, ' +
    'witnessed-residue mu_27A final-exp TAIL), but each chunk fills a 100 kB input instead of ' +
    '10 kB, collapsing the verifier from 39 inputs to 5 (GLV vk_x 1, fused Miller 3, residue ' +
    'walk+finalize tail 1), 270,713 B / 250,648,934 op. The arithmetic is unchanged; fewer state ' +
    'boundaries also remove repeated checks and padding. The residue witness (c, cInv) threads ' +
    'through every fused-Miller chunk and is re-checked in the tail (c*cInv==ONE, mu_27A membership ' +
    'on w); the verdict is fF*w==frob(c,1). Every input fits one bch-spec input budget (op-cost <= ' +
    '88,000,000, scripts <= 100,000 B); the whole verifier is one non-standard (<1 MB) transaction. ' +
    'NOT valid on current BCH (BCH_2026, which caps scripts at 10,000 B) — it requires the bch-spec ' +
    'upgrade. Deployed as P2SH32 so each chunk redeem rides in the scriptSig where it counts toward ' +
    'the op-cost budget. The supplied worst-case run uses the same deterministic valid ' +
    'all-position stress proof as the current-BCH builds and is executed separately against ' +
    'these five bch-spec lockings.',
  load: async () => ({
    valid: toRun(v.steps),
    extraValidProofs: (v.extraValidProofs ?? []).map(toRun),
    worstCaseProof: v.worstCaseProof ? toRun(v.worstCaseProof) : undefined,
    invalid: (v.invalid ?? []).map(toRun),
  }),
};
