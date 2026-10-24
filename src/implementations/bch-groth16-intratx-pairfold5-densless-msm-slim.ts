// WITHDRAWN full-verifier qualification; retained as a historical measurement artifact.
// The vk_x MSM description is component-level and does not establish pairing soundness.
// See https://github.com/mr-zwets/zk-verifier-bench/issues/49.
// PairFold-5 densless with a sound vk_x, SLIM MSM state + malleability pins (kzKallisti).
// Same pairing programs and GLV Straus vk_x MSM as bch-groth16-intratx-pairfold5-densless-msm;
// MSM state layout is slim, and the terminal redeem prepends length/order/sign-bit pins.
// Owning source: chunked/bn254/densless-msm-slim in groth16_cashscript (byte-exact export; SLIM_PINS=full).
//
// Construction / what is enforced:
// - Claimed public inputs n0, n1 are the TERMINAL's own number pushes (input 4, pushes 53, 52). The
//   terminal range-checks 0 <= n < r and checks the GLV decomposition of the witness bytes w against
//   them (S0 = k10 + lambda*k20 == n0, S1 = k11 + lambda*k21 == n1 mod r).
// - w (64 bytes, one per Straus position) lives only in the terminal's state push (w, X, Y, Z;
//   exactly 160 B, required by the terminal; it is the last push before the terminal redeem, whose
//   length the locking pins). Genesis (input 3, positions 63..31) and the executors (inputs 0, 1, 2;
//   positions by OP_INPUTINDEX, cuts 33,43,54,60) read their witness bytes from that window,
//   located from the end of input 4's unlocking.
// - Each stage pins the next stage's X, Y, Z (96-B executor state push, 160-B terminal push) from the
//   end of the receiver's unlocking; the terminal finishes positions 3..0, adds IC0 - [2^64]G,
//   converts to affine with a witnessed Z inverse and requires the result to equal the genesis vk_x
//   that the Miller loop consumes. Terminal pins input count and all worker lockings.
// - Malleability pins (paid once, prepended to the densless terminal): PUSHDATA2 length pins on the
//   terminal header/quot and each executor quot; canonical non-decreasing order on terminal witness
//   limbs 2..11 (minimally encoded LE numbers); fixed-table sign-bit clear on all three executor
//   tables (OP_DEFINE/INVOKE). Closes the eight witness-malleability findings shared with the parent
//   (see zk-verifier-bench#39).
// Soundness: every stage consumes one w, which the terminal binds to its claimed n0, n1; the X, Y, Z
// chain is pinned stage to stage, so vk_x = IC0 + n0*IC1 + n1*IC2 for the claimed inputs, and the
// pairing check uses that vk_x. A forged claim needs a forged w, which changes vk_x. Length/order/
// sign pins do not change the statement; they reject alternate witnesses for the same statement.
// Finite dense-witness sample: 30/30 deterministic proofs accept on standard BCH2026,
// seed densless-msm-slim-v1; peak budgets 98.3 / 95.9 / 90.4 / 98.8 / 84.5 %.
// The order reader accepts minimally encoded variable-width numbers; default and explicit-full
// exports match. Source regression includes a valid proof with a 31-byte terminal number.
// Exact-byte attack file: the original 36 cases refreshed plus 8 issue39 cases (44 total),
// re-encoded by GPT-6.1 Sol at Kallisti's request; upstream maintainer review remains pending.
// Primary full-pinned score 35,143 = 34,908 script +235 overhead; no universal resource bound claimed.
// First-use floating prime caches: 13 MADD sites and six selected DBL sites; full pins, zero padding.
// Locking sha256:
//   exec0+vkx-msm           9232671d582bca3a830aaa9b3c320f60113aa6b2bd6e4d715c042ec83010a500
//   exec1+vkx-msm           9232671d582bca3a830aaa9b3c320f60113aa6b2bd6e4d715c042ec83010a500
//   exec2+vkx-msm           9232671d582bca3a830aaa9b3c320f60113aa6b2bd6e4d715c042ec83010a500
//   genesis+vkx-msm         09ee4f93c1b8913bccfd31dd7f83d6e56197424e1c17359738d748a7b035c7ea
//   terminal+vkx-msm-final  ad86d37567945f43fa08fc8a828989eced4708cc263bf33c8d88d3f09b675958
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep {
  label: string;
  locking: string;
  unlocking: string;
  checkpoint?: string;
}

interface Vectors {
  steps: RawStep[];
  extraValidProofs?: RawStep[][];
  worstCaseProof?: RawStep[];
  invalid?: RawStep[][];
  invalidInputs?: RawStep[][];
}

const vectors = JSON.parse(
  readFileSync('src/bch/groth16-intratx-pairfold5-densless-msm-slim-vectors.json', 'utf8'),
) as Vectors;

const toRun = (raw: RawStep[]): Step[] => {
  const inputs = raw.map((step) => ({
    lockingBytecode: hexToBin(step.locking),
    unlockingBytecode: hexToBin(step.unlocking),
    valueSatoshis: 1000n,
    sequenceNumber: 0,
  }));
  return raw.map((step, index) => ({
    label: step.label,
    lockingBytecode: inputs[index]!.lockingBytecode,
    unlockingBytecode: inputs[index]!.unlockingBytecode,
    checkpoint: step.checkpoint,
    valueSatoshis: 1000n,
    sequenceNumber: 0,
    intraTx: { index, inputs },
  }));
};

export const bchGroth16IntratxPairfold5DenslessMsmSlim: Implementation = {
  id: 'bch-groth16-intratx-pairfold5-densless-msm-slim',
  // where the claimed public inputs live (public-input binding gate, harness/gates.ts)
  publicInputs: [{ input: 4, push: 53, name: 'n0' }, { input: 4, push: 52, name: 'n1' }],
  name: 'BCH Groth16 intra-tx PairFold-5 densless with sound vk_x MSM (slim MSM state)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'WITHDRAWN full-verifier claim: the retained pairing/terminal construction has a confirmed correctness gap. ' +
    'Historical program and measurement bytes are preserved; the vk_x MSM description is component-level. ' +
    'PairFold-5 densless (chunked/bn254/densless-recovered) with the GLV Straus vk_x MSM in a slim state layout ' +
    '(chunked/bn254/densless-msm-slim): claimed inputs are terminal pushes, witness bytes live only in the terminal state, ' +
    'executors carry X, Y, Z. Five P2SH32 inputs, one standard transaction; the terminal pins input count and all worker lockings.',
  load: async () => ({
    valid: toRun(vectors.steps),
    extraValidProofs: (vectors.extraValidProofs ?? []).map(toRun),
    worstCaseProof: vectors.worstCaseProof ? toRun(vectors.worstCaseProof) : undefined,
    invalid: (vectors.invalid ?? []).map(toRun),
  }),
};
