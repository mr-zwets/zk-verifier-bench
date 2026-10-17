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
// seed densless-msm-slim-v1; peak budgets 98.1 / 95.7 / 90.2 / 98.3 / 83.8 %.
// The order reader accepts minimally encoded variable-width numbers; default and explicit-full
// exports match. Source regression includes a valid proof with a 31-byte terminal number.
// Exact-byte attack file: the original 36 cases refreshed plus 8 issue39 cases (44 total),
// re-encoded by GPT-6.1 Sol at Kallisti's request; upstream maintainer review remains pending.
// Primary full-pinned score 35,125 = 34,890 script +235 overhead; no universal resource bound claimed.
// Co8 with guarded floating prime caches: 13 MADD sites and six selected DBL sites; full pins, zero padding.
// Optional raw-dbl/raw-madd/raw-both profiles score 35,282 / 35,496 / 35,636 bytes.
// Consensus native costs: 24,830,569 / 24,690,991 / 24,669,602; all keep full pins and zero pads.
// Raw-both alone uses MSM_SPLIT=27 MSM_CUTS=37,43,51,52; default/raw-dbl/raw-madd remain split31.
// Raw-both retains DBL418/terminal copy and compacts executor cleanup; all pre-redeem values fixed.
// Raw-both minimum sampled dense native input margin: 61,094; no changed-range universal cap claimed.
// Each retains five core + short +30 archived dense proofs, 44 attacks and both native modes.
// Default locking sha256:
//   exec0+vkx-msm           b71630e7d38a0576de09894f8c231527e7fe73ba8e236ac94e2aebc27bb072ee
//   exec1+vkx-msm           b71630e7d38a0576de09894f8c231527e7fe73ba8e236ac94e2aebc27bb072ee
//   exec2+vkx-msm           b71630e7d38a0576de09894f8c231527e7fe73ba8e236ac94e2aebc27bb072ee
//   genesis+vkx-msm         2e2ff6de1e924f24075897b87be8f8616be5a72b4476918f2f48e479371c1eaa
//   terminal+vkx-msm-final  97769eb23ff1c3aa4d4dd1eba2a57ff5e9fe433ed600b5fa82273356c44135e6
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

const slim = (id: string, name: string, path: string): Implementation => {
  const vectors = JSON.parse(readFileSync(path, 'utf8')) as Vectors;
  return {
    id,
    // where the claimed public inputs live (public-input binding gate, harness/gates.ts)
    publicInputs: [{ input: 4, push: 53, name: 'n0' }, { input: 4, push: 52, name: 'n1' }],
    name,
    proofSystem: 'Groth16',
    field: 'BN254',
    structure: 'single-tx',
    proofBinding: 'runtime',
    source:
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
};

const id = 'bch-groth16-intratx-pairfold5-densless-msm-slim';
const name = 'BCH Groth16 intra-tx PairFold-5 densless with sound vk_x MSM (slim MSM state)';
export const bchGroth16IntratxPairfold5DenslessMsmSlim = slim(
  id, name, 'src/bch/groth16-intratx-pairfold5-densless-msm-slim-vectors.json',
);

// Larger helper bodies lower native cost; retain the smaller floating-cache entry.
export const bchGroth16IntratxPairfold5DenslessMsmSlimCacheProfiles =
  ['raw-dbl', 'raw-madd', 'raw-both'].map(profile => slim(
    `${id}-${profile}`, `${name} (${profile})`,
    `src/bch/groth16-intratx-pairfold5-densless-msm-slim-${profile}-vectors.json`,
  ));
