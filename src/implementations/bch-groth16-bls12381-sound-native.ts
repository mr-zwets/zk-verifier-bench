// bls-native-sound: a sound-by-construction BLS12-381 Groth16 verifier for CURRENT BCH (bch-2026), as ONE standard
// transaction with 4 P2SH32 inputs that all lock to the same redeem R. R pins the graph (exactly 4 inputs, every
// input spending the same locking), loads the shared program from fixed byte ranges of two carrier inputs, checks its
// SHA256, and runs it; the program dispatches on the input index into 4 roles. The mathematics is SI-GLS (one batched
// torus identity at +-z over 33 chunk identities, GT-GLS folding of e(vk_x, gamma) with an exact base-|x| integer
// binding, residue root), with an all-affine B walk whose slopes are each fixed by an exact field equation and the
// endpoint [|x|]B = -psi(B) as the G2 check. Input 0 is the head (transcript over every input's committed region,
// challenges, statement checks, binding, quotient, final identity) and runs the first Miller events; inputs 1..3 run
// the rest and hand over byte-exact canonical claims. Every accept-relevant value is computed on-chain, a baked VK
// constant (delta blocks pinned by SHA256 in the program), hash-committed before its challenge, or fixed by an exact
// equation. Statement: full Groth16 under the fixed VK, public inputs n0, n1 in input 0, push 1 (the region G) at
// bytes 384 and 416, 32-byte little-endian (canonical: 0 <= n < r enforced on-chain).
// Owning source: chunked/bls12-381/bls-native-sound in groth16_cashscript.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';
import { bls12381SoundNativeProofInputs } from './groth16-proof-inputs.js';

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
}

const vectors = JSON.parse(
  readFileSync('src/bch/groth16-bls12381-sound-native-vectors.json', 'utf8'),
) as Vectors;

// one transaction: every step is one input of the same tx (OP_INPUTBYTECODE / OP_UTXOBYTECODE resolve to siblings)
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

export const bchGroth16Bls12381SoundNative: Implementation = {
  id: 'bch-groth16-bls12381-sound-native',
  // where the claimed public inputs live (public-input binding gate, harness/gates.ts)
  publicInputs: [
    { input: 0, push: 1, name: 'n0', offset: 384, encoding: 'le32' },
    { input: 0, push: 1, name: 'n1', offset: 416, encoding: 'le32' },
  ],
  name: 'BCH Groth16 SI-GLS sound native (BLS12-381), one transaction with 4 inputs (bch-2026)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  proofInputs: bls12381SoundNativeProofInputs,
  source:
    'SI-GLS mathematics split over 4 P2SH32 inputs of one bch-2026 transaction (uniform redeem: input count and ' +
    'identical lockings pinned, hash-authenticated shared program loaded from two carriers; role by input index); ' +
    'all-affine B walk with exact slope equations and the psi endpoint G2 check; head transcript over every input\'s ' +
    'committed region; exact base-|x| GT-GLS binding of n0, n1; canonical byte-exact handovers between roles ' +
    '(chunked/bls12-381/bls-native-sound).',
  load: async () => ({
    valid: toRun(vectors.steps),
    extraValidProofs: (vectors.extraValidProofs ?? []).map(toRun),
    worstCaseProof: vectors.worstCaseProof ? toRun(vectors.worstCaseProof) : undefined,
    invalid: (vectors.invalid ?? []).map(toRun),
  }),
};
