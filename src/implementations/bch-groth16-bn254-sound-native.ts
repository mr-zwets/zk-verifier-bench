// bn-native-sound (SI-MX3): a sound-by-construction BN254 Groth16 verifier for CURRENT BCH (bch-2026), as ONE
// transaction with 3 P2SH32 inputs that share one 65-byte redeem. The redeem loads the verifier code from fixed
// byte ranges of inputs 0 and 1, checks its SHA256 and runs it; the code pins the graph (exactly 3 inputs, all
// spending the same locking) and dispatches on the input index into 3 roles. The mathematics is SI-GLS (one
// batched torus identity at +-z, GT-GLS folding of e(vk_x, gamma), residue root), with an affine B walk whose
// slopes are fixed by exact inverse-norm equations; the roles split the 65 Miller events at chunk boundaries and
// chain their state by canonical handovers checked byte-exactly. Every accept-relevant value is computed on-chain,
// a baked VK constant, hash-committed before its challenge, or fixed by an exact equation.
// Statement: full Groth16 under the fixed VK, public inputs n0, n1 packed in input 2, push 1 (STMT) at bytes
// 256 and 288, 32-byte little-endian (canonical: 0 <= n < r enforced on-chain by every role).
// Owning source: chunked/bn254/bn-native-sound in groth16_cashscript.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';
import { bn254SoundNativeProofInputs } from './groth16-proof-inputs.js';

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
  readFileSync('src/bch/groth16-bn254-sound-native-vectors.json', 'utf8'),
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

export const bchGroth16Bn254SoundNative: Implementation = {
  id: 'bch-groth16-bn254-sound-native',
  // where the claimed public inputs live (public-input binding gate, harness/gates.ts)
  publicInputs: [
    { input: 2, push: 1, name: 'n0', offset: 256, encoding: 'le32' },
    { input: 2, push: 1, name: 'n1', offset: 288, encoding: 'le32' },
  ],
  name: 'BCH Groth16 SI-MX3 sound native (BN254), one transaction with 3 inputs (bch-2026)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  proofInputs: bn254SoundNativeProofInputs,
  source:
    'SI-GLS mathematics split over 3 P2SH32 inputs of one bch-2026 transaction (shared redeem loads hash-authenticated ' +
    'code; graph pinned by input count and identical lockings; affine B walk with exact inverse-norm witnesses; ' +
    'per-input digests of the committed data; canonical handovers between roles) (chunked/bn254/bn-native-sound).',
  load: async () => ({
    valid: toRun(vectors.steps),
    extraValidProofs: (vectors.extraValidProofs ?? []).map(toRun),
    worstCaseProof: vectors.worstCaseProof ? toRun(vectors.worstCaseProof) : undefined,
    invalid: (vectors.invalid ?? []).map(toRun),
  }),
};
