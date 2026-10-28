// Rolled residue singleton (Track 2 "frontier middle" design T2, BN254): a rolled, single-input exact-identity
// Groth16 verifier with a real Fp12 accumulator in the SI-GLS polynomial basis (Fp12 = Fp[X]/M, M = X^12 - 18X^6 + 82)
// and no Miller hints, no Fiat-Shamir and no Schwartz-Zippel. One rolled OP_BEGIN loop over the 65 NAF events of
// 6x+2 runs three projective G2 walks on-chain: B with P = -A, gamma with P = vk_x, delta with P = C. The residue root
// c (a monic class representative, 6 words) is folded at the 21 addition events, e(alpha, beta) is a baked monic
// class representative, and the terminal checks the class identity [F * c^(p^2)] == [c^p * c^(p^3)] EXACTLY (zero odd
// part). B in G2 by the reviewed SI-GLS endpoint (X:Y:Z) == -psi^3(B) with Z != 0; vk_x = IC0 + n0 IC1 + n1 IC2 by a
// joint Jacobian double-and-add with a witnessed zInv (exceptional steps force Z = 0, then Z * zInv == 1 fails).
// ONE P2SH32 input under BCH 2026 script sizes (redeem and unlocking under 10,000 B); it needs a much looser op-cost
// density than bch-2026, so it is NOT bch-compatible as shipped (same status as the singletons).
// Witness: push 0 = W, 17 32-byte little-endian words: xA yA xB0 xB1 yB0 yB1 xC yC n0 n1 sc0..sc5 zInv (every word
// < p, n < r, SIZE(W) == 544, DEPTH == 1 at entry). Statement: full Groth16 under the fixed VK of the bench BN254
// singleton fixture (src/checkpoints/pairing-vectors.json).
// Owning source: research/frontier-middle/bn254/rolled-residue in groth16_cashscript. Vectors: rolled-residue/export.mjs:
// the bench's EXISTING BN254 singleton proofs (committed, multiproof extras, dense worst case) and, as invalid runs,
// exactly their existing invalid statements (tampered public inputs), with the prover's best witness.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';
import { bn254RolledResidueProofInputs } from './groth16-proof-inputs.js';

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

const vectors = JSON.parse(readFileSync('src/bch/groth16-singleton-rolled-residue-vectors.json', 'utf8')) as Vectors;

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

export const bchGroth16SingletonRolledResidue: Implementation = {
  id: 'bch-groth16-singleton-rolled-residue',
  // where the claimed public inputs live (public-input binding gate, harness/gates.ts)
  publicInputs: [
    { input: 0, push: 0, name: 'n0', offset: 256, encoding: 'le32' },
    { input: 0, push: 0, name: 'n1', offset: 288, encoding: 'le32' },
  ],
  name: 'BCH Groth16 verifier singleton, BN254 — rolled residue (exact class identity, on-chain gamma/delta walks)',
  vm: 'bch-2026',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  proofInputs: bn254RolledResidueProofInputs,
  source:
    'BCH-native single-input BN254 Groth16 verifier: one rolled Miller loop over the three pairs with every G2 walk ' +
    'computed on-chain (shared doubling / addition / line-multiply kernels), a residue root folded at the addition ' +
    'events and an exact class-identity terminal (no hints, no Fiat-Shamir, no Schwartz-Zippel), the SI-GLS exact ' +
    'G2 endpoint check for B, and a Jacobian vk_x with a witnessed zInv (research/frontier-middle/bn254/rolled-residue). ' +
    'Fits the BCH 2026 script-size caps; over the per-input op-cost budget.',
  load: async () => ({
    valid: toRun(vectors.steps),
    extraValidProofs: (vectors.extraValidProofs ?? []).map(toRun),
    worstCaseProof: vectors.worstCaseProof ? toRun(vectors.worstCaseProof) : undefined,
    invalid: (vectors.invalid ?? []).map(toRun),
  }),
};
