// Current-BCH BLS12-381 FS-PIT,15 P2SH32 inputs, all21 logical Miller stages.
// Qualified source: groth16_cashscript 89dda8b996ca24b750202fd50120bb66aee7ed13.
// Owner SHA256:c46077c189621cbd3e53bad7d6409e0707873c8908b12da418bf4aab69eaca0f; compiler efc6ab80d9cbbea06c3c364b8fd5e915b9da84b4.
// RPA_PACK_REGULAR_PAIR_MAPS=1 with six Regular pairs and existing final19/20.
// Packed public1-bit frame ordinals/4-bit physical indices; unchanged535 arithmetic.
// Same proof, witness, public, root, quotient, auxiliary and challenge values.
// 64024 script B +665 overhead B =64689 challenge B.
// Versus published15: -94B and -98026 native primary standard units.
// Native primary:37985878/38164950; maxima:49266690/49624322;
// minimum margins:6196/3369 consensus/standard.
// Ten source exports reject2380 owning/whole controls. Native replay:
// 724contexts,300positive input prices. All114 old15 invalid transactions
// with140 prior origins plus119 source cases retained as114 distinct cases.
// Seven old sibling-locking flips explicitly relocated to the same logical owner.
// Prior-origin and new source target indices both use15-input layouts.
// FS-PIT/exactG2/pairing-equivalentG1 unchanged; finite supplied-corpus evidence,
// no universal arbitrary-witness resource, new red-team or live relay claim.
// Retained13/15/20/21/22 entries unchanged. Vector SHA256:2e643f5c5061831c78ecb9bdc9fb82cc9766dc3f5c8e129d815baa7d2a5e1cf5.
import { readFileSync } from 'node:fs';

import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';
import { bls12381IntratxFsProofInputs } from './groth16-proof-inputs.js';

interface RawStep {
  label: string;
  locking: string;
  unlocking: string;
}

interface Vectors {
  steps: RawStep[];
  extraValidProofs: RawStep[][];
  worstCaseProof: RawStep[];
  invalid: RawStep[][];
}

const vectors = JSON.parse(readFileSync(
  'src/bch/groth16-bls12381-intratx-fs-fused-regular-pairs-packed-vectors.json',
  'utf8',
)) as Vectors;

const toRun = (raw: RawStep[]): Step[] => {
  const inputs = raw.map(({ locking, unlocking }) => ({
    lockingBytecode: hexToBin(locking),
    unlockingBytecode: hexToBin(unlocking),
  }));
  return raw.map(({ label }, index) => ({
    label,
    lockingBytecode: inputs[index]!.lockingBytecode,
    unlockingBytecode: inputs[index]!.unlockingBytecode,
    intraTx: { index, inputs },
  }));
};

export const bchGroth16Bls12381IntratxFsFusedRegularPairsPacked: Implementation = {
  id: 'bch-groth16-bls12381-intratx-fs-fused-regular-pairs-packed',
  // where the claimed public inputs live (public-input binding gate, harness/gates.ts): every copy
  // of n0, n1 in the valid run (32-byte fields packed in larger pushes), located by the maintainers
  publicInputs: [
    { input: 0, push: 1, offset: 193, encoding: 'le32', name: 'n0' },
    { input: 0, push: 1, offset: 225, encoding: 'le32', name: 'n1' },
  ],
  name: 'BCH BLS12-381 Groth16 Fiat-Shamir PIT six Regular pairs with packed maps (15 inputs, one standard transaction)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  proofInputs: bls12381IntratxFsProofInputs,
  source:
    'Complete BLS12-381 Groth16 verification in one current-BCH standard transaction. ' +
    'The externally anchored coordinator commits to the 14 worker lockings, while worker ' +
    'inputs read the required siblings with OP_INPUTBYTECODE. The coordinator also pins the ' +
    'proof/public-input statement, every Miller-block payload, and one logical ' +
    '132-coefficient quotient leaf. The quotient is carried as an exact ' +
    '110-coefficient head plus 22-coefficient tail and evaluated in order. The public-input ' +
    'contribution is authenticated from a table derived only from public verification-key ' +
    'points; published synthetic VK scalar relations are limited to fixture generation. ' +
    'Regular5/6,7/8,9/10,11/12,13/14,16/17 each share a physical input and initialized arithmetic; Regular19/Terminal20 share another; the original21 logical stages and transcript leaves remain. The terminal residue relation enforces the full four-pair Groth16 equation. B receives ' +
    'an exact G2 subgroup check. A/C are on-curve and equation-binding, while unique G1 ' +
    'subgroup encodings and the separate harness input-validation grade are not claimed. ' +
    'One locking set accepts all ten supplied equation-valid fixtures. The candidate has ' +
    'finite ten-fixture source and current-native coverage only; universal operation-cost ' +
    'and resource certification remains pending.',
  load: async () => ({
    valid: toRun(vectors.steps),
    extraValidProofs: vectors.extraValidProofs.map(toRun),
    worstCaseProof: toRun(vectors.worstCaseProof),
    invalid: vectors.invalid.map(toRun),
  }),
};
