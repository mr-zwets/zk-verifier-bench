// Current-BCH BLS12-381 FS-PIT,20 P2SH32 inputs, all21 logical Miller stages.
// Qualified source: groth16_cashscript 49aa88247461a10265b7559d4b39df7a11c03408.
// Owner SHA256:f1adcbd9d3fc4bb33c5aa66e61de33715944f735853acf12b249fe1f64338bc3; compiler zk-language efc6ab80d9cbbea06c3c364b8fd5e915b9da84b4.
// RPA_FUSE_REGULAR_PAIR=1 adds Regular7/8 sharing; retain final-pair fusion,
// both schedulers, original minus-one profile, group funding478 and block2pad0.
// Exact padding map and flags are in the vector. Same original proof/public/root/
// quotient/auxiliary/challenge values, same21 logical transcript leaves.
// 64280 script B +880 overhead B =65160 challenge B.
// Versus published21-input point: -166 B for +20,722 native primary standard cost.
// Native primary:37925935/38106543 consensus/standard;
// worst:48989019/49348187; minimum margins:4494/2318.
// Ten fresh source exports reject680 owning/whole producer controls. Actual native
// replay:198 contexts,400 positive input-cost identities. All21 prior invalids
// and34 source cases retained as49 distinct transactions with origin labels.
// FS-PIT/exactG2/pairing-equivalentG1 posture unchanged; no new red-team corpus,
// universal arbitrary-witness resource bound, or live relay/admission claim.
// Vector SHA256:0d5bd82eaa438ff50ef207a3ba470200db4808e6a43d62eea8bed4ffe264bb97.
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
  'src/bch/groth16-bls12381-intratx-fs-fused-regular-vectors.json',
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

export const bchGroth16Bls12381IntratxFsFusedRegular: Implementation = {
  id: 'bch-groth16-bls12381-intratx-fs-fused-regular',
  // where the claimed public inputs live (public-input binding gate, harness/gates.ts): every copy
  // of n0, n1 in the valid run (32-byte fields packed in larger pushes), located by the maintainers
  publicInputs: [
    { input: 0, push: 1, offset: 193, encoding: 'le32', name: 'n0' },
    { input: 0, push: 1, offset: 225, encoding: 'le32', name: 'n1' },
  ],
  name: 'BCH BLS12-381 Groth16 Fiat-Shamir PIT shared Regular and final pairs (20 inputs, one standard transaction)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  proofInputs: bls12381IntratxFsProofInputs,
  source:
    'Complete BLS12-381 Groth16 verification in one current-BCH standard transaction. ' +
    'The externally anchored coordinator commits to the 19 worker lockings, while worker ' +
    'inputs read the required siblings with OP_INPUTBYTECODE. The coordinator also pins the ' +
    'proof/public-input statement, every Miller-block payload, and one logical ' +
    '132-coefficient quotient leaf. The quotient is carried as an exact ' +
    '110-coefficient head plus 22-coefficient tail and evaluated in order. The public-input ' +
    'contribution is authenticated from a table derived only from public verification-key ' +
    'points; published synthetic VK scalar relations are limited to fixture generation. ' +
    'Regular7/8 share one physical input and initialized arithmetic, and Regular19/Terminal20 share another; the original21 logical stages and transcript leaves remain. The terminal residue relation enforces the full four-pair Groth16 equation. B receives ' +
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
