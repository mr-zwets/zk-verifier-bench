// Current-BCH BLS12-381 FS-PIT,12 P2SH32 inputs, all21 logical Miller stages.
// Qualified source: groth16_cashscript 0b7d5f3d9ad66b855a987371ba89d88039b33e3c.
// Owner SHA256:1ff4c888e6eb947d50b7d152f4fbf952fa6a86d84ab32d8913ebaf0d71dadfcb; compiler efc6ab80d9cbbea06c3c364b8fd5e915b9da84b4.
// RPA_FUSE_CARRIER_PAIR=1 plus four Regular triples and final19/20 fusion.
// Same535 arithmetic and all original proof/witness/public/root/quotient/
// auxiliary/challenge values. Exact group funding and flags in vector.
// 63623 script B +536 overhead B =64159 challenge B.
// Versus published13: -373B/-1input for +105973 native primary standard units.
// Native primary:38492275/38669811; maxima:50114463/50470559;
// minimum margins:3101/177 consensus/standard.
// Ten source exports reject2800 owning/whole controls. Native replay:
// 836contexts,240positive input prices; all128 old13 invalid transactions and
// their235 direct prior-origin records plus140 source cases retained as142
// distinct transactions. Five old P2SH32 hash flips explicitly relocated.
// Nested prior-origin indices use historical layouts; new source targets use12.
// FS-PIT/exactG2/pairing-equivalentG1 unchanged; finite supplied-corpus evidence,
// no universal arbitrary-witness resource, new red-team or live relay claim.
// Retained13/15/15packed/20/21/22 entries unchanged. Vector SHA256:254bb3c9e180d2e9b392200ceace96a4fc88bb5e68917c619031493c6d602ab9.
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
  'src/bch/groth16-bls12381-intratx-fs-fused-carrier-pair-vectors.json',
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

export const bchGroth16Bls12381IntratxFsFusedCarrierPair: Implementation = {
  id: 'bch-groth16-bls12381-intratx-fs-fused-carrier-pair',
  // where the claimed public inputs live (public-input binding gate, harness/gates.ts): every copy
  // of n0, n1 in the valid run (32-byte fields packed in larger pushes), located by the maintainers
  publicInputs: [
    { input: 0, push: 1, offset: 193, encoding: 'le32', name: 'n0' },
    { input: 0, push: 1, offset: 225, encoding: 'le32', name: 'n1' },
  ],
  name: 'BCH BLS12-381 Groth16 Fiat-Shamir PIT carrier Regular2/3 pair and four Regular triples (12 inputs, one standard transaction)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  proofInputs: bls12381IntratxFsProofInputs,
  source:
    'Complete BLS12-381 Groth16 verification in one current-BCH standard transaction. ' +
    'The externally anchored coordinator commits to the 11 worker lockings, while worker ' +
    'inputs read the required siblings with OP_INPUTBYTECODE. The coordinator also pins the ' +
    'proof/public-input statement, every Miller-block payload, and one logical ' +
    '132-coefficient quotient leaf. The quotient is carried as an exact ' +
    '110-coefficient head plus 22-coefficient tail and evaluated in order. The public-input ' +
    'contribution is authenticated from a table derived only from public verification-key ' +
    'points; published synthetic VK scalar relations are limited to fixture generation. ' +
    'Regular2/3 and Regular5/6/7,8/9/10,11/12/13,16/17/18 each share an input and initialized arithmetic; Regular19/Terminal20 share another; the original21 logical stages and transcript leaves remain. The terminal residue relation enforces the full four-pair Groth16 equation. B receives ' +
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
