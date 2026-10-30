// Current-BCH BLS12-381 FS-PIT,11 P2SH32 inputs, all21 logical Miller stages.
// Qualified source: groth16_cashscript dccd527715d373e65b7350dd0854bae24d8d74a0.
// Owner SHA256:61f62c4dc8a669f7f5256f3f305794d511e6f79d8f6c1515ea47d8d906f4a295; compiler efc6ab80d9cbbea06c3c364b8fd5e915b9da84b4.
// RPA_FUSE_MIDDLE_PAIR=1 plus carrier2/3, four Regular triples and final19/20.
// Same535 arithmetic and original proof/witness/public/root/quotient/auxiliary/
// state/challenge values. Exact flags and group funding are in the vector.
// 63373 script B +493 overhead B =63866 challenge B.
// Versus published12: -293B/-1input for +118785 native primary standard units.
// Native primary:38611828/38788596; maxima:50254176/50609504;
// minimum margins:6175/159 consensus/standard.
// Ten source exports reject3140 owning/whole controls. Actual native replay:
// 932contexts,220positive input prices; all142 old12 invalid transactions and
// their268 direct prior-origin records plus157 source cases retained as150
// distinct transactions. Six old P2SH32 hash flips explicitly relocated.
// Nested prior-origin indices use historical layouts; new source targets use11.
// FS-PIT/exactG2/pairing-equivalentG1 unchanged. Finite supplied-corpus evidence;
// no universal arbitrary-witness resource, new red-team or live relay claim.
// Retained12/13/15/15packed/20/21/22 entries unchanged. Vector SHA256:0c5584e3a3f759c0e5a7da5e39883a0b1c4e4e51d1026d96d8936276c6261b5c.
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
  'src/bch/groth16-bls12381-intratx-fs-fused-middle-pair-vectors.json',
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

export const bchGroth16Bls12381IntratxFsFusedMiddlePair: Implementation = {
  id: 'bch-groth16-bls12381-intratx-fs-fused-middle-pair',
  // where the claimed public inputs live (public-input binding gate, harness/gates.ts): every copy
  // of n0, n1 in the valid run (32-byte fields packed in larger pushes), located by the maintainers
  publicInputs: [
    { input: 0, push: 1, offset: 193, encoding: 'le32', name: 'n0' },
    { input: 0, push: 1, offset: 225, encoding: 'le32', name: 'n1' },
  ],
  name: 'BCH BLS12-381 Groth16 Fiat-Shamir PIT Regular14/AdditionMiddle15 pair, carrier Regular2/3 pair and four Regular triples (11 inputs, one standard transaction)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  proofInputs: bls12381IntratxFsProofInputs,
  source:
    'Complete BLS12-381 Groth16 verification in one current-BCH standard transaction. ' +
    'The externally anchored coordinator commits to the 10 worker lockings, while worker ' +
    'inputs read the required siblings with OP_INPUTBYTECODE. The coordinator also pins the ' +
    'proof/public-input statement, every Miller-block payload, and one logical ' +
    '132-coefficient quotient leaf. The quotient is carried as an exact ' +
    '110-coefficient head plus 22-coefficient tail and evaluated in order. The public-input ' +
    'contribution is authenticated from a table derived only from public verification-key ' +
    'points; published synthetic VK scalar relations are limited to fixture generation. ' +
    'Regular14/AdditionMiddle15, Regular2/3 and Regular5/6/7,8/9/10,11/12/13,16/17/18 each share an input and initialized arithmetic; Regular19/Terminal20 share another; the original21 logical stages and transcript leaves remain. The terminal residue relation enforces the full four-pair Groth16 equation. B receives ' +
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
