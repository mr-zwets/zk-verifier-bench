// Current-BCH BLS12-381 FS-PIT,13 P2SH32 inputs, all21 logical Miller stages.
// Qualified source: groth16_cashscript 8d642c7b89ae198c67101ade6f593fe56ffcd2c2.
// Owner SHA256:5e0caf02e4e5dbcd54463788c92fb4534f91ca9c0dc8a9b186f04d24aaf18864; compiler efc6ab80d9cbbea06c3c364b8fd5e915b9da84b4.
// RPA_FUSE_REGULAR_TRIPLES=1: four non-carrier triples and existing final19/20.
// Packed public2-bit frame ordinals/4-bit physical indices; unchanged535 arithmetic.
// Exact groups/funding/flags in vector; all original proof/witness/public/root/
// quotient/auxiliary/challenge values and21 logical transcript leaves preserved.
// 63953 script B +579 overhead B =64532 challenge B.
// Versus published15: -251B/-2inputs for +300862 native primary standard units.
// Native primary:38385406/38563838; maxima:49960554/50317546;
// minimum margins:6060/3671 consensus/standard.
// Ten fresh source exports reject2420 owning/whole controls. Native replay:
// 732contexts,260positiveinputcostidentities. All114 old15 invalid transactions
// with140 prior-origin records plus121 new source cases retained as128
// distinct transactions. Seven old sibling-locking flips explicitly relocated.
// Prior-origin target indices refer to old15 layout; new source targets use13.
// FS-PIT/exactG2/pairing-equivalentG1 unchanged; finite supplied-corpus evidence,
// no universal arbitrary-witness resource, newred-team orlive relay claim.
// Retained15/20/21/22 entries unchanged. Vector SHA256:dddffba1cb8712dd5953cd36aea4e22040d4f7f41d61c67abad278b441abc53b.
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
  'src/bch/groth16-bls12381-intratx-fs-fused-regular-triples-vectors.json',
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

export const bchGroth16Bls12381IntratxFsFusedRegularTriples: Implementation = {
  id: 'bch-groth16-bls12381-intratx-fs-fused-regular-triples',
  // where the claimed public inputs live (public-input binding gate, harness/gates.ts): every copy
  // of n0, n1 in the valid run (32-byte fields packed in larger pushes), located by the maintainers
  publicInputs: [
    { input: 0, push: 1, offset: 193, encoding: 'le32', name: 'n0' },
    { input: 0, push: 1, offset: 225, encoding: 'le32', name: 'n1' },
  ],
  name: 'BCH BLS12-381 Groth16 Fiat-Shamir PIT four Regular triples (13 inputs, one standard transaction)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  proofInputs: bls12381IntratxFsProofInputs,
  source:
    'Complete BLS12-381 Groth16 verification in one current-BCH standard transaction. ' +
    'The externally anchored coordinator commits to the 12 worker lockings, while worker ' +
    'inputs read the required siblings with OP_INPUTBYTECODE. The coordinator also pins the ' +
    'proof/public-input statement, every Miller-block payload, and one logical ' +
    '132-coefficient quotient leaf. The quotient is carried as an exact ' +
    '110-coefficient head plus 22-coefficient tail and evaluated in order. The public-input ' +
    'contribution is authenticated from a table derived only from public verification-key ' +
    'points; published synthetic VK scalar relations are limited to fixture generation. ' +
    'Regular5/6/7,8/9/10,11/12/13,16/17/18 each share an input and initialized arithmetic; Regular19/Terminal20 share another; the original21 logical stages and transcript leaves remain. The terminal residue relation enforces the full four-pair Groth16 equation. B receives ' +
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
