// Current-BCH BLS12-381 FS-PIT,15 P2SH32 inputs, all21 logical Miller stages.
// Qualified source: groth16_cashscript b9a2410087bd8afeda30e07ff58b6d2f35d61a4f.
// Owner SHA256:3e572a2c4d69308116d9b1e792479641fbdcf83ac83eb393360c4a1ae6f973d6; compiler zk-language efc6ab80d9cbbea06c3c364b8fd5e915b9da84b4.
// RPA_FUSE_REGULAR_PAIRS=1 adds six non-carrier Regular pairs; original
// final19/20fusion, both schedulers, minus-one arithmetic and q132 remain.
// Public physical-index table; exact groups, funding and flags in vector/source.
// Same original proof/public/root/quotient/auxiliary/challenge values and21leaves.
// 64118 script B +665 overhead B =64783 challenge B.
// Versus published20-input point: -377 B for +156,433 primarynative standard cost.
// Native primary:38083776/38262976 consensus/standard;
// worst:49364588/49722348; minimum margins:5437/3261.
// Ten source exports reject2380 owning/whole controls. Actual native replay:
// 538contexts,300positiveinput-costidentities. All21legacy and119source cases
// retained as114 distinct transactions, preserving allorigin/owner labels.
// FS-PIT/exactG2/pairing-equivalentG1 unchanged; no newred-team/universalresource
// or live relay/admission claim. Retained20/21/22entries remain byteexact.
// Vector SHA256:fba7ef2c78fdfde64dabf5aa023231e9df675edd12fe153f3c1a78dd3e809e3c.
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
  'src/bch/groth16-bls12381-intratx-fs-fused-regular-pairs-vectors.json',
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

export const bchGroth16Bls12381IntratxFsFusedRegularPairs: Implementation = {
  id: 'bch-groth16-bls12381-intratx-fs-fused-regular-pairs',
  // where the claimed public inputs live (public-input binding gate, harness/gates.ts): every copy
  // of n0, n1 in the valid run (32-byte fields packed in larger pushes), located by the maintainers
  publicInputs: [
    { input: 0, push: 1, offset: 193, encoding: 'le32', name: 'n0' },
    { input: 0, push: 1, offset: 225, encoding: 'le32', name: 'n1' },
  ],
  name: 'BCH BLS12-381 Groth16 Fiat-Shamir PIT six Regular pairs (15 inputs, one standard transaction)',
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
