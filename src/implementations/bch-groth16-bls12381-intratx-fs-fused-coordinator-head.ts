// Current-BCH BLS12-381 FS-PIT: nine P2SH32 inputs, all21 logical stages.
// Source 9c1f0fe614da7c00b513e34216712dde1c572423; owner SHA256 9bd26d416375327405b92c759ce377544f606917dafdbbf2989d05a6725d653c.
// Compiler efc6ab80d9cbbea06c3c364b8fd5e915b9da84b4; full flags in vectors.
// 59878 script + 407 overhead = 60285 challenge bytes.
// RPA_PIC_ZERO_MASK=1: canonical32-byte scalar OR for zero-window lengths only.
// Original authenticated digits, statement, roots, transcript and46 arguments fixed.
// Inline root checks pin the final ordered eight-worker locking set before imports.
// Complete coordinator code stays in four funding carriers and FirstTail overflow.
// Prefix mode 1; data-only cache bodies and arithmetic ABI unchanged.
// Native primary C/STD 37816994/37986594;
// maximum 49462972/49811132; minimum sampled
// per-input margins 54639/48751.
// Ten normal exports,3520 source checks;1090 native
// contexts,180 reconciled positive prices; failed prices null.
// Retain all173 old invalids/350 direct prior origins,
// all nested histories,176 current source cases and10carrier controls.
// Complete transaction byte-identity dedup only; every origin retained.
// Existing FS-PIT, exact-G2/cofactor-equivalent-G1 and security grades unchanged.
// Finite corpus: no universal resource/soundness or live relay claim.
// Locking-set SHA256 98baf9022aab106f9328b57e330bd20609c9353d6df97d4bc02a4202b5e9aa94; vector SHA256 59f0e4cc153f80ad01f1b7491294236df58b11b80771bb84732b3ae6062386fe.
// Input 0 locking SHA256 828ab4efec5c8b672df1ff669076437012298202e2738389f73a2fb0d33864d4.
// Input 1 locking SHA256 e78cef3e6825364751ebe6ada4755945b496c7252f554b84c4d2f164ba99188c.
// Input 2 locking SHA256 59aecca8cfbf79a3c3d5122da20be5ef754bf6017b1f56830c1afd9f50347a62.
// Input 3 locking SHA256 d6ec654d6a2f97adb4c3f869aff911dddf76a7078f9479c14f1cb5438ed3073c.
// Input 4 locking SHA256 eae327101b50859dc8a71151b2c47a56af57cae8419b480f1692b40b0518c0b8.
// Input 5 locking SHA256 9a4e69d67894c6974a4502998d76921f94758ff9aa19a4550895ee5325ad9b90.
// Input 6 locking SHA256 ff13bd3693311d1bb45bb647dd9b9c7b98b1745f92632ee4109e5b8c0573394e.
// Input 7 locking SHA256 f5caf621f0a32793049faf29c3c0afcc4e60a1b2768043d614707b10f3ae30d5.
// Input 8 locking SHA256 356e2e9e0725d68279c06a572addd9f2e62f9b9a7310e4250244d619a1dd6609.
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
  'src/bch/groth16-bls12381-intratx-fs-fused-coordinator-head-vectors.json',
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

export const bchGroth16Bls12381IntratxFsFusedCoordinatorHead: Implementation = {
  id: 'bch-groth16-bls12381-intratx-fs-fused-coordinator-head',
  // where the claimed public inputs live (public-input binding gate, harness/gates.ts): every copy
  // of n0, n1 in the valid run (32-byte fields packed in larger pushes), located by the maintainers
  publicInputs: [
    { input: 0, push: 1, offset: 193, encoding: 'le32', name: 'n0' },
    { input: 0, push: 1, offset: 225, encoding: 'le32', name: 'n1' },
  ],
  name: 'BCH BLS12-381 Groth16 Fiat-Shamir PIT with Regular initializer and fused coordinator/quotient head and bounded prefix cache (9 inputs, one standard transaction)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  proofInputs: bls12381IntratxFsProofInputs,
  source:
    'Complete BLS12-381 Groth16 verification in one current-BCH standard transaction. ' +
    'The unchanged 528-byte arithmetic initializer is carried by the Regular representative. The externally anchored coordinator commits to the 8 worker lockings, while worker ' +
    'inputs read the required siblings with OP_INPUTBYTECODE. The coordinator shares input0 with the quotient head and caches only the bounded encoded header/statement as a literal data push. It also pins the ' +
    'proof/public-input statement, every Miller-block payload, and one logical ' +
    '132-coefficient quotient leaf. The quotient is carried as an exact ' +
    '110-coefficient head plus 22-coefficient tail and evaluated in order. The public-input ' +
    'contribution is authenticated from a table derived only from public verification-key ' +
    'points; published synthetic VK scalar relations are limited to fixture generation. ' +
    'First0/AdditionTail1, Regular14/AdditionMiddle15, Regular2/3 and Regular5/6/7,8/9/10,11/12/13,16/17/18 each share an input and initialized arithmetic; Regular19/Terminal20 share another; the original21 logical stages and transcript leaves remain. The terminal residue relation enforces the full four-pair Groth16 equation. B receives ' +
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
