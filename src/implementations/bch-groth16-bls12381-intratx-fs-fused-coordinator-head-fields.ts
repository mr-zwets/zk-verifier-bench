// Current-BCH BLS12-381 FS-PIT: nine P2SH32 inputs, all21 logical stages.
// Source 9c1f0fe614da7c00b513e34216712dde1c572423; owner SHA256 9bd26d416375327405b92c759ce377544f606917dafdbbf2989d05a6725d653c.
// Compiler efc6ab80d9cbbea06c3c364b8fd5e915b9da84b4; full flags in vectors.
// 59901 script + 407 overhead = 60308 challenge bytes.
// RPA_PIC_ZERO_MASK=1: canonical32-byte scalar OR for zero-window lengths only.
// Original authenticated digits, statement, roots, transcript and46 arguments fixed.
// Inline root checks pin the final ordered eight-worker locking set before imports.
// Complete coordinator code stays in four funding carriers and FirstTail overflow.
// Prefix mode fields; data-only cache bodies and arithmetic ABI unchanged.
// Native primary C/STD 37719760/37889360;
// maximum 49365738/49713898; minimum sampled
// per-input margins 75479/69591.
// Ten normal exports,3520 source checks;1090 native
// contexts,180 reconciled positive prices; failed prices null.
// Retain all173 old invalids/359 direct prior origins,
// all nested histories,176 current source cases and10carrier controls.
// Complete transaction byte-identity dedup only; every origin retained.
// Existing FS-PIT, exact-G2/cofactor-equivalent-G1 and security grades unchanged.
// Finite corpus: no universal resource/soundness or live relay claim.
// Locking-set SHA256 3dc8dc2d98a5d3ca0763f72ebc5c35b443fb86d67001572984f93846451cbce8; vector SHA256 d7e50301fb65ae83a9126fe20e5e4cfb89f4f698d9e26a357ba6ba33856ba933.
// Input 0 locking SHA256 74bd865b0dcf15807aa69ce9f5c10c7d32416faee6f381226283ff400dcde0e1.
// Input 1 locking SHA256 799dab8217b0c6f5cce5987da76fec88fd761a221b6fc490aed8424a8bde27c7.
// Input 2 locking SHA256 2fa8499bcebfbbd12134a754caf797acd694d2f11f18f887feffdc4cad7b1a7a.
// Input 3 locking SHA256 56d7725328c6cf041bb656cda629f780628d3b4acdd5fd0b9c6b65ab2f192501.
// Input 4 locking SHA256 210722b3d30c95c806600d9e5afab36736de7694a20ea555127bb77b8d9f082b.
// Input 5 locking SHA256 3db82cd012e0d19fbac9f9c18346c9344e0a5ee1b831943f842542359160532a.
// Input 6 locking SHA256 c4518c7bc56f6ce8b0b60bc6d6e68c955dabd8cd70f7bb0bb7fcda44b1d59e9a.
// Input 7 locking SHA256 5fb84b508b6d0b527256ec98be47925f4a50c17221dcb3818c3c35f1169289c0.
// Input 8 locking SHA256 878bc56fce8ead06bfd71497354694a826cf45806d228abf695bc3f99f8177a5.
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
  'src/bch/groth16-bls12381-intratx-fs-fused-coordinator-head-fields-vectors.json',
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

export const bchGroth16Bls12381IntratxFsFusedCoordinatorHeadFields: Implementation = {
  id: 'bch-groth16-bls12381-intratx-fs-fused-coordinator-head-fields',
  // where the claimed public inputs live (public-input binding gate, harness/gates.ts): every copy
  // of n0, n1 in the valid run (32-byte fields packed in larger pushes), located by the maintainers
  publicInputs: [
    { input: 0, push: 1, offset: 193, encoding: 'le32', name: 'n0' },
    { input: 0, push: 1, offset: 225, encoding: 'le32', name: 'n1' },
  ],
  name: 'BCH BLS12-381 Groth16 Fiat-Shamir PIT with Regular initializer and fused coordinator/quotient head and separate header/statement caches (9 inputs, one standard transaction)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  proofInputs: bls12381IntratxFsProofInputs,
  source:
    'Complete BLS12-381 Groth16 verification in one current-BCH standard transaction. ' +
    'The unchanged 528-byte arithmetic initializer is carried by the Regular representative. The externally anchored coordinator commits to the 8 worker lockings, while worker ' +
    'inputs read the required siblings with OP_INPUTBYTECODE. The coordinator shares input0 with the quotient head and caches only the bounded encoded header/statement as two literal data pushes. It also pins the ' +
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
