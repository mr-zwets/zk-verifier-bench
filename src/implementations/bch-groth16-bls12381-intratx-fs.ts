// Complete BLS12-381 Groth16 verification in one current-BCH standard transaction.
//
// Entry name: bch-groth16-bls12381-intratx-fs (intra-tx packing + Fiat-Shamir
// polynomial-identity checking). The Fp6/torus relations are checked at
// SHA-256-derived challenges rather than computed exactly, so this entry sits in
// the separate Fiat-Shamir PIT security-model category defined in
// groth16_cashscript/verifiers.md; the residue entries remain the unconditional
// frontier. "qsplit tail-22" is the internal build codename.
// Twenty-two P2SH32 inputs jointly enforce
//
//   e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) = 1,
//   vk_x = IC0 + input0*IC1 + input1*IC2.
//
// The runtime proof and public inputs are committed before the Fiat-Shamir
// challenges. Each Miller-block payload is committed before beta, and the 132
// quotient coefficients are committed as one logical leaf before alpha. The
// quotient is carried physically as a fixed 110-coefficient head followed by a
// fixed 22-coefficient tail; both consumers enforce the exact lengths, order,
// sibling programs, recurrence, and terminal residue relation.
//
// The fixed Miller data and authenticated public-input table are derived only
// from public verification-key points. The repository's published synthetic VK
// scalar relations are used only to mint equation-valid benchmark fixtures;
// locking-program compilation and table generation do not consume them. No
// proof value, setup secret, or private witness is specialized. All ten supplied
// fixtures use the same locking set. B is checked on-curve and in the exact
// order-r G2 subgroup by the psi relation with the mid-walk nonzero guard. A and
// C have canonical field encodings and are checked on-curve; cofactor-equivalent
// G1 points remain equivalent for the pairing verdict, so this entry does not
// claim a separate unique-G1-encoding grade. These vectors also do not supply
// isolated point-validation runs, so the entry does not claim the harness's
// separate input-validation grade.
//
// The 24 pre-beta relations have cancellation degree at most 23, and the alpha
// identity has degree at most 137. In the SHA-256 random-oracle model, the
// conservative union bound is 160/(2^256-1), less than 161/2^256.
//
// Largest supplied valid fixture:
//   22 inputs, 89,357 script B, 89,553 wire B, 90,323 challenge-score B
//   69,798,359 consensus opcost, 70,171,351 standard opcost
// Committed fixture:
//   67,899,727 consensus opcost, 68,272,719 standard opcost
// Every supplied valid fixture passes the current BCH consensus and standard
// VMs, remains below the 100,000-byte relay limit, and pays exactly 1 sat/byte.
//
// Source revision:
//   groth16_cashscript PR #14 commit 608f74747dc50def17c3b07a223585b330342124 (entry named at fd3c843)
// Source artifact:
//   groth16_cashscript/chunked/bls12-381/measure_d3_two_chart_binary.mjs
//   sha256 f0c15ed60d1507542f40ea392478693b7e7b8ded73a666313ee82e748602c46d
// Resource export sha256:
//   254ee78bda438f4ec8589a30f1acd58a25b39fc10b156a37e9da8ca62db4b314
// Benchmark vector sha256:
//   9152db69265b2b15e8b5ef4720ecc6c6e3bcdf07a7847068e42a457d1692b102
// Length-prefixed locking-set sha256:
//   4cd6f93829da3708513aa61d408c0b2bd4bba851ba31abefaad573b82c1d0284
// Individual locking-bytecode sha256 values, input order:
//   00 3bbb5ec2ea078faba879d73c4d49ac6e9fa3fa73cdc6036fca7d3b057ac0a16c
//   01 6744cb960e516d9b07856f4b9bfde952ad96fd2e1ca8ed82787cf679a69d6f52
//   02 fb5d0decba4702bb3a67305c62d22cd27d403b0727c93e1ebf4f5ce970bc2dac
//   03 25897317dfec6df1a32ca958e896851109d68931a8d73b864382b7039b580254
//   04 c853b9a548e87ed5ae51237890d868361e6abb009310b86edff87afd2cf11746
//   05 656d3fb26eff72bd31eb5e705665fbcbf9283e0de2f689328a9b32ec3b5bcba3
//   06 b114dcfe7229b8589f12fb6d38bd67dd5aba2583e6c52ac52182bb8dfef6fabd
//   07 fa09fce3af578c5e90987d1cbc689355deb309e8c0f4484e6e4c5ec893174192
//   08 15abd2b7f7a39d7ce0181233f310f4f3c197dc309836457cfdcb814f4a1b0dad
//   09 90b9dbab56936980b727e6a2869db3b7de2889ec958a7574427a412e9038b5c1
//   10 e058365c9d7520fdea54017d85bb4799e119238e889a8d9ad48ff6b9d8e33742
//   11 98e78798c1938556e4c39c66ed27fa28e9165337cf11679159c65507be0c7114
//   12 c930e6ff1164cbbed9316f2edf3f492cd9ec8f104d39fdb6e84aece9a72742f7
//   13 1936ce59d28e70e9e51fd24b12d15ce33e19c7e881c695dfd46ff5473a5cac8a
//   14 8886d29d6c1326f4b1c6075d48fa506b87a5d399ec7e9b28c538a258a3936adb
//   15 9cad062b746bca7499004273194b47d87ddedf449790ffe8afeb5d95d278eb86
//   16 29cd55f78e3c3a19099ef0ec96443ec923791175005114259ec81e04f11b9df1
//   17 a03061d33e2be8dfabd7458010dfaedcb197fb8403552168ffa726e352bb1f2e
//   18 e57e2e6cae522c71f49dcef07dc0c74b9630cdd55ebeae79924d3d0e68418d3d
//   19 7503f8815e8f6cf58436c0d5feed9ff270ca7ab3141a903cb3fe020bed271651
//   20 a4d77352be448f744dace5c909430e217d8d78fd5d609e12762aa5690ea4a323
//   21 44bc6ac98b5d2617d1b47a1fdf0779de18492351f016118fb82f19fefe40be0f
import { readFileSync } from 'node:fs';

import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

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
  'src/bch/groth16-bls12381-intratx-fs-vectors.json',
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

export const bchGroth16Bls12381IntratxFs: Implementation = {
  id: 'bch-groth16-bls12381-intratx-fs',
  name: 'BCH BLS12-381 Groth16 Fiat-Shamir PIT (22 inputs, one standard transaction)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'Complete BLS12-381 Groth16 verification in one current-BCH standard transaction. ' +
    'The externally anchored coordinator commits to the 21 worker lockings, while worker ' +
    'inputs read the required siblings with OP_INPUTBYTECODE. The coordinator also pins the ' +
    'proof/public-input statement, every Miller-block payload, and one logical ' +
    '132-coefficient quotient leaf. The quotient is carried as an exact ' +
    '110-coefficient head plus 22-coefficient tail and evaluated in order. The public-input ' +
    'contribution is authenticated from a table derived only from public verification-key ' +
    'points; published synthetic VK scalar relations are limited to fixture generation. ' +
    'The terminal residue relation enforces the full four-pair Groth16 equation. B receives ' +
    'an exact G2 subgroup check. A/C are on-curve and equation-binding, while unique G1 ' +
    'subgroup encodings and the separate harness input-validation grade are not claimed. ' +
    'One locking set accepts all ten supplied equation-valid fixtures. The proof-independent ' +
    'resource certificate derives per-input ' +
    'ceilings from the exported bytecodes and covers both B branch classes.',
  load: async () => ({
    valid: toRun(vectors.steps),
    extraValidProofs: vectors.extraValidProofs.map(toRun),
    worstCaseProof: toRun(vectors.worstCaseProof),
    invalid: vectors.invalid.map(toRun),
  }),
};
