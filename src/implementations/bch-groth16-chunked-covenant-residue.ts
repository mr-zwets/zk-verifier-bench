// BCH-native covenant-threaded BN254 Groth16 quotient-torus verifier.
//
// Source-reproducible covenant graph:
//   vk_x = IC0 + in0*IC1 + in1*IC2 (four-scalar GLV MSM)  ->  3 transactions
//   fused GLV terminal + Miller prefix                     ->  1 transaction
//   remaining Miller + quotient residue verdict            ->  8 transactions
//                                                            ----------------
//                                                            = 12 transactions
//
// The Miller accumulator lives in Q=Fp12*/Fp6*. A six-limb canonical u represents
// [c]=[1+u*W], and [c^-1]=[1-u*W]. In Q, gcd(lambda,p^6+1)=r for
// lambda=6x+2+p-p^2+p^3, so the lambda-power image is exactly the final-exponent kernel.
// The terminal checks [f*c^(p^2)]=[c^p*c^(p^3)] and explicitly rejects the projective
// zero representative. The older Fp6 residue-coset correction disappears in Q.
//
// The GLV minting-baton genesis commits the raw proof tuple while computing vk_x. After three
// standalone GLV chunks, one fused transaction finishes vk_x and immediately executes the first
// Miller prefix. It derives a B-identity flag exactly from the all-zero raw B encoding, maps only
// that identity case to G2.BASE, checks canonical A/B/C and all three curve equations, derives
// normalized unit-line coordinates, and emits the first Miller state. A finite raw B=G2.BASE
// remains finite. There is no intermediate GLV-output/Miller-input covenant seam: the fused input
// commitment binds the partial GLV state and raw proof tuple, and its output commitment binds the
// resulting Miller state. Runtime effective-B is affine and its post-loop endomorphism endpoint is
// an exact G2 subgroup check; the identity flag makes only the original all-zero B pairing neutral.
// Later state is hash-committed in mutable NFT commitments. Each nonterminal pins its successor
// P2SH32 locking; the terminal verdict NFT is immutable. The genesis recreates its minting baton
// under the same locking and category.
//
// Committed proof (from the shipped vector file): 92,207 script B; 93,800 actually serialized B
// across 12 transactions; 69,858,891 op; largest transaction 10,091 B; largest step 7,716,482 op.
// The second proof is 93,814 wire B, and the dense (worst-case) proof is 110,769 wire B /
// 85,348,784 op. All 14 valid runs (committed, second, dense, 11 identity/boundary) pass the BCH
// 2026 consensus and standard-policy VMs under the same lockings. Harness-score totals are in
// results.json; the harness covenant overhead model counts an empty-commitment length byte for the
// baton and the terminal NFT. The companion source generator certifies exact 1 satoshi-per-
// serialized-byte fee templates; the covenant contracts do not pin satoshi values.
//
// The prescribed checkpoint key is synthetic and publishes its setup and IC scalars. The contracts
// evaluate the complete four-pair equation, but these vectors do not establish circuit knowledge,
// secure binding of the public-input vector, or interoperability with an independently generated
// setup. Relayability is demonstrated for the 14 accepting fixture families; unlike the one-tx
// track, this covenant entry does not claim a proof-independent relay ceiling for every valid proof.
//
// Deployment premises (composition argument: groth16_cashscript chunked/pairing/README.md,
// "Covenant-residue composition"): the category genesis must create no NFT of the category other
// than minting batons at the genesis locking, and the bench category 0xcd..cd is a placeholder
// (a deployment regenerates the graph with its real category). The verdict is an unspendable
// immutable NFT with an empty commitment; a consumer reads the statement (n0, n1) from the genesis
// unlocking at the end of the verdict's unique one-input ancestry: push 6 is in0 (n0) and push 5
// is in1 (n1).
//
// Reproduction (byte-identical; both 2026-10-27 reviews): groth16_cashscript
// 35561c7a7d7f07920a6b1a3d1f3dac8906c55837 (0cff585 also reproduces it), cashc
// compiler-optimizations-2 9fb14833713449403104c8a77cb10973130993e1, input fixtures from bench
// 082da7c^:
//   VERIFIER_DIR=/path/to/zk-verifier-bench pnpm vectors:covenant:torus
// Shipped by bench 082da7c (co-2 regeneration).
//
// Input fixture SHA-256 (at bench 082da7c^; the current multiproof file differs, so reproduce
// from that revision's fixtures):
//   multiproof (src/bch/groth16-singleton-multiproof-vectors.json)
//     d513f1fe45d7aba20f289cbc38439d5ebdb05a9975950a5e32d2bf21239d4abc
//   pairing checkpoint (src/checkpoints/pairing-vectors.json)
//     e393e8b6af6f528c93f97f37656802bf44daefa5819640a557fbff95e236739e
//
// Vector SHA-256: 059b319c7ef8d6803d7d8ff0144e990fdd6f5c5bc842176b8bb2211adaeeb6cb
// Locking graph SHA-256 (UTF-8 concatenated locking-hex text):
// b0370a991a55fcce4d71b4e4ffa154838e44a1f8a4133ddfc5891c273217c36c
//
// sha256 of locking bytecode, in transaction order:
//   00 4520d52adf0ce058d938236d77dd2f9b8df52d8658ed33b4fc33c20375b48d96
//   01 c059c074f984900af5433a5399084198906e71e09db29a032b7cb6c44a8d8260
//   02 dbc5363f5971b6fe8a2cbb2f2c2a2061e7af7eb23a3b1427832f626808d7b013
//   03 72168dd4ff14cae0344bc0ca2af4cf158ec1d91ce19c4f57544f7edbc56dac61
//   04 a8197c5240e9a6851349a0ed21d3880f3ece5522d1eb0b1c43c62f954464983f
//   05 89350e019e821c8c04233a27150f4cd2b63b38e1fd2afd2b8596288fe53a2397
//   06 f0dc04df40b0d5e7182e1b2a9f0aa21c5fbc9a3c327c8c9aee4331d196b3c1b1
//   07 23a140345350ab92d84e3dfa24130e9b7b6149ee4402127764163ae22c8aa4ce
//   08 d8a18bd798f02b03a5a444da681fe3be7091f3691354370b7e2efe28f6074f2b
//   09 525e1a369fc7e83af4a0fd891b0d860c7f4b639e524d253fb3f5b4656d8cc42c
//   10 5b8319381e435f60bdc95a082b1ad27ca7819588fc5d0648cdbaf81ea375cc8e
//   11 280a220c64dbffc0e1f40e1f5b2f45b5313418e53fc28ceae679939a706f7f48
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';
import { bn254CovenantResidueProofInputs } from './groth16-proof-inputs.js';

interface RawStep {
  label: string; locking: string; unlocking: string; invalidUnlocking?: string; checkpoint?: string;
  kind: 'genesis' | 'forward' | 'terminal'; expectReject?: boolean;
  covenant: {
    category: string; capability: 'none' | 'mutable' | 'minting';
    inCommitment: string; outCommitment: string; outLockingBytecode: string;
  };
}
const v = JSON.parse(readFileSync('src/bch/groth16-chunked-covenant-residue-vectors.json', 'utf8')) as {
  steps: RawStep[];
  // A second independently minted proof with different canonical public inputs: same lockings,
  // distinct unlockings, demonstrating that the verifier bakes only the VK and structure.
  extraProofSteps?: RawStep[];
  worstCaseSteps?: RawStep[];
  identityProofSteps?: Record<string, RawStep[]>;
  invalidRuns?: RawStep[][];
  // Isolated invalid-input runs cover non-canonical A/B/C, off-curve A/B/C, and an
  // on-curve G2 point outside the order-r subgroup.
  invalidInputSteps?: Record<string, RawStep[]>;
};

const toStep = (s: RawStep): Step => ({
  label: s.label,
  lockingBytecode: hexToBin(s.locking),
  unlockingBytecode: hexToBin(s.unlocking),
  checkpoint: s.checkpoint,
  covenant: {
    category: hexToBin(s.covenant.category),
    capability: s.covenant.capability,
    inCommitment: hexToBin(s.covenant.inCommitment),
    outCommitment: hexToBin(s.covenant.outCommitment),
    outLockingBytecode: hexToBin(s.covenant.outLockingBytecode),
    inputCapability: s.kind === 'genesis' ? 'minting' : s.kind === 'terminal' ? 'mutable' : s.covenant.capability,
    secondOutputBaton: s.kind === 'genesis',
  },
});

export const bchGroth16ChunkedCovenantResidue: Implementation = {
  id: 'bch-groth16-chunked-covenant-residue',
  // where the claimed public inputs live (public-input binding gate, harness/gates.ts), located by
  // the maintainers. In each GLV input the pushes are k11, k20, k10, in1, in0 in ascending order
  // (genesis: 2..6; inputs 1-2: 10, 11, 12, 13, 14; input 3: 38..42). The slots named n0/n1 at the
  // in0/in1 pushes (6/5, 14/13, 42/41) are the statement; the ones at the k10/k11 pushes (4/2,
  // 12/10, 40/38) are GLV witnesses that equal n0/n1 only for small scalars, as in the committed
  // fixture, so grouping them under the same name makes each mutation change all copies together.
  // This is a mutation-test list, not a statement locator.
  publicInputs: [{ input: 0, push: 4, name: 'n0' }, { input: 0, push: 6, name: 'n0' }, { input: 1, push: 12, name: 'n0' }, { input: 1, push: 14, name: 'n0' }, { input: 2, push: 12, name: 'n0' }, { input: 2, push: 14, name: 'n0' }, { input: 3, push: 40, name: 'n0' }, { input: 3, push: 42, name: 'n0' }, { input: 0, push: 2, name: 'n1' }, { input: 0, push: 5, name: 'n1' }, { input: 1, push: 10, name: 'n1' }, { input: 1, push: 13, name: 'n1' }, { input: 2, push: 10, name: 'n1' }, { input: 2, push: 13, name: 'n1' }, { input: 3, push: 38, name: 'n1' }, { input: 3, push: 41, name: 'n1' }],
  name: 'BCH Groth16 covenant quotient-torus verifier (12 standard transactions)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'multi-tx',
  proofBinding: 'runtime',
  proofInputs: bn254CovenantResidueProofInputs,
  tokenSafetyEnforced: true,
  source:
    'BCH-native CashScript: the complete runtime-proof Groth16 verifier in 12 covenant-threaded ' +
    'transactions. Three standalone GLV vk_x chunks begin at the minting-baton genesis and commit ' +
    'the raw proof tuple. A fused fourth transaction finishes the GLV MSM and immediately executes ' +
    'the first Miller prefix: it derives the B-identity flag from exactly the all-zero raw B encoding, ' +
    'maps only that case to G2.BASE, validates canonical A/B/C and the G1/G2 curve equations, and ' +
    'commits the first Miller state. ' +
    'There is no intermediate GLV-output/Miller-input covenant seam; the fused input commitment binds ' +
    'the partial GLV state and raw proof tuple, and its output commitment binds the resulting Miller ' +
    'state. Eight remaining affine/unit-line optimal-ate Miller chunks enforce the exact G2 subgroup ' +
    'endpoint and evaluate the accumulator in ' +
    'Fp12*/Fp6*. One canonical six-limb finite residue root replaces c/cInv plus the Fp6 coset witness; ' +
    'the terminal checks the exact quotient relation and rejects projective zero. Canonical state limbs ' +
    'ride in NFT commitments. Every nonterminal pins its successor P2SH32 locking; token category and ' +
    'capability are fixed; the genesis recreates its minting baton; the terminal emits an immutable NFT. ' +
    'Byte-exact vectors reproduce from groth16_cashscript commit ' +
    '35561c7a7d7f07920a6b1a3d1f3dac8906c55837 with the pinned input fixtures and cashc ' +
    '9fb14833713449403104c8a77cb10973130993e1. All 14 valid runs pass BCH 2026 consensus ' +
    'and standard policy under one locking graph. The companion source generator certifies exact ' +
    '1 satoshi-per-byte fee templates; the covenant contracts do not pin satoshi values. The prescribed ' +
    'checkpoint key is synthetic ' +
    'and publishes its setup and IC scalars, so the vectors establish complete-equation execution and ' +
    'covenant validity for that key, not circuit knowledge, secure public-input-vector binding, or ' +
    'independent-setup interoperability. Relayability is measured across the accepting fixture suite; ' +
    'this track does not claim a proof-independent relay ceiling for every valid proof.',
  load: async () => {
    const valid: Step[] = v.steps.map(toStep);
    const tampered = (i: number): Step[] => [{ ...valid[i]!, unlockingBytecode: hexToBin(v.steps[i]!.invalidUnlocking!) }];
    // Tamper at the GLV genesis, an early Miller state, a late Miller state, and the terminal verdict.
    const invalid: Step[][] = [
      tampered(0),
      tampered(Math.min(6, valid.length - 1)),
      tampered(valid.length - 2),
      tampered(valid.length - 1),
      ...(v.invalidRuns ?? []).map((run) => run.map(toStep)),
    ];
    const extraValidProofs: Step[][] = [
      ...(v.extraProofSteps ? [v.extraProofSteps.map(toStep)] : []),
      ...(v.worstCaseSteps ? [v.worstCaseSteps.map(toStep)] : []),
      ...Object.values(v.identityProofSteps ?? {}).map((steps) => steps.map(toStep)),
    ];
    const worstCaseProof: Step[] | undefined = v.worstCaseSteps?.map(toStep);
    const invalidInputs: Step[][] = v.invalidInputSteps
      ? Object.values(v.invalidInputSteps).map((steps) => steps.map(toStep))
      : [];
    return { valid, invalid, extraValidProofs, worstCaseProof, invalidInputs };
  },
};
