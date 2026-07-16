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
// Committed proof: 92,781 script B; 94,376 harness-score B; 94,374 actually serialized B
// across 12 transactions; 70,004,192 op. The second proof is 94,394 actual wire B and the
// dense proof is 111,331 actual wire B. All 14 valid runs pass both BCH 2026 consensus and
// standard-policy VMs under the same lockings, and every individual transaction is at most
// 10,127 bytes and 7,902,941 op-cost across the accepting suite. The companion source generator
// certifies exact 1 satoshi-per-serialized-byte fee templates; the covenant contracts do not pin
// satoshi values. The currently published entry is 104,901 script B / 106,754 harness-score B /
// 106,752 actual wire B / 78,686,995 op across 14 transactions.
// The harness's covenant overhead model is two bytes above actual serialization because it
// includes an empty-commitment length byte for the baton and terminal NFT; every total is labeled.
//
// The prescribed checkpoint key is synthetic and publishes its setup and IC scalars. The contracts
// evaluate the complete four-pair equation, but these vectors do not establish circuit knowledge,
// secure binding of the public-input vector, or interoperability with an independently generated
// setup. Relayability is demonstrated for the 14 accepting fixture families; unlike the one-tx
// track, this covenant entry does not claim a proof-independent relay ceiling for every valid proof.
//
// Reproduction: groth16_cashscript commit 27c5d5e4a9c7404bc79135b73832788991e7f19f,
// cashc commit
// 1c707c1dbf87396b30ba5e0704b1db44475ce893:
//   VERIFIER_DIR=/path/to/zk-verifier-bench pnpm vectors:covenant:torus
//
// Input fixture SHA-256:
//   multiproof d513f1fe45d7aba20f289cbc38439d5ebdb05a9975950a5e32d2bf21239d4abc
//   pairing checkpoint e393e8b6af6f528c93f97f37656802bf44daefa5819640a557fbff95e236739e
// Vector SHA-256: b0ad2b1166503604ab0157d1f11bfca4c6aaf15da76b6f96ed7b9f501fd43a25
// Locking graph SHA-256 (UTF-8 concatenated locking-hex text):
// 21b8555c00e5713ef857d066f20fc9b19337d9e6ad5c903d95f3d20de38a9e3d
//
// sha256 of locking bytecode, in transaction order:
//   00 55c8990d1b9502b1c79de68a6406a54ef3420095bb7d6169eb6565180f74e915
//   01 6210f758fc2daadcc51a8dbb5cc76e61ffbc723e8cca4b631155b5fe4e4dfd02
//   02 0efaf6e5565e0746d2bf5976da7796bb72980102b1b2b38f8f4f9724bb87a76b
//   03 6b73ed2a4937b0023a667c095efb379eedc5b1f0dccb71174c961b71d88c4c0a
//   04 80d9bfaa0ed9137d4c3ffbd80dfd95d82e0b76c9e86dc69738084edfbad82683
//   05 700fa9d160082c6dec9f20efc132bfd0f191c4956d3436d87c577f7a234f4902
//   06 e5fdeef6f11b697feef5e7480e3ff498c08f40ba7221b5fd69f79d6e61508938
//   07 d923d485ec77b6032b5615b6e868a581dbd51dfa1848b306b203803c81de01bb
//   08 ea87358a3fabf218a8ab0f3f16cea014bf0dce4783b844b103f9acb999119e78
//   09 0e55b3a18d6c5a1e1494f4e00268c9b1476f2d0339302b00f77faca2d8087788
//   10 7cd9f79339d655bb1d1a4bfee5dc7e03decf219fcf2139cb54ba0890e53d856b
//   11 f6fba8336b190db01a9bdd9b1cd2002293bc2d6c09d36e3c1a096be65c16ddb2
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

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
  name: 'BCH Groth16 covenant quotient-torus verifier (12 standard transactions)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'multi-tx',
  proofBinding: 'runtime',
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
    '27c5d5e4a9c7404bc79135b73832788991e7f19f with the pinned input fixtures and cashc ' +
    '1c707c1dbf87396b30ba5e0704b1db44475ce893. All 14 valid runs pass BCH 2026 consensus ' +
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
