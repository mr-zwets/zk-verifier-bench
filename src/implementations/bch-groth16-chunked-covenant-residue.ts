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
// Committed proof: 92,946 script B; 94,541 harness-score B; 94,539 actually serialized B
// across 12 transactions; 69,900,119 op. The second proof is 94,556 actual wire B and the
// dense proof is 111,491 actual wire B. All 14 valid runs pass both BCH 2026 consensus and
// standard-policy VMs under the same lockings, and every individual transaction is at most
// 9,840 bytes and 7,752,921 op-cost across the accepting suite. The companion source generator
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
// Reproduction: groth16_cashscript commit d0245ba223f1112a69d12ce094dad5a3e0d19399,
// cashc commit
// 1c707c1dbf87396b30ba5e0704b1db44475ce893:
//   VERIFIER_DIR=/path/to/zk-verifier-bench pnpm vectors:covenant:torus
//
// Input fixture SHA-256:
//   multiproof d513f1fe45d7aba20f289cbc38439d5ebdb05a9975950a5e32d2bf21239d4abc
//   pairing checkpoint e393e8b6af6f528c93f97f37656802bf44daefa5819640a557fbff95e236739e
// Vector SHA-256: df77d16b95f362df2149f1782997d01d760b11ca164c82e0d9b226a53d10b8a4
// Locking graph SHA-256 (UTF-8 concatenated locking-hex text):
// 280d78910d7f0f257c17ac24f7465646bce266b5202067bbdad2911527d409a8
//
// sha256 of locking bytecode, in transaction order:
//   00 804ed64e508391fd6cf1e28a8673d1e46209fba4ce6a6fde5a520da97b4d71f5
//   01 fac59f5c6a99941a583c77ba71b5e3b5356e72d74f0b3644b031901330850c9e
//   02 2d6d7270c63064dfa7ad495ab2e195cdef5bbdc553655b4ba6c279ed3752589b
//   03 d5abb885a1d1b147fffd96757efad1b5b402b7a429e6e4c6eb73319d8009aaa6
//   04 746df99b845f9dd81f854e61cd91f33ce93d147785de4c64ff2b366dae6de837
//   05 65e0648b5677cf14d0dd3bc5074c296cc91851f5aa05890b403982b4238a3cc0
//   06 dfcd310b1cfc60510d8fcc2795fb3076cfad200d65fde53b85f7bfb6a8f528a6
//   07 3e1f84de7755a56bfe5568412cf6a257f2d17e1cec5a66fd500c58cf435a6fe0
//   08 91107f77f0fd333fc3ebe57bb57dfc8255d06f100af8e966e0f783c6fb90b6ff
//   09 90d9efd57c05e340fa659c56a032e23faf85baa1b71a5348957fba83633a9573
//   10 3f5a6d47712e1bcf92ce88907dfbbdd93a93b2bbee561969c1b5cd209b23cdf9
//   11 aec7a2bb061043487f7505b1eb17bb87c818b1e30eb618df253c847c3fd797e9
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
    'd0245ba223f1112a69d12ce094dad5a3e0d19399 with the pinned input fixtures and cashc ' +
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
