// BCH-native covenant-threaded BN254 Groth16 quotient-torus verifier.
//
// Source-reproducible covenant graph:
//   vk_x = IC0 + in0*IC1 + in1*IC2 (four-scalar GLV MSM)  ->  4 transactions
//   affine/unit-line Miller + quotient residue verdict     -> 10 transactions
//                                                            ----------------
//                                                            = 14 transactions
//
// The Miller accumulator lives in Q=Fp12*/Fp6*. A six-limb canonical u represents
// [c]=[1+u*W], and [c^-1]=[1-u*W]. In Q, gcd(lambda,p^6+1)=r for
// lambda=6x+2+p-p^2+p^3, so the lambda-power image is exactly the final-exponent kernel.
// The terminal checks [f*c^(p^2)]=[c^p*c^(p^3)] and explicitly rejects the projective
// zero representative. The older Fp6 residue-coset correction disappears in Q.
//
// The GLV minting-baton genesis commits the proof tuple while computing vk_x, then emits
// exactly (-A,B,C,vk_x). The first Miller transaction consumes that commitment, checks
// canonical A/B/C and all three curve equations, derives normalized unit-line coordinates,
// and introduces the finite quotient root. Runtime B is affine and its post-loop endomorphism
// endpoint is an exact G2 subgroup check. Later state is hash-committed in mutable NFT
// commitments. Each nonterminal pins its successor P2SH32 locking; the terminal verdict NFT
// is immutable. The genesis recreates its minting baton under the same locking and category.
//
// Committed proof: 104,901 script B; 106,754 harness-score B; 106,752 actually serialized B
// across 14 transactions; 78,686,995 op. The second proof is 106,548 actual wire B and the
// dense proof is 123,702 actual wire B; all three pass both BCH 2026 consensus and
// standard-policy VMs under the same lockings. The published predecessor was 232,811 script B /
// 236,470 harness-score B / 236,468 actual wire B / 181,018,795 op across 28 transactions.
// The harness's covenant overhead model is two bytes above actual serialization because it
// includes an empty-commitment length byte for the baton and terminal NFT; every total is labeled.
//
// Reproduction: groth16_cashscript commit 9c93f5c2433e56c618578dcf9bd9cdc88f2897c2,
// cashc commit
// 1c707c1dbf87396b30ba5e0704b1db44475ce893:
//   VERIFIER_DIR=/path/to/zk-verifier-bench pnpm vectors:covenant:torus
//
// sha256 of locking bytecode, in transaction order:
//   00 6450f225d6bc35567f84afcd0ddcb8f4ca72b8166a5fd19737d8e6c76d1781e7
//   01 da13425f021b735faff8e0c7ad21cb96d4dcbf3e624c5baab031d859b436a3f0
//   02 eda2aef8c7a8d672b8a9588bfb85e9652fb28bbbcc8e0ad7f07a07a9ed513c4b
//   03 fbec16a09514475ce45c7b34c2fa9346581876739360e281a5b1bb27409d763f
//   04 caa6ffaaf96ff65c046c298eb8b828119b2242d705970d296af3713ae719d5e3
//   05 1109d0da689d9374e1dba0a27dc07f5cd6e00fddffb4270e972385a244117020
//   06 39a5469cb2eb61338125273725d4bef78c88568e8e42d90d3fa24e9d3f5b5818
//   07 0ca3fdc3e6bcb165363f623358ed485c42b4ed5c9e23de7a6d7286ccbe3ddc2d
//   08 75df1457c400bbc1ac7eed4e4e7a3d50636e9d61cd0a94e113dd3059eb4a147c
//   09 33aa5513a6a25dd72a41f96296d45a051656894f18716b15c4c10b2979e241fb
//   10 f0b7e48d049b2c08368924385511fbb82e427b1413d8cb08f37e8e0c35a96211
//   11 5f95902612f0f9a789803d00e09eab8091f05ac1a21646fbbb21c92e17e00dfe
//   12 3f37c06fe172c0e623e416686e3e97504dcd33d0dc3c0a72a643ef3c60348a1b
//   13 01c11761858f09618885bf8d9266ca067a57c4f0411e6617c799cdb33bb698d1
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep {
  label: string; locking: string; unlocking: string; invalidUnlocking?: string; checkpoint?: string;
  kind: 'genesis' | 'forward' | 'terminal'; expectReject?: boolean;
  covenant: { category: string; capability: 'none' | 'mutable' | 'minting'; inCommitment: string; outCommitment: string; outLockingBytecode: string };
}
const v = JSON.parse(readFileSync('src/bch/groth16-chunked-covenant-residue-vectors.json', 'utf8')) as {
  steps: RawStep[];
  // A second independently minted proof with different canonical public inputs: same lockings,
  // distinct unlockings, demonstrating that the verifier bakes only the VK and structure.
  extraProofSteps?: RawStep[];
  worstCaseSteps?: RawStep[];
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
  name: 'BCH Groth16 covenant quotient-torus verifier (14 standard transactions)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'multi-tx',
  proofBinding: 'runtime',
  tokenSafetyEnforced: true,
  source:
    'BCH-native CashScript: the complete runtime-proof Groth16 verifier in 14 covenant-threaded ' +
    'transactions. A four-chunk GLV vk_x MSM begins at the minting-baton genesis and commits the exact ' +
    '(-A,B,C,vk_x) handoff. Ten affine/unit-line optimal-ate Miller chunks validate canonical A/B/C, ' +
    'enforce the G1/G2 curve equations and exact G2 subgroup endpoint, and evaluate the accumulator in ' +
    'Fp12*/Fp6*. One canonical six-limb finite residue root replaces c/cInv plus the Fp6 coset witness; ' +
    'the terminal checks the exact quotient relation and rejects projective zero. Canonical state limbs ' +
    'ride in NFT commitments. Every nonterminal pins its successor P2SH32 locking; token category and ' +
    'capability are fixed; the genesis recreates its minting baton; the terminal emits an immutable NFT. ' +
    'Byte-exact vectors reproduce from groth16_cashscript commit ' +
    '9c93f5c2433e56c618578dcf9bd9cdc88f2897c2 with cashc ' +
    '1c707c1dbf87396b30ba5e0704b1db44475ce893. All three distinct valid proofs pass BCH 2026 consensus ' +
    'and standard policy under one locking graph.',
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
    ];
    const worstCaseProof: Step[] | undefined = v.worstCaseSteps?.map(toStep);
    const invalidInputs: Step[][] = v.invalidInputSteps
      ? Object.values(v.invalidInputSteps).map((steps) => steps.map(toStep))
      : [];
    return { valid, invalid, extraValidProofs, worstCaseProof, invalidInputs };
  },
};
