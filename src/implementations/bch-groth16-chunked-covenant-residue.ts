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
// Committed proof: 92,389 script B; 93,984 harness-score B; 93,982 actually serialized B
// across 12 transactions; 69,897,089 op. The second proof is 93,997 actual wire B and the
// dense proof is 110,941 actual wire B. All 14 valid runs pass both BCH 2026 consensus and
// standard-policy VMs under the same lockings, and every individual transaction is at most
// 10,127 bytes and 7,902,941 op-cost across the accepting suite. The companion source generator
// certifies exact 1 satoshi-per-serialized-byte fee templates; the covenant contracts do not pin
// satoshi values. The preceding published entry is 92,781 script B / 94,376 harness-score B /
// 94,374 actual wire B / 70,004,192 op across 12 transactions.
// The harness's covenant overhead model is two bytes above actual serialization because it
// includes an empty-commitment length byte for the baton and terminal NFT; every total is labeled.
//
// The prescribed checkpoint key is synthetic and publishes its setup and IC scalars. The contracts
// evaluate the complete four-pair equation, but these vectors do not establish circuit knowledge,
// secure binding of the public-input vector, or interoperability with an independently generated
// setup. Relayability is demonstrated for the 14 accepting fixture families; unlike the one-tx
// track, this covenant entry does not claim a proof-independent relay ceiling for every valid proof.
//
// Reproduction: groth16_cashscript commit b4d9780275d5f1545465c2dec9702e70ea621006,
// cashc commit
// 1c707c1dbf87396b30ba5e0704b1db44475ce893:
//   VERIFIER_DIR=/path/to/zk-verifier-bench pnpm vectors:covenant:torus
//
// Input fixture SHA-256:
//   multiproof d513f1fe45d7aba20f289cbc38439d5ebdb05a9975950a5e32d2bf21239d4abc
//   pairing checkpoint e393e8b6af6f528c93f97f37656802bf44daefa5819640a557fbff95e236739e
// Vector SHA-256: a77b1166beeafbc0ff3bfc9d9c7c61942ac00e7a8b184a13d84c95a0bd7eb0d2
// Locking graph SHA-256 (UTF-8 concatenated locking-hex text):
// 5020578322c3c25436f0c5edae26626bb1f0a70c0d6fa77613896d87cc892771
//
// sha256 of locking bytecode, in transaction order:
//   00 20b8adc9fc9340971ea5253b781d0ae5ede2e3c7b410c425df8deaef941f1346
//   01 570e616589155709152c9229762ac7b47800223d08109c9ec786ab4b3b206b87
//   02 db69fc09c118da6d40a2ca56726b86c592fad533014a090a85f754ca2acc52c3
//   03 7a63de2e82dc7524a10b1a52c04007a3a5d198198ba6bab49231ed18de8446f0
//   04 e1e20485b01221b5d73448ef2cb8360db097092f977acb42587432e066b3ff97
//   05 426cf80c63792be0ee5e7ad01016a3cc1fea79740064674e42a1038cec9b16cf
//   06 a1407fd6c1cb06164844a9fa2e7c661a90385c933be60e5894a2da5fab3a7d6b
//   07 b495bd8f8979d9ed778aecfc37e58dd3746204a9c1c1c1c2ab67a852417c02dd
//   08 316bc7e38904c7b94b6e6c6d7388c1cdb84e0039e54d59965744eb87c5ef4781
//   09 c6df0a08f44299e8a166fd9b34b4c4fcbaa07b08a38ebc6de85cfeffd3c193df
//   10 e7caf69566db1c8c47365329baefeacadca7aae76d33506a60ab079928cecf61
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
    'b4d9780275d5f1545465c2dec9702e70ea621006 with the pinned input fixtures and cashc ' +
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
