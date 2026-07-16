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
// Committed proof: 92,343 script B; 93,938 harness-score B; 93,936 actually serialized B
// across 12 transactions; 69,888,236 op. The second proof is 93,946 actual wire B and the
// dense proof is 110,891 actual wire B. All 14 valid runs pass both BCH 2026 consensus and
// standard-policy VMs under the same lockings, and every individual transaction is at most
// 10,161 bytes and 7,722,180 op-cost across the accepting suite. The companion source generator
// certifies exact 1 satoshi-per-serialized-byte fee templates; the covenant contracts do not pin
// satoshi values. The currently published entry is 92,389 script B / 93,984 harness-score B /
// 93,982 actual wire B / 69,897,089 op across 12 transactions.
// The harness's covenant overhead model is two bytes above actual serialization because it
// includes an empty-commitment length byte for the baton and terminal NFT; every total is labeled.
//
// The prescribed checkpoint key is synthetic and publishes its setup and IC scalars. The contracts
// evaluate the complete four-pair equation, but these vectors do not establish circuit knowledge,
// secure binding of the public-input vector, or interoperability with an independently generated
// setup. Relayability is demonstrated for the 14 accepting fixture families; unlike the one-tx
// track, this covenant entry does not claim a proof-independent relay ceiling for every valid proof.
//
// Reproduction: groth16_cashscript commit c90f27b659750ffe090f6b9854d02b923a149f0d,
// cashc commit
// 1c707c1dbf87396b30ba5e0704b1db44475ce893:
//   VERIFIER_DIR=/path/to/zk-verifier-bench pnpm vectors:covenant:torus
//
// Input fixture SHA-256:
//   multiproof d513f1fe45d7aba20f289cbc38439d5ebdb05a9975950a5e32d2bf21239d4abc
//   pairing checkpoint e393e8b6af6f528c93f97f37656802bf44daefa5819640a557fbff95e236739e
// Vector SHA-256: 0829b898d798de01a48adc464fa4c00c99d3c2a057429a2f5fda749faebb6467
// Locking graph SHA-256 (UTF-8 concatenated locking-hex text):
// 73fe974ca5f2199679c357df6be49617dfff162190b6bc922c18c24b51c1f5a2
//
// sha256 of locking bytecode, in transaction order:
//   00 3aeca83459d7da9ac0350ef0796d1ad17c8070148e9556eec5af6d386b985040
//   01 2c9ffb70a7576eb7c764494123cd8da63be5426fa3f724357bdb8540510ca2da
//   02 ec22a60e3fca1ade2428f6530060cef6031aa47a9d4acbe052eec100626ef506
//   03 6e39de33452beb2e34f8cd0e277e3e80e7fbeb6d34215e358376c2ed5841bbb0
//   04 766455e65c7d537d3c8ee514cb89d6d1dbdaed4ef9ba1b6d29517a1a972492be
//   05 4796440c29e9096aed43fd6bf07606e7650b00bed9cc552babed9704dcd04594
//   06 314c23175330a8cac84bcdad14ee06843951e27671b6c71ebe733adf48df79bb
//   07 d68d5ae026cdde247f120ac93efd4cfc963163d8fb7c8f672ead54c5a82f3bc2
//   08 fec9c0e3f9b35f3086787bb1a080ab80236c4273fd1fdd98e2ae835c457ca7ae
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
    'c90f27b659750ffe090f6b9854d02b923a149f0d with the pinned input fixtures and cashc ' +
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
