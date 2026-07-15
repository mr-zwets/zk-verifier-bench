// BCH-native fixed-VK BLS12-381 Groth16 verifier in one current-BCH standard transaction:
//
//   width-six fixed-base comb for D                         2 inputs
//   affine two-pair Miller + quotient-torus verdict        10 inputs
//                                                           ---------
//                                                           12 inputs
//
// This repository's verification key has beta=5*G2.BASE, gamma=7*G2.BASE, and
// delta=11*G2.BASE. Bilinearity therefore rewrites the four-pair Groth16 equation to
//
//   e(-A, B) * e(D, G2.BASE) = 1,  D = 5*alpha + 7*vk_x + 11*C.
//
// A 43-iteration, width-six fixed-base comb computes the public-input term with 63 affine
// table entries. The proof witness carries the invertible transformed point
// T=11*C+5*alpha+7*IC0, and the final comb input adds T to the public-input term. The 6,048-byte
// table is split across Miller inputs 6, 8, and 10; each carrier has an exact argument length,
// and the final comb input reconstructs and hash256-pins the complete table.
//
// The Miller accumulator lives in Q=Fp12*/Fp6*. A canonical six-limb u represents the finite
// class [c]=[1+u*W]. For lambda=p+|x|, gcd(lambda,p^6+1)=r, so the lambda-power image is exactly
// the final-exponent kernel in Q. The terminal input checks [fF]=[frob(c,1)] using a nonzero
// projective cross-product. A fixed r-torsion shift supplies a finite representative for every
// accepting class without changing its lambda power. Because the final-exponent result is
// r-torsion and gcd(r,p^6-1)=1, this quotient verdict is equivalent to the full pairing verdict.
//
// A and the transformed C term use canonical field encodings and on-curve gates. B additionally
// passes the fused psi(B)==[-x]B order-r subgroup gate; canonical identity encodings are handled
// explicitly. G1 subgroup walks are unnecessary here because A and C are paired only with order-r
// G2 points, so their cofactor components contribute the identity to the reduced pairing.
//
// Input 0 is the graph entry. Every program requires the exact 12-input count and its exact input
// index; every nonterminal program SHA-256-pins its immediate successor's full P2SH32 locking
// bytecode. OP_INPUTBYTECODE then binds the exact state handoff. This terminal-to-root construction
// is acyclic, and input 0 transitively commits to all eleven successors. The generator verifies all
// eleven successor pins and asserts that the same locking graph accepts all 15 valid-domain fixtures.
// This is a rooted transaction predicate: spending the designated input-0 verifier UTXO enforces
// the complete graph; an individual suffix UTXO does not independently establish the full prefix.
//
// Exact comparison with the currently published 34-input entry:
//                         published       this vector       reduction
//   inputs                       34                12           64.71%
//   script bytes            195,413            97,455           50.13%
//   serialized bytes        195,705            97,571           50.14%
//   leaderboard score       196,895            97,991           50.23%
//   consensus op-cost   153,091,714        77,865,802           49.14%
//
// The exact funded transaction pays 97,571 satoshis (1 sat/byte), has hash256
// 4daf3309ca4059d1f87d60582d2f56f9a2f315927a350a81c5debfc6f6cf6d45, and passes both
// BCH 2026 consensus and default-policy VMs. Across the 15 valid fixtures, the largest concrete
// input is 7,333,570 consensus / 7,345,602 standard op-cost and 9,142 unlocking bytes. The vector
// includes 23 rejection fixtures plus three isolated point-validation fixtures.
//
// The source-pinned proof-independent resource certificate covers 40 control sites and all 78
// required edges. Its all-canonical-input envelope is 98,570 serialized bytes (1,430-byte policy
// margin), with every unlocking <=9,172 bytes and every consensus/standard input <=7,357,920 /
// 7,369,952 op-cost. It also checks the independent standard hash-density bound and proves the
// fixed-comb table entry used for the initial numeric envelope is componentwise maximal.
//
// Byte-exact provenance:
//   source: groth16_cashscript commit 0819bb0ca786a6500eec6d9bebb5d2037d380c1a
//   compiler: CashScript commit 1c707c1dbf87396b30ba5e0704b1db44475ce893 (enforced clean)
//   vector sha256: 7868c0fde00dd7c9aedf50cf2679f18e039db5519afc28cd6b6e2b714ed7bb4b
// Reproduce from the source checkout; the command regenerates the bytecode and vector, runs the
// algebra/bounds/dual-VM suites, and finishes with the proof-independent resource certificate:
//   VERIFIER_DIR=/path/to/zk-verifier-bench pnpm vectors:intratx:torus:bls
//
// sha256 of locking bytecode, in input order:
//   00 be18f9846847a72ab3a6b28f56cbdc9f0d83c7f3b33cfbdcf095e5655aed666b
//   01 1c48ba582aa280ffbc48f2f1d4ff8e72f0b1cb136866920d204217350dbbbb8d
//   02 0a4719bb7083d8448b604f8c0f6e38ff10802e7949c1b0438b59c5f63da86393
//   03 bf6ed068a4ce1b95e21044b1bcd0bd1e193c472461f0d2ab537c4f85835fb986
//   04 c85d229a6661878951ebb80d028f6f96cb747534bf50d147651d5b6a8510795b
//   05 7779a259b759a882dfed1fe0ecbbcc4ec2cb0f4e6561153cf15977da058a8b4a
//   06 569df373c371788a16f8e0155c9aeab987a2264a9e4af261faf9f49218418d63
//   07 5491de4be2d5a3ded15c5341f90f2b1dafd7405938f3ff0765af81f4a108c947
//   08 37bdf10ac873d1e9abc39846f8b62716b77b166a26b3b1d0b2288fcd1bcae795
//   09 89a1478cee0c0931666590a2bd2213ced05ddfddcec4a32fca3ed1a3f58e4eb5
//   10 89523e72e7ecb6f529a6546fe00abb0a3def5743c17a983fd4ecc51077e56245
//   11 df1b8665bacd0434a7d867a966d5beb9b70384f2031dabd847a53ce41f5cc595
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep { label: string; locking: string; unlocking: string; checkpoint?: string }
interface Vectors { steps: RawStep[]; extraValidProofs?: RawStep[][]; worstCaseProof?: RawStep[]; invalid?: RawStep[][]; invalidInputs?: RawStep[][] }

const v = JSON.parse(readFileSync('src/bch/groth16-bls12381-intratx-residue-vectors.json', 'utf8')) as Vectors;

// Turn one run (an ordered list of chunk inputs) into Step[] sharing ONE inputs array, so each
// step is evaluated against the same multi-input transaction (its tx.inputs[idx±1] introspection
// resolves to the real siblings).
const toRun = (raw: RawStep[]): Step[] => {
  const inputs = raw.map((s) => ({ lockingBytecode: hexToBin(s.locking), unlockingBytecode: hexToBin(s.unlocking) }));
  return raw.map((s, i) => ({ label: s.label, lockingBytecode: inputs[i]!.lockingBytecode, unlockingBytecode: inputs[i]!.unlockingBytecode, checkpoint: s.checkpoint, intraTx: { index: i, inputs } }));
};

export const bchGroth16Bls12381IntratxResidue: Implementation = {
  id: 'bch-groth16-bls12381-intratx-residue',
  name: 'BCH BLS12-381 Groth16 fixed-VK quotient-torus (12-input standard one-tx verifier)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'BCH-native CashScript fixed-key verifier in one 12-input transaction. Bilinearity collapses ' +
    'the four-pair equation to e(-A,B)*e(D,G2.BASE)=1, where D=5*alpha+7*vk_x+11*C. Two ' +
    'width-six fixed-base-comb inputs assemble D, and ten affine two-pair Miller inputs finish a ' +
    'quotient-torus residue verdict. Exact state and carrier lengths bind the 6,048-byte hash-pinned ' +
    'comb table. The proof supplies the invertible transformed point 11*C+5*alpha+7*IC0. Every ' +
    'script requires its exact input position and the exact transaction input ' +
    'count; input 0 transitively SHA-256-pins every successor P2SH32 program while ' +
    'OP_INPUTBYTECODE binds each state handoff. Canonical field, curve, identity, and G2 subgroup ' +
    'gates cover the runtime proof domain. One locking graph accepts all canonical satisfying proofs ' +
    'for this VK. The primary funded spend is 97,571 bytes at an exact 1 sat/byte fee and passes ' +
    'both current-BCH consensus and default relay policy. A source-pinned proof-independent resource ' +
    'certificate bounds all canonical inputs to 98,570 bytes and every standard input to 7,369,952 ' +
    'op-cost.',
  load: async () => ({
    valid: toRun(v.steps),
    extraValidProofs: (v.extraValidProofs ?? []).map(toRun),
    worstCaseProof: v.worstCaseProof ? toRun(v.worstCaseProof) : undefined,
    invalid: (v.invalid ?? []).map(toRun),
    invalidInputs: (v.invalidInputs ?? []).map(toRun),
  }),
};
