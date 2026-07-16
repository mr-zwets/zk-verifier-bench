// BCH-native BLS12-381 Groth16 verifier for the same fixed benchmark VK as the published grouped
// entry. It evaluates the complete equation
//
//   e(-A,B) * e(alpha,beta) * e(IC0 + in0*IC1 + in1*IC2,gamma) * e(C,delta) = 1
//
// with runtime A/B/C and two runtime public inputs. The fixed e(alpha,beta) Miller value and the
// fixed-G2 gamma/delta line coefficients are ordinary VK preparation; the runtime terms are not
// collapsed with the fixture's published scalar relations.
//
// The graph has five shared-table GLV vk_x inputs followed by 21 fused prepared-Miller inputs,
// packed 9/9/8 into three transactions. The Miller accumulator lives in Q=Fp12*/Fp6*. A
// canonical six-limb u represents the finite class [c]=[1+u*W]. For lambda=p+|x|,
// gcd(lambda,p^6+1)=r, so the lambda-power image is exactly the final-exponent kernel in Q. The
// final Miller input checks the projective Frobenius relation and rejects the zero representative.
//
// A and C use canonical half-normalized G1 coordinates, reserve (0,0) for identity, and are checked
// on-curve. Their G1 subgroup checks are intentionally omitted: each is paired only with an
// order-r G2 point, so G1 cofactor components pair trivially and do not enlarge the accepted
// prime-order equation. Their encodings are therefore not claimed to be unique modulo cofactor
// components. Non-identity B is canonical, on-curve, and checked in the exact G2 subgroup; all-zero
// B maps to a fixed G2 base paired with the effective G1 identity.
//
// OP_INPUTBYTECODE binds all 23 in-group successor states and lockings. Each group root fixes input
// index zero and the exact input count, requires input[0] to carry a mutable NFT, and excludes its
// 32-byte category from every sibling input. The two cross-group hand-offs pin the successor P2SH32
// locking and carry hash256(state); full tokenCategory equality pins category and mutable capability.
// The terminal root requires exactly one token-free output, burning the thread. Committed fixtures
// reject a stripped capability, a minting input/output thread, a same-category sibling token, and a
// retained terminal token. A deployment designates the initial group-0 token UTXO as the graph root
// and must retain control of that category's minting authority.
//
// Exact committed measurements: 204,424 script B; 205,734 challenge-score B; 204,894 serialized
// spend B across 3 transactions (46,535 / 82,049 / 76,310); 160,953,436 op; maximum input
// 8,004,501 op. The same 26 lockings accept ten measured runtime fixtures plus a separate valid
// all-position GLV stress run. Across that accepting suite, the largest transaction is 83,356 B,
// maximum input is 8,004,501 op, and maximum unlocking bytecode is 9,980 B; every transaction
// passes the BCH 2026 consensus and current standard-policy VMs with an exact 1 sat/B fee template.
// The contracts do not constrain satoshi values. The vectors also commit 27 rejecting runs and
// four isolated point/range rejection runs, including finite off-curve C and complete token flow.
//
// Against the immediate-upstream 34-input artifact, this schedule removes 8 inputs and lowers
// score by 1,975 B, serialized size by 1,695 B, script bytes by 1,631 B, and total op-cost by
// 1,294,337. In the measured accepting suite, the largest transaction falls from 87,708 B to
// 83,356 B; maximum input cost rises to 8,004,501 op and maximum unlocking bytecode rises to
// 9,980 B, both within current policy. It does not claim the overall cross-curve record or a
// single-transaction result.
//
// The prescribed fixed benchmark key is synthetic and publishes its setup and IC scalars. These
// vectors establish complete-equation execution and BCH transaction packaging for that key; they do
// not establish circuit knowledge, secure application public-input binding, arbitrary-VK support,
// or independent-setup interoperability. Relayability is measured across the accepting fixture
// suite, not asserted as a proof-independent size ceiling for every possible witness.
//
// Byte-exact provenance:
//   source: groth16_cashscript commit 2b76007bec86727ccc0018dcb4ea9b905042a52f
//   compiler: CashScript commit 1c707c1dbf87396b30ba5e0704b1db44475ce893
//   vector sha256: eb8806c597a83048f7c6bfc66aaa0d0c9afc710d7890a6503b509e5f63f42441
//   Miller manifest sha256: 3eb42b9b506752d76f09433de5b4fca59fe94ba2cfd079a12b827bc45110d888
//   locking graph sha256 (UTF-8 concatenated locking-hex text):
//     028335fbd7cfc80524a76b615b1cdaafba4713d47d059b40366a1cced4aea692
// Reproduce from the source checkout:
//   VERIFIER_DIR=/path/to/zk-verifier-bench BLS_QUOTIENT_TORUS=1 pnpm vectors:grouped:residue:bls
//
// sha256 of locking bytecode, in graph order:
//   00 34fb27f3ea859149f8e9e18e15d380e9b779a8099fa01d247c090a7f496965a1
//   01 582933f9eb8e09cdd22fcb4a68ab43e935024340336c801ddf793939d1d058de
//   02 40e8a96fff096e4dce75f9bb98b9b18e50ffddffb293b563e6d879235d0b1aba
//   03 da8e6011a9f9183bdd8725f8bf7ab9346f384d659d03c8ff73315c8e313384e7
//   04 fd61b736066bc21eace19784e06a5c90f516cfab8100f3cd091640e075e4553c
//   05 55dc57f05fd7f91ca3d11ef8bae626a5280fe5f545492dea94052dbf7de862b4
//   06 0c2eb086e4750da9ada0d9582e009f5131d267f28e3e1252920159cf7c4f0d98
//   07 f54ec2af00b4896149078d06759bc80eb706ba94b9bee8c4bdaba05595f61ecf
//   08 1fcafcfffac888ad4590fc26b94e0c200dc6433b9f6cac4184b7be8b69581020
//   09 d6c072b8890e63813c6ca7a18f310f1d8c730f3ddf3843b155090cbcef146d94
//   10 61e5a76e286544995001776c331f3b23d4c810552a91eb03750d4d1cf0a86fba
//   11 3edffd34d79bd2699e602c65835a95f7b6bddd403efdc5ae119524ea5ff4741d
//   12 34d9f81894cfd13b44da6fa24d449c2021eb123e871d97c76e392fc48893b1cc
//   13 768c514c2bdffa204ce235a3b0ef7ad41d8854a574b52190c33fd527f20e1186
//   14 ee9baf1cda573e948b266c7b9b8ad70bc2ee5af4d44695f6cd7eccc2588c8a32
//   15 b25054b510be50ff5d6b3dd82ebb2da088963fe5bce909f2ef5de610e567c300
//   16 52797daa4d66a062a7bc8834d1677e2a0b55e4b98b183c883f53be3d6f60b9cb
//   17 614959aaf5b3c5eb18da45b898566d94ff7cf13ba63322a67bd55ea8528c0649
//   18 f9a22f230b02a4e84df614945dc9c34dae367215dacf5f25723bce7e47925eca
//   19 b84433d0fb275a0ab7a5e8891249ea3e0197a12cbb5685dc044efc7641b65f7b
//   20 eacc6fe369c22b3d1bbe9f73da748419504f141c64f33113e722188c2fb300e9
//   21 ea7d22dea1041379639096215ca37022667dc54c2bdf72764ea80f9d2fc040c5
//   22 434d105d95b439a857c52b13715b62176c75ffbcc3e0a3708d4350b7b3a91346
//   23 713f41dd7b68a23dc5bd573447ac960ede09da143ba4a5acb391d44cd6ed7d60
//   24 1e239caf491eb8053c93092f68e5d06935ba83ca7efbec553e30823623a635e0
//   25 2237117e28a0fb0333a9a27659a5ae119a7fb38bd918a53f59d8279717b971b7
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep { label: string; locking: string; unlocking: string; checkpoint?: string; group: number }
interface RawGroup {
  lo: number; hi: number;
  inToken: { capability: 'none' | 'mutable' | 'minting'; commitment: string } | null;
  inputTokens?: ({ capability: 'none' | 'mutable' | 'minting'; commitment: string } | null)[];
  outToken: { capability: 'none' | 'mutable' | 'minting'; commitment: string } | null;
  outLocking: string | null;
}
interface RawRun { steps: RawStep[]; groups: RawGroup[] }
interface Vectors { category: string; valid: RawRun; extraValidProofs?: RawRun[]; worstCaseProof?: RawRun; invalid?: RawRun[]; invalidInputs?: RawRun[] }

const v = JSON.parse(readFileSync('src/bch/groth16-bls12381-grouped-residue-vectors.json', 'utf8')) as Vectors;
const CATEGORY = hexToBin(v.category);

const toRun = (run: RawRun): Step[] => {
  const inputsByGroup = run.groups.map((g) =>
    run.steps.slice(g.lo, g.hi + 1).map((s) => ({ lockingBytecode: hexToBin(s.locking), unlockingBytecode: hexToBin(s.unlocking) })),
  );
  const inputTokensByGroup = run.groups.map((g) => g.inputTokens?.map((token) => token
    ? { capability: token.capability, commitment: hexToBin(token.commitment) }
    : undefined));
  return run.steps.map((s, i) => {
    const g = run.groups[s.group]!;
    return {
      label: s.label,
      lockingBytecode: hexToBin(s.locking),
      unlockingBytecode: hexToBin(s.unlocking),
      checkpoint: s.checkpoint,
      grouped: {
        group: s.group,
        index: i - g.lo,
        inputs: inputsByGroup[s.group]!,
        category: CATEGORY,
        inToken: g.inToken ? { capability: g.inToken.capability, commitment: hexToBin(g.inToken.commitment) } : undefined,
        inputTokens: inputTokensByGroup[s.group],
        outToken: g.outToken ? { capability: g.outToken.capability, commitment: hexToBin(g.outToken.commitment) } : undefined,
        outLockingBytecode: g.outLocking ? hexToBin(g.outLocking) : undefined,
      },
    };
  });
};

export const bchGroth16Bls12381GroupedResidue: Implementation = {
  id: 'bch-groth16-bls12381-grouped-residue',
  name: 'BCH BLS12-381 Groth16 grouped quotient-torus verifier (26 inputs, 3 current-policy standard transactions)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'multi-tx',
  proofBinding: 'runtime',
  // Every group root requires one mutable state NFT at input[0], excludes the same category from
  // siblings, and fixes its input layout. Nonterminal covout equality pins output[0]'s category and
  // mutable capability; the terminal root requires one token-free output and burns the thread.
  tokenSafetyEnforced: true,
  source:
    'BCH-native CashScript: the complete four-pair BLS12-381 Groth16 equation for the same fixed ' +
    'benchmark VK as the published grouped entry, with runtime public inputs and runtime A/B/C. ' +
    'Five shared-table GLV vk_x inputs feed 21 fused prepared-Miller inputs. The fixed ' +
    'e(alpha,beta) Miller value and fixed-G2 gamma/delta line coefficients are ordinary VK ' +
    'preparation; runtime terms are not collapsed using the fixture\'s scalar relations. The ' +
    'accumulator lives in Fp12*/Fp6*, where one canonical six-limb u represents [c]=[1+u*W] and ' +
    'the terminal enforces the exact projective Frobenius relation while rejecting zero. A and C ' +
    'use canonical half-normalized G1 coordinates and are checked on-curve. Their G1 subgroup ' +
    'checks are intentionally omitted because each is paired only with an order-r G2 point, so ' +
    'cofactor components pair trivially and do not change the accepted prime-order equation; ' +
    'encoding uniqueness modulo those components is not claimed. Non-identity B is canonical, ' +
    'on-curve, and checked in G2; all-zero B represents pairing identity. OP_INPUTBYTECODE binds ' +
    'all in-group states and successor lockings. Group roots fix index zero and exact input count. ' +
    'Across groups, mutable NFT commitments bind state, successor locking, category, and capability. ' +
    'Group roots exclude same-category sibling inputs and the terminal root burns the thread; the ' +
    'vectors replay capability stripping, minting-thread, sibling-token, and retained-terminal-token ' +
    'rejections. One fixed 26-locking P2SH32 graph ' +
    'accepted ten measured runtime fixtures plus the separate all-position GLV stress run. Every ' +
    'transaction in that suite passes BCH 2026 consensus and current standard policy, remains under ' +
    '100,000 bytes, and has an exact 1 sat/B fee template; the contracts do not constrain satoshi ' +
    'values. Byte-exact vectors reproduce from groth16_cashscript ' +
    '2b76007bec86727ccc0018dcb4ea9b905042a52f and CashScript ' +
    '1c707c1dbf87396b30ba5e0704b1db44475ce893. The fixed benchmark key is synthetic and publishes ' +
    'its setup and IC scalars, so these vectors establish complete-equation execution and BCH ' +
    'packaging for that key, not circuit knowledge, secure application public-input binding, ' +
    'arbitrary-VK support, independent-setup interoperability, or a proof-independent standardness ' +
    'ceiling for every possible witness.',
  load: async () => {
    const valid = toRun(v.valid);
    const extraValidProofs = (v.extraValidProofs ?? []).map(toRun);
    const worstCaseProof = v.worstCaseProof ? toRun(v.worstCaseProof) : undefined;
    const invalid = (v.invalid ?? []).map(toRun);
    const invalidInputs = (v.invalidInputs ?? []).map(toRun);
    return { valid, extraValidProofs, worstCaseProof, invalid, invalidInputs };
  },
};
