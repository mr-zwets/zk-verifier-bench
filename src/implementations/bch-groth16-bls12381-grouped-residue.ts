// BCH-native BLS12-381 Groth16 verifier for the same fixed benchmark VK as the published grouped
// entry. It evaluates the complete equation
//
//   e(-A,B) * e(alpha,beta) * e(IC0 + in0*IC1 + in1*IC2,gamma) * e(C,delta) = 1
//
// with runtime A/B/C and two runtime public inputs. The fixed e(alpha,beta) Miller value and the
// fixed-G2 gamma/delta line coefficients are ordinary VK preparation; the runtime terms are not
// collapsed with the fixture's published scalar relations.
//
// The graph has five shared-table GLV vk_x inputs followed by 29 fused prepared-Miller inputs,
// packed 11/13/10 into three transactions. The Miller accumulator lives in Q=Fp12*/Fp6*. A
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
// OP_INPUTBYTECODE binds all 31 in-group successor states and lockings. Each group root fixes input
// index zero and the exact input count, requires input[0] to carry a mutable NFT, and excludes its
// 32-byte category from every sibling input. The two cross-group hand-offs pin the successor P2SH32
// locking and carry hash256(state); full tokenCategory equality pins category and mutable capability.
// The terminal root requires exactly one token-free output, burning the thread. Committed fixtures
// reject a stripped capability, a minting input/output thread, a same-category sibling token, and a
// retained terminal token. A deployment designates the initial group-0 token UTXO as the graph root
// and must retain control of that category's minting authority.
//
// Exact committed measurements: 206,055 script B; 207,709 challenge-score B; 206,589 serialized
// spend B across 3 transactions (50,480 / 87,705 / 68,404); 162,247,773 op; maximum input
// 5,845,574 op. The same 34 lockings accept ten measured runtime fixtures plus a separate valid
// all-position GLV stress run. Across that accepting suite, the largest transaction is 87,708 B,
// maximum input is 7,520,837 op, and maximum unlocking bytecode is 9,363 B; every transaction
// passes the BCH 2026 consensus and current standard-policy VMs with an exact 1 sat/B fee template.
// The contracts do not constrain satoshi values. The vectors also commit 27 rejecting runs and
// four isolated point/range rejection runs, including finite off-curve C and complete token flow.
//
// The current published BLS grouped-residue entry at benchmark commit 5ee4140 scores 326,251 B
// (324,210 script B, 39 inputs, 5 transactions, 256,896,867 op). This construction lowers that
// standard-relayable BLS score by 118,542 B and op-cost by 94,649,094. It does not claim the overall
// cross-curve record or a single-transaction result.
//
// The prescribed fixed benchmark key is synthetic and publishes its setup and IC scalars. These
// vectors establish complete-equation execution and BCH transaction packaging for that key; they do
// not establish circuit knowledge, secure application public-input binding, arbitrary-VK support,
// or independent-setup interoperability. Relayability is measured across the accepting fixture
// suite, not asserted as a proof-independent size ceiling for every possible witness.
//
// Byte-exact provenance:
//   source: groth16_cashscript commit 6819ad7908a66169897f3b9149e11278b261452b
//   compiler: CashScript commit 1c707c1dbf87396b30ba5e0704b1db44475ce893
//   vector sha256: ef0b7904285f635fd3294e1979b4f9e9dfc287ce6faacce43d8effecb83c17fa
//   Miller manifest sha256: 5abe1c8516ea7e945973f1baef620f5f52bfd09484b11bc4afc08896ac5000ea
//   locking graph sha256 (UTF-8 concatenated locking-hex text):
//     b5a1605f3e0c038d9c55db2de441e6f5a2a2cb8490ba7ccf28ec4caf827e1f07
// Reproduce from the source checkout:
//   VERIFIER_DIR=/path/to/zk-verifier-bench BLS_QUOTIENT_TORUS=1 pnpm vectors:grouped:residue:bls
//
// sha256 of locking bytecode, in graph order:
//   00 b9ba5d3cc057c890a61ab4e89f7be2d31af17122a474999d5c302b29cc7424f9
//   01 cb53e635abbeea2242cf2f09a7025fa45e9667437d1bc3a7c765a59c590cacaf
//   02 decf9551603cc0e6b227bab9f081c92b1ba865ba34e5d9f6307c810ec63f2226
//   03 ee463a7bf79c269ff7561913be9e7b56d00c5c6d54a4fb4d19976908370047cb
//   04 323f51b3c40a6d59f1cc57d1e2a49ff21626384cb5e3c6028d189cc298fb5a7d
//   05 d89ee40fc4b1207bcba709b662d1e415ad8d12bce5300a346022fe19d7c00e1b
//   06 64b92b5390f7064f4b3f45f7b0eeb1fd58f7fb1a2a4276f362f3fe64f5ace3a4
//   07 7823ad52b8259d0867e3ce773f32fe00899f3cd2c2c2ae5707f6fde49e0b9c20
//   08 b90d9688c3719644585c9c75dd79448a0f745a71590f5ec27fa4515304dd357a
//   09 7bd9343cdbe5e0dc0021e98c0d1413124908a005eaf9cec448c13234d2653331
//   10 16d82ca0c5358725fb042d472b5f9d5ceb2100e994ab6f6993ec9f850226937a
//   11 c88d3dc56c33ebc71846627903bccd24de9eb4c468851a567ec4ebf3834c0f1d
//   12 d3c0aeb77c253bf6164f1e3f18b48871dc8ab24d08a5c99d272fbe50de1eefae
//   13 0c75f56a10c73f496f12228ead03faeb236545e9a3d5ee458910d5725ec5c74b
//   14 7e750e8b5224372f0358d8b73b4e5d56e32bfbcea35a74f2f11a186b60a8c385
//   15 ec214cbba3a1da84d8b974df7f4e15642587ffc420e0caab0332b52bf69a626a
//   16 fee827afc0a347c25b6a2a2f802bd18182458aad6ea77e4ad9c1d9a7bebdff69
//   17 dd39ecfcbda901ba47dfc083a8524cb77bacc96c943b6da3bd981556ed1398fc
//   18 aaebe16cfcc2f960a59c5d1369fc8633304759f546b8f46a58e74a8445dc755c
//   19 e0a69de8b292cd41630096d210589d9b10f184517c99cd132ab0e89d93c8a0b1
//   20 72e54160a6fa59df27e1a078c66439305b3d7eb25614574bbbad70bed67691bb
//   21 6e7b8f61187ddaaa3d25e070630f2d3c25c2a61d38f3bf56d78984f6bc730358
//   22 5c1241feb3d9ce1dca924467b3cca221211fdcfc4398cbfce3bfe0427b4ba0b1
//   23 d30eeb578a284d6bd96bc68d570d7fa74ed7c1f577b91841654a2719474ce89c
//   24 066d4f2d7b7cf9e6e11191110cb9a8eb8960b304e86a9cba1cdd64e16cbe901c
//   25 3fab7098020ef813a96856ea0ed8fdd0661aec371a4a1bbc77331fdeb9c2189f
//   26 446f065faa7e9b2f65e6c36d9ffc6ce0b06ecb7b7d51b17fcbb8fa64c513c260
//   27 5c24a366707d902b47c66ca089c214445979ecc4d126da22e104f8e4fcea244c
//   28 3230f25a943f2a08334292a9b460e7df3af1160f5780cf81aa2b17641aac094f
//   29 396de7f887accb8ceb58aea1ea795282b536fb6cf76ba04f37516a146a3c1b7b
//   30 9227fa4109a1569ea7629e6dd59ebf01a9ab2b1afbc74892b5615e81c556c733
//   31 55a6f21f2e2ba0137781219568c1a7aa2309db552d790819fb6f3301b0c4c080
//   32 5dcf0e79df20bd36c7c3e77b03ea7102622bdba20c25d871efbd9feaf16aeafa
//   33 6e0e9873101dd063b666e2177e842e9ecb15875c53ff61aa1c51d77395608d24
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
  name: 'BCH BLS12-381 Groth16 grouped quotient-torus verifier (34 inputs, 3 current-policy standard transactions)',
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
    'Five shared-table GLV vk_x inputs feed 29 fused prepared-Miller inputs. The fixed ' +
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
    'rejections. One fixed 34-locking P2SH32 graph ' +
    'accepted ten measured runtime fixtures plus the separate all-position GLV stress run. Every ' +
    'transaction in that suite passes BCH 2026 consensus and current standard policy, remains under ' +
    '100,000 bytes, and has an exact 1 sat/B fee template; the contracts do not constrain satoshi ' +
    'values. Byte-exact vectors reproduce from groth16_cashscript ' +
    '6819ad7908a66169897f3b9149e11278b261452b and CashScript ' +
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
