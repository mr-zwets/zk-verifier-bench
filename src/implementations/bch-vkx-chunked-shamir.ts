// BCH-native Groth16 checkpoint #1 (vk_x) as a MULTI-TRANSACTION chain where
// EVERY chunk fits one standard BCH input.
//
//   vk_x = IC0 + input0*IC1 + input1*IC2   (G1 points on BN254/alt_bn128)
//
// The monolithic single-tx contract (groth16_contract/singleton/vkx.cash) is
// ~61M op-cost — about 8 BCH inputs, so it cannot validate in one input. Here
// a SINGLE 254-iteration MSB-first double-and-add (Shamir/Straus shared
// doublings) is split into byte-budgeted windows; each chunk is its own
// CashScript contract (compiled by the local cashc feat/reusable-functions
// build) that:
//   - hashes its incoming state -- the accumulator R = (rX,rY,rZ) PLUS the
//     carried PUBLIC INPUTS (input0,input1), each toPaddedBytes 40 -- and
//     require()s hash256(state) == <incoming commitment>,
//   - runs its window of double-and-add iterations. Per bit it doubles R, then
//     reads bit i of input0/input1 AT RUNTIME (bit_i(x) = (x / 2^i) % 2, since
//     CashScript's >>/& are bytes-only) and does a 2-bit Shamir select over the
//     VK-derived constants {IC1, IC2, T=IC1+IC2} to choose the addend,
//   - require()s hash256(newState) == <outgoing commitment>.
// chunk i's outgoing commitment == chunk i+1's incoming, so state is carried
// forward (the multi-step-computation.md hash-chained-state mechanism). The
// FINAL chunk folds the constant IC0, does a verified inverse-on-stack -> affine
// and require()s the result == the py_ecc-validated vk_x point (no outgoing
// commit). The public inputs execute at runtime, but every step's state commitment
// is baked for this instance, so another input pair requires regenerating the chain.
//
// PADDING: each chunk's trailing unused zeroPadding parameter is pushed first,
// followed by the incoming coords + inputs in reverse declaration order. Its length
// is tuned to the minimum that buys the measured op-cost budget; no OP_DROP is needed.
//
// Vectors are built/measured by groth16_contract/chunked/shamir/build_vectors.mjs and
// committed to src/bch/vkx-chunked-shamir-vectors.json. Standalone measurement +
// validation runner: src/bch/vkx-chunked.ts (pnpm tsx src/bch/vkx-chunked.ts).
//
// TO WIRE INTO THE BENCHMARK (coordination: do NOT edit benchmark.ts here):
//   1. add import:  import { bchVkxChunked } from '../implementations/bch-vkx-chunked.js';
//   2. add to REGISTRY array:  ..., bchVkxChunked]
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface ChunkVec {
  idx: number;
  lo: number;
  hi: number;
  final: boolean;
  locking: string;
  unlocking: string;
  invalidUnlocking: string;
}
interface ChunkedVectors {
  K: number;
  byteBudget: number;
  algorithm: string;
  numChunks: number;
  input0: number;
  input1: number;
  expected: [string, string];
  budgetPerInput: number;
  chunks: ChunkVec[];
}

const v = JSON.parse(readFileSync('src/bch/vkx-chunked-shamir-vectors.json', 'utf8')) as ChunkedVectors;

export const bchVkxChunkedShamir: Implementation = {
  id: 'bch-vkx-chunked-shamir',
  name: 'BCH vk_x chunked Shamir (Groth16 checkpoint #1, multi-tx, one-input chunks)',
  proofSystem: 'Groth16 vk_x (BCH-native)',
  field: 'BN254',
  structure: 'multi-tx',
  // per-step state commitments are baked for this instance -> instance-specific
  proofBinding: 'baked',
  source:
    'BCH-native CashScript: Shamir/Straus shared doublings in one 254-iteration ' +
    'MSB-first loop, split into two hash-chained steps. Public inputs are bit-tested ' +
    'in-script through the baked affine VK table {IC1,IC2,IC1+IC2}; each conditional ' +
    'addition uses the mixed Jacobian-affine formula. The final step folds affine IC0 ' +
    'and verifies the supplied Jacobian inverse before asserting vk_x. Multi-return EC ' +
    'functions are defined once per chunk, and padding is tuned to the measured per-input ' +
    'budget. The state commitments are instance-specific: another input pair requires ' +
    'regenerating the two-step chain. Current footprint: 14,250 script bytes and ' +
    '9,325,906 op-cost.',
  load: async () => {
    const valid: Step[] = v.chunks.map((c) => {
      const tail = c.final ? ' +fold IC0 +verified-inverse->affine, assert vk_x' : '';
      const step: Step = {
        label: `chunk ${c.idx}/${v.numChunks - 1}: Shamir iters [${c.lo},${c.hi})${tail}`,
        lockingBytecode: hexToBin(c.locking),
        unlockingBytecode: hexToBin(c.unlocking),
      };
      // Checkpoint at the final vk_x milestone.
      if (c.final) step.checkpoint = 'vk_x';
      return step;
    });

    // Explicit invalid run: the full valid chain but with the FINAL chunk's
    // unlocking replaced by its forged-zInv witness (Z*zInv != 1 -> reject).
    // This proves the verified-inverse-on-stack actually checks the supplied
    // inverse rather than trusting it.
    const finalIdx = v.chunks.length - 1;
    const invalidFinalZInv: Step[] = valid.map((s, i) =>
      i === finalIdx
        ? { ...s, unlockingBytecode: hexToBin(v.chunks[finalIdx]!.invalidUnlocking) }
        : s,
    );

    // A second invalid run: tamper a middle chunk's incoming state.
    const midIdx = Math.floor(v.chunks.length / 2);
    const invalidMidState: Step[] = valid.map((s, i) =>
      i === midIdx
        ? { ...s, unlockingBytecode: hexToBin(v.chunks[midIdx]!.invalidUnlocking) }
        : s,
    );

    return { valid, invalid: [invalidFinalZInv, invalidMidState], tamperable: true };
  },
};
