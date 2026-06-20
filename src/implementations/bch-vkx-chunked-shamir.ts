// BCH-native Groth16 checkpoint #1 (vk_x) as a MULTI-TRANSACTION chain where
// EVERY chunk fits one standard BCH input.
//
//   vk_x = IC0 + input0*IC1 + input1*IC2   (G1 points on BN254/alt_bn128)
//
// The monolithic single-tx contract (groth16_contract/singleton/vkx.cash) is
// ~76M op-cost — about 10 BCH inputs, so it cannot validate in one input. Here
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
// commit). Because only VK constants are baked (never the proof's inputs), the
// verifier is proof-AGNOSTIC: the same chunk bytecode verifies any input pair.
//
// PADDING (so each chunk buys a full input's op-cost budget): a P2SH unlocking
// must be PUSH-ONLY, so each chunk's unlocking is the incoming coords + inputs
// (reverse declaration order, minimal pushes) followed by ONE big zero-PUSH that
// pads the unlocking to ~10,000 bytes; the locking has a single OP_DROP prepended
// to consume that padding push before the contract runs. Real-VM budget per
// input = (41 + 10000) * 800 = 8,032,800; every chunk's op-cost is under it.
//
// Vectors are built/measured by groth16_contract/chunked/build_vectors.mjs and
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
    'BCH-native CashScript: Shamir/Straus + multi-return EC functions + tuned padding. ' +
    'Shamir/Straus shared ' +
    'doublings (single 254-iter MSB-first loop), RUNTIME public inputs (input0/' +
    'input1 carried in the hash-chained state and bit-tested in-script via a 2-bit ' +
    'Shamir select over VK consts {IC1,IC2,T}), verified-inverse-on-stack, ' +
    'tuned per-chunk padding for per-input budget. The EC ops ' +
    'jacDouble/jacAdd/selectPoint are MULTI-VALUE-RETURN reusable functions ' +
    '(returns (int,int,int) -> OP_DEFINE/OP_INVOKE) defined ONCE per chunk, and ' +
    'each chunk LOOPS over its bit-range (body compiled once) so per-chunk bytecode ' +
    'is ~1.5KB and op-cost (not size) binds -> 3 chunks, ~23KB total, ~14.3M op-cost',
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
