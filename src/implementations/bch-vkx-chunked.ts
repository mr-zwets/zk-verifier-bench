// BCH-native Groth16 checkpoint #1 (vk_x) as a MULTI-TRANSACTION chain where
// EVERY chunk fits one standard BCH input.
//
//   vk_x = IC0 + input0*IC1 + input1*IC2   (G1 points on BN254/alt_bn128)
//
// The monolithic single-tx contract (groth16_contract/singleton/vkx.cash) is
// ~76M op-cost — about 10 BCH inputs, so it cannot validate in one input. Here
// the two 254-iteration double-and-add scalar multiplies are split into K=32-
// iteration windows; each chunk is its own CashScript contract (compiled by the
// local cashc feat/reusable-functions build) that:
//   - hashes its 9 incoming Jacobian coords (acc, base, R: each toPaddedBytes 40)
//     and require()s hash256(state) == <incoming commitment>,
//   - runs its K double-and-add iterations (Fp ops are OP_DEFINE/OP_INVOKE),
//   - require()s hash256(newState) == <outgoing commitment>.
// chunk i's outgoing commitment == chunk i+1's incoming, so state is carried
// forward (the multi-step-computation.md hash-chained-state mechanism). The
// FINAL chunk does the single Fermat modular inverse -> affine and require()s
// the result == the py_ecc-validated expected vk_x point (no outgoing commit).
//
// PADDING (so each chunk buys a full input's op-cost budget): a P2SH unlocking
// must be PUSH-ONLY, so each chunk's unlocking is the 9 incoming coords (reverse
// declaration order, minimal pushes) followed by ONE big zero-PUSH that pads the
// unlocking to ~10,000 bytes; the locking has a single OP_DROP prepended to
// consume that padding push before the contract runs. Real-VM budget per input =
// (41 + 10000) * 800 = 8,032,800; every chunk's measured op-cost is under it.
//
// Vectors are built/measured by groth16_contract/chunked/build_vectors.mjs and
// committed to src/bch/vkx-chunked-vectors.json. Standalone measurement +
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
  term: number;
  lo: number;
  hi: number;
  fold: boolean;
  final: boolean;
  locking: string;
  unlocking: string;
}
interface ChunkedVectors {
  K: number;
  numChunks: number;
  input0: number;
  input1: number;
  expected: [string, string];
  budgetPerInput: number;
  chunks: ChunkVec[];
}

const v = JSON.parse(readFileSync('src/bch/vkx-chunked-vectors.json', 'utf8')) as ChunkedVectors;

export const bchVkxChunked: Implementation = {
  id: 'bch-vkx-chunked',
  name: 'BCH vk_x chunked (Groth16 checkpoint #1, multi-tx, one-input chunks)',
  proofSystem: 'Groth16 vk_x (BCH-native)',
  field: 'BN254',
  structure: 'multi-tx',
  source:
    'BCH-native CashScript (cashc feat/reusable-functions); hash-chained state, ' +
    'K=32-iteration chunks, zero-padded unlocking for per-input budget',
  load: async () => {
    const valid: Step[] = v.chunks.map((c) => {
      const term = c.term === 0 ? 'input0*IC1' : 'input1*IC2';
      const tail = c.final ? ' +fold+inverse->affine, assert vk_x' : c.fold ? ' +fold acc+=R' : '';
      const step: Step = {
        label: `chunk ${c.idx}/${v.numChunks - 1}: ${term} iters [${c.lo},${c.hi})${tail}`,
        lockingBytecode: hexToBin(c.locking),
        unlockingBytecode: hexToBin(c.unlocking),
      };
      // Checkpoint at each term boundary (acc += R fold) and the final vk_x.
      if (c.final) step.checkpoint = 'vk_x';
      else if (c.fold) step.checkpoint = `term${c.term}-fold`;
      return step;
    });
    return { valid, tamperable: true };
  },
};
