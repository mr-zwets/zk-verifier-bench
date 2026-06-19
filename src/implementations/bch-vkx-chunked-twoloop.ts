// BCH-native Groth16 checkpoint #1 (vk_x) -- the ORIGINAL "two-loop" baseline,
// kept alongside the tuned Shamir version so the tradeoff is visible.
//
//   vk_x = IC0 + input0*IC1 + input1*IC2   (G1 points on BN254/alt_bn128)
//
// This baseline runs TWO SEPARATE 254-iteration MSB-first double-and-add scalar
// mults (term0 = input0*IC1, term1 = input1*IC2), each split into byte-budgeted
// chunks, then folds IC0. State carried forward is the 9-coord tuple
// (accX,accY,accZ, bX,bY,bZ, rX,rY,rZ): the running accumulator, the per-term
// base, and the per-term result. EC ops are INLINED (no multi-return functions),
// and the final affine conversion uses an in-script Fermat inverse (no zInv
// witness on the stack). Unlocking is padded blindly to 10,000 bytes -- which is
// fine, since the heaviest chunk is op-cost-bound at ~7.49M and genuinely needs
// ~9.3KB of padding to buy the per-input budget anyway.
//
// 16 chunks (8 per term, the last of each folding); each chunk fits one standard
// BCH input. Vectors built/measured by
// groth16_contract/chunked/twoloop/build_vectors.mjs ->
// src/bch/vkx-chunked-twoloop-vectors.json.
//
// The two-loop vectors carry NO per-chunk invalidUnlocking, so rejection is
// proven by the harness's witness-tampering (tamperable: true).
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

const v = JSON.parse(readFileSync('src/bch/vkx-chunked-twoloop-vectors.json', 'utf8')) as ChunkedVectors;

export const bchVkxChunkedTwoloop: Implementation = {
  id: 'bch-vkx-chunked-twoloop',
  name: 'BCH vk_x chunked two-loop (Groth16 checkpoint #1, multi-tx, one-input chunks)',
  proofSystem: 'Groth16 vk_x (BCH-native)',
  field: 'BN254',
  structure: 'multi-tx',
  source:
    'BCH-native CashScript baseline: original two separate double-and-add scalar ' +
    'mults (term0 = input0*IC1, term1 = input1*IC2), each a 254-iteration MSB-first ' +
    'loop split into byte-budgeted chunks; 9-coord carried state ' +
    '(accX,accY,accZ,bX,bY,bZ,rX,rY,rZ); inlined EC (no multi-return functions); ' +
    'in-script Fermat inverse for affine conversion (no zInv witness); blind ' +
    '10,000-byte zero-padded unlocking for per-input budget -- simpler baseline.',
  load: async () => {
    const valid: Step[] = v.chunks.map((c) => {
      const tail = c.final
        ? ' +fold IC0 +Fermat-inverse->affine, assert vk_x'
        : c.fold
          ? ' +fold term into acc'
          : '';
      const step: Step = {
        label: `chunk ${c.idx}/${v.numChunks - 1}: term${c.term} d&a iters [${c.lo},${c.hi})${tail}`,
        lockingBytecode: hexToBin(c.locking),
        unlockingBytecode: hexToBin(c.unlocking),
      };
      // Checkpoint at the final vk_x milestone.
      if (c.final) step.checkpoint = 'vk_x';
      return step;
    });

    // The two-loop vectors carry no explicit invalidUnlocking. The harness's
    // default tampering flips a bit in the LARGEST data push -- here the big
    // zero-PAD, which the locking's leading OP_DROP discards before the contract
    // runs, so it would not produce a rejection. Instead we build explicit
    // invalid runs by perturbing a REAL argument push: the unlocking layout is
    //   <coord pushes, minimal> <OP_PUSHDATA2 pad>
    // so flipping a byte inside the FIRST coord push corrupts an incoming
    // coordinate -> hash256(state) mismatch -> reject. (This mirrors how the
    // Shamir impl supplies explicit invalid runs.)
    const tamperFirstCoord = (unlocking: Uint8Array): Uint8Array | undefined => {
      // Walk the push-only unlocking and corrupt the payload of the FIRST coord
      // that is a real data push, stopping before the trailing big zero-PAD
      // (which OP_DROP discards -- tampering it would not reject). OP_0 /
      // OP_1..OP_16 / OP_1NEGATE carry no payload (coords 0/1/-1) -- skip them.
      let i = 0;
      while (i < unlocking.length) {
        const op = unlocking[i]!;
        i += 1;
        let len = -1;
        if (op >= 0x01 && op <= 0x4b) len = op;
        else if (op === 0x4c) { len = unlocking[i]!; i += 1; }
        else if (op === 0x4d) { len = unlocking[i]! | (unlocking[i + 1]! << 8); i += 2; }
        else if (op === 0x4e) { len = unlocking[i]! | (unlocking[i + 1]! << 8) | (unlocking[i + 2]! << 16) | (unlocking[i + 3]! << 24); i += 4; }
        else continue;
        // Skip the trailing pad: it is by far the largest push (>= 1000 bytes).
        if (len >= 1000) { i += len; continue; }
        if (len > 0) {
          const copy = unlocking.slice();
          copy[i]! ^= 0x01; // corrupt the first real incoming coordinate
          return copy;
        }
        i += len;
      }
      return undefined;
    };

    // Two invalid runs: tamper the final chunk's incoming state, and a middle
    // chunk's incoming state. Each must be rejected.
    const finalIdx = v.chunks.length - 1;
    const midIdx = Math.floor(v.chunks.length / 2);
    const mkInvalid = (badIdx: number): Step[] | undefined => {
      const bad = tamperFirstCoord(valid[badIdx]!.unlockingBytecode);
      if (bad === undefined) return undefined;
      return valid.map((s, i) => (i === badIdx ? { ...s, unlockingBytecode: bad } : s));
    };
    const invalid = [mkInvalid(finalIdx), mkInvalid(midIdx)].filter(
      (r): r is Step[] => r !== undefined,
    );

    return { valid, invalid };
  },
};
