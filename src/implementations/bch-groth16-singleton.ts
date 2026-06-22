// BCH-native COMPLETE Groth16 verifier as a single-tx contract -- the full
// verification, not just a piece: vk_x computed on-chain from the public inputs,
// then the pairing check.
//
//   vk_x = IC0 + in0*IC1 + in1*IC2                                  (on-chain, G1)
//   require( e(-A,B) * e(alpha,beta) * e(vk_x,gamma) * e(C,delta) == 1 )
//
// The ENTIRE verifier in ONE CashScript contract (Groth16Verify,
// groth16_contract/singleton/pairing/groth16.cash): the BN254 field tower
// (Fp2/Fp6/Fp12), the G1 scalar-mult for vk_x (Jacobian double-and-add + a final
// Fermat inverse), four optimal-ate Miller loops, their product, and the final
// exponentiation. The verifying key (alpha,beta,gamma,delta,IC) is hardcoded for
// the committed instance; the proof (A,B,C) and public inputs (in0,in1) are
// supplied at RUNTIME. A is negated in-script. The contract require()s the
// product == Fp12 ONE -- the verification verdict. Sound: vk_x is recomputed
// on-chain, so a forged vk_x cannot satisfy the equation. Every field/curve op is
// a reusable function (OP_DEFINE/OP_INVOKE). Verified against @noble/curves bn254.
//
// Same curve (BN254) as scrypt-bn256, so a direct apples-to-apples size compare:
// this is ~543x smaller bytecode. But at ~1.26B op-cost (~157 standard BCH
// inputs) and a ~21.7 KB contract it does NOT fit one input -- on the real BCH
// 2026 VM it fails the 10,000-byte bytecode limit (and op-cost density). That is
// the honest result that motivates the chunked (multi-tx) verifier.
//
// Vectors: groth16_contract/singleton/pairing/build_vectors_groth16.mjs ->
// src/bch/groth16-singleton-vectors.json.
import { readFileSync } from 'node:fs';
import { hexToBin, binToHex, bigIntToVmNumber, vmNumberToBigInt } from '@bitauth/libauth';
import { bn254 } from '@noble/curves/bn254.js';

import type { Implementation, Step } from '../harness/types.js';

// spend() decl order: Ax,Ay,Bxa,Bxb,Bya,Byb,Cx,Cy,in0,in1 (pushed reversed, Ax on top).
const pushInt = (n: bigint): number[] => {
  const d = bigIntToVmNumber(n);
  if (d.length === 0) return [0x00];
  if (d.length === 1 && d[0]! >= 1 && d[0]! <= 16) return [0x50 + d[0]!];
  if (d.length === 1 && d[0]! === 0x81) return [0x4f];
  if (d.length <= 75) return [d.length, ...d];
  if (d.length <= 255) return [0x4c, d.length, ...d];
  return [0x4d, d.length & 0xff, (d.length >> 8) & 0xff, ...d];
};
const parseUnlocking = (hex: string): bigint[] => {
  const b = hexToBin(hex); const vals: bigint[] = []; let i = 0;
  while (i < b.length) {
    const op = b[i++]!;
    if (op === 0x00) vals.push(0n);
    else if (op === 0x4f) vals.push(-1n);
    else if (op >= 0x51 && op <= 0x60) vals.push(BigInt(op - 0x50));
    else { let len: number; if (op <= 75) len = op; else if (op === 0x4c) len = b[i++]!; else { len = b[i]! | (b[i + 1]! << 8); i += 2; } vals.push(vmNumberToBigInt(b.slice(i, i + len), { requireMinimalEncoding: false }) as bigint); i += len; }
  }
  return vals.reverse(); // -> decl order
};
const encodeUnlocking = (args: bigint[]): Uint8Array => Uint8Array.from([...args].reverse().flatMap((a) => pushInt(a)));

const v = JSON.parse(readFileSync('src/bch/groth16-singleton-vectors.json', 'utf8')) as {
  lockingOK: string;
  unlocking: string;
  invalidUnlocking: string;
};

// Extra DISTINCT proofs minted under the SAME VK (same locking), so the benchmark
// can confirm this verifier is runtime-general rather than a single proof baked in.
// Built by groth16_contract/singleton/bn254/gen_multiproof.mjs. proofs[0] is the
// committed instance (== v above); proofs[1..] are the additional ones.
const mp = JSON.parse(readFileSync('src/bch/groth16-singleton-multiproof-vectors.json', 'utf8')) as {
  lockingOK: string;
  proofs: { publicInputs: string[]; unlocking: string; invalidUnlocking: string; committed: boolean }[];
};

export const bchGroth16Singleton: Implementation = {
  id: 'bch-groth16-singleton',
  name: 'BCH Groth16 verifier singleton (vk_x on-chain + full pairing, single-tx)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'BCH-native CashScript: the COMPLETE Groth16 verifier in ONE contract ' +
    '(Groth16Verify, singleton/bn254/groth16.cash). Computes vk_x = IC0 + in0*IC1 ' +
    '+ in1*IC2 on-chain (G1 Jacobian double-and-add + Fermat inverse), then the full ' +
    'BN254 pairing e(-A,B)*e(alpha,beta)*e(vk_x,gamma)*e(C,delta) and require()s == 1. ' +
    'VK hardcoded; proof (A,B,C) + public inputs (in0,in1) at RUNTIME; A negated ' +
    'in-script. Sound (vk_x recomputed on-chain). Verified vs @noble/curves bn254. ' +
    'Same curve as scrypt-bn256 -> ~543x smaller bytecode, but ~1.26B op-cost ' +
    '(~157 BCH inputs); ~21.7 KB does NOT fit one input -- motivates the chunked ' +
    'multi-tx verifier.',
  load: async () => {
    const valid: Step[] = [
      {
        label: 'full Groth16 verify: vk_x on-chain + e(-A,B)*e(a,b)*e(vk_x,g)*e(C,d)==1 (single tx)',
        lockingBytecode: hexToBin(v.lockingOK),
        unlockingBytecode: hexToBin(v.unlocking),
        checkpoint: 'verify',
      },
    ];
    // invalid run: tampered public input -> different vk_x -> product != 1 -> reject
    const invalid: Step[][] = [
      [{ ...valid[0]!, unlockingBytecode: hexToBin(v.invalidUnlocking) }],
    ];
    // extra DISTINCT proofs (proofs[1..]) against the SAME locking -- a
    // runtime-general verifier must accept every one of them.
    const extraValidProofs: Step[][] = mp.proofs
      .filter((p) => !p.committed)
      .map((p) => [{ ...valid[0]!, unlockingBytecode: hexToBin(p.unlocking) }]);

    // adversarial INPUT runs: structurally-invalid points the EIP-197 validation must
    // reject (decl order Ax,Ay,Bxa,Bxb,Bya,Byb,Cx,Cy,in0,in1). Built verifier-side.
    const args = parseUnlocking(v.unlocking);
    const withArgs = (mut: bigint[]): Step[] => [{ ...valid[0]!, unlockingBytecode: encodeUnlocking(mut) }];
    const offCurveA = args.slice(); offCurveA[1] = offCurveA[1]! + 1n;   // A off G1
    const offCurveB = args.slice(); offCurveB[4] = offCurveB[4]! + 1n;   // B off G2
    // an on-curve but OFF-SUBGROUP G2 point (the subgroup check's reason to exist)
    const Fp2 = bn254.fields.Fp2;
    const b2 = Fp2.div(Fp2.fromBigTuple([3n, 0n]), Fp2.fromBigTuple([9n, 1n]));
    let offSub = args.slice();
    for (let i = 1n; i < 400n; i++) {
      const x = Fp2.fromBigTuple([i, 0n]); const rhs = Fp2.add(Fp2.mul(Fp2.sqr(x), x), b2);
      let y; try { y = Fp2.sqrt(rhs); } catch { continue; }
      if (!Fp2.eql(Fp2.sqr(y), rhs)) continue;
      try { bn254.G2.Point.fromAffine({ x, y }).assertValidity(); continue; } catch { /* on-curve, not torsion-free */ }
      offSub = args.slice(); offSub[2] = x.c0; offSub[3] = x.c1; offSub[4] = y.c0; offSub[5] = y.c1; break;
    }
    const invalidInputs: Step[][] = [withArgs(offCurveA), withArgs(offCurveB), withArgs(offSub)];
    return { valid, invalid, extraValidProofs, invalidInputs };
  },
};
