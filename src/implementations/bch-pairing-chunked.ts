// BCH-native Groth16 PAIRING, multi-transaction — the BCH-compatible pairing:
// every step fits ONE BCH input (op-cost <= 8,032,800, scripts <= 10,000 B).
//
// The pre-final-exponentiation Miller boundary
//   e(-A,B) * e(alpha,beta) * e(vk_x,gamma) * e(C,delta)            (an Fp12)
// computed as 4 single-pair optimal-ate Miller chains + a combine step, split
// across 133 transactions. Each step carries its state (f in Fp12 + the running
// G2 point R, or the 4 f_i for the combine) committed as hash256(40-byte LE
// limbs) and re-supplied in the witness, verified on entry and exit — the same
// stateful-covenant pattern as the chunked vk_x. Per chunk the Miller steps are
// UNROLLED with the NAF digit baked, so the body compiles once and op-cost binds
// (not size): chunks are ~4.7 KB, <=6.2M op-cost. Verified against the singleton
// oracle / @noble/curves: the combine's boundary == the golden millerHex.
//
// This is the multi-tx counterpart of bch-pairing-singleton (~1.21B op-cost,
// ~151 inputs, BCH-INcompatible): here every one of the 133 steps validates on
// the real BCH 2026 VM. Reaches checkpoint "miller-boundary"; the final
// exponentiation (verdict) is added on top of this boundary.
//
// Vectors: groth16_contract/chunked/pairing/build_vectors.mjs ->
// src/bch/pairing-chunked-vectors.json.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

const v = JSON.parse(readFileSync('src/bch/pairing-chunked-vectors.json', 'utf8')) as {
  steps: { label: string; locking: string; unlocking: string; invalidUnlocking: string; checkpoint?: string }[];
};

export const bchPairingChunked: Implementation = {
  id: 'bch-pairing-chunked',
  name: 'BCH Groth16 pairing chunked (Miller boundary, multi-tx, BCH-compatible)',
  proofSystem: 'Groth16 pairing (BCH-native)',
  field: 'BN254',
  structure: 'multi-tx',
  source:
    'BCH-native CashScript: the BN254 Groth16 Miller boundary e(-A,B)*e(alpha,beta)*' +
    'e(vk_x,gamma)*e(C,delta) split across transactions so EVERY step fits one ' +
    'BCH input (op-cost <=8,032,800, scripts <=10,000 B). 4 single-pair optimal-ate ' +
    'Miller chains (f in Fp12 + running G2 point R, hash256-committed, ~5 KB/chunk, ' +
    'NAF steps unrolled with the digit baked so op-cost binds not size) + a combine ' +
    'step (boundary = f0*f1*f2*f3). Verified vs @noble/curves: combine boundary == ' +
    'golden millerHex. Multi-tx counterpart of bch-pairing-singleton (which needs ' +
    '~151 inputs); here every step is BCH-compatible. Reaches the miller-boundary ' +
    'checkpoint (the full verdict is bch-groth16-chunked).',
  load: async () => {
    const valid: Step[] = v.steps.map((s) => ({
      label: s.label,
      lockingBytecode: hexToBin(s.locking),
      unlockingBytecode: hexToBin(s.unlocking),
      checkpoint: s.checkpoint,
    }));
    // invalid runs: a tampered witness (wrong committed incoming state) must be
    // rejected -- test it at the first Miller step and at the combine.
    const tampered = (i: number): Step[] => [{ ...valid[i]!, unlockingBytecode: hexToBin(v.steps[i]!.invalidUnlocking) }];
    const invalid: Step[][] = [tampered(0), tampered(valid.length - 1)];
    return { valid, invalid };
  },
};
