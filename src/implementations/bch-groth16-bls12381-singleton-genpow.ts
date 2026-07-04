// The SMALLEST known BLS12-381 Groth16 verifier: a single-tx contract whose entire
// locking bytecode is 3,425 bytes and is BYTE-EXACT REPRODUCIBLE from source (a
// committed search witness + a deterministic, RNG-free tail; see reproduce.sh in the
// pipeline dir). Same curve, same complete verification as
// bch-groth16-bls12381-singleton, but the final-exponentiation is done GENPOW:
// a textbook full final exponentiation f^E with E = (p^12 - 1)/r, i.e. the verify
// equation is simply
//
//   finalExpPow(millerProduct) == Fp12.ONE           (f^E == 1)
//
// where millerProduct = e(-A,B)*e(alpha,beta)*e(vk_x,gamma)*e(C,delta) is the RAW
// product of the four optimal-ate Miller loops (NO per-loop final exp). The whole
// pairing check collapses to one square-and-multiply ladder over the fixed 4,000-bit
// exponent E. This is WITNESS-FREE: the unlocking carries ONLY the proof points
// (A, B, C compressed) and the two public inputs -- there is no residue/cofactor
// witness in the unlocking (contrast the witnessed-residue chunked entries). vk_x is
// still recomputed on-chain (IC0 + in0*IC1 + in1*IC2), so it is sound: a swapped
// proof fails the f^E == 1 equation.
//
// The genpow ladder trades op-cost UP for bytes DOWN: exponentiating by the full E
// is more VM operations than a witnessed-residue check, but the program that does it
// is far smaller -- 3,425 B locking (harness score 3,715) vs the 14,468 B
// (score 14,952) of bch-groth16-bls12381-singleton on the SAME curve in THIS harness:
// a same-harness -75.2% (14,952-3,715 = -11,237). Like every singleton (and the competitor), the full
// monolithic verify does NOT fit one BCH standard input's op-cost budget -- it is
// op-waived / non-runnable-as-one-input on the real 2026 VM; the win here is purely
// on-chain byte footprint.
//
// Source + provenance: tools/singleton-artifact/pipeline-bls-compress/
//   groth16_residue.cash (the genpow verifier source),
//   bls_ederive_E.mjs    (the Lean-licensed E = (p^12-1)/r derivation spliced in),
//   gen_genpow_vectors.mjs (asserts millerProduct^E == Fp12.ONE for every valid
//                           proof before emitting -> bls-multiproof-vectors.json).
// Compiled with the cashc fork (library support), then a deterministic tail
// (replay.mjs -> stackcert cse/inline/renumber passes) run by reproduce.sh, which
// asserts the result byte-for-byte. Locking sha256(bytecode):
//   44d79298047a012b2a1d132949f55c1bbd1c803d28197b2e63366eb54614e4c1
//
// Vectors: src/bch/groth16-bls12381-singleton-genpow-vectors.json (primary valid +
// tampered) and -multiproof-vectors.json (3 further distinct proofs under the SAME
// locking, to confirm runtime-generality).
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

const v = JSON.parse(readFileSync('src/bch/groth16-bls12381-singleton-genpow-vectors.json', 'utf8')) as {
  lockingOK: string;
  unlocking: string;
  invalidUnlocking: string;
};

// Extra DISTINCT proofs minted under the SAME VK (same locking), to confirm this
// verifier is runtime-general (one program verifies many proofs). committed:true is
// the primary vector already in `v`; the rest are the extra runtime proofs.
const mp = JSON.parse(readFileSync('src/bch/groth16-bls12381-singleton-genpow-multiproof-vectors.json', 'utf8')) as {
  proofs: { publicInputs: string[]; unlocking: string; invalidUnlocking: string; committed: boolean }[];
};

export const bchGroth16Bls12381SingletonGenpow: Implementation = {
  id: 'bch-groth16-bls12381-singleton-genpow',
  name: 'BCH Groth16 verifier singleton, BLS12-381 genpow (full final-exp f^E, witness-free, 3,425 B, source-reproducible)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'BCH-native CashScript: the SMALLEST known complete Groth16 verifier on ' +
    'BLS12-381 (groth16_residue.cash, genpow). Computes vk_x = IC0 + in0*IC1 + ' +
    'in1*IC2 on-chain, forms the RAW product of four optimal-ate Miller loops ' +
    'e(-A,B)*e(alpha,beta)*e(vk_x,gamma)*e(C,delta), and require()s a textbook ' +
    'full final exponentiation finalExpPow(product) == Fp12.ONE (f^E, ' +
    'E = (p^12-1)/r, the Lean-licensed E-derivation spliced in via ' +
    'bls_ederive_E.mjs). WITNESS-FREE: the unlocking carries only the proof ' +
    'points (A,B,C compressed) + the two public inputs -- no residue/cofactor ' +
    'witness. Sound (vk_x recomputed on-chain; a swapped proof or tampered ' +
    'public input fails f^E==1). Locking 3,425 B, harness score 3,715 vs the ' +
    '14,952 of bch-groth16-bls12381-singleton on the SAME curve in THIS harness ' +
    '(same-harness -75.2%); byte-exact reproducible from source (reproduce.sh). ' +
    'The genpow ladder trades op-cost up for bytes down: like every singleton it ' +
    'does NOT fit one standard input, so it is op-waived / non-runnable-as-one-' +
    'input -- the win is purely byte size. Verified vs @noble/curves bls12-381 ' +
    '(millerProduct^E == Fp12.ONE asserted for every valid vector). No BLS G1/G2 ' +
    'subgroup check (inherited singleton posture, same as the competitor): ' +
    'off-subgroup A/C are accepted but provably harmless (torsion pairs to 1, ' +
    'statement unchanged) = proof malleability only, no false-statement forgery.',
  load: async () => {
    const valid: Step[] = [
      {
        label: 'full BLS12-381 Groth16 verify (genpow): vk_x on-chain + finalExpPow(e(-A,B)*e(a,b)*e(vk_x,g)*e(C,d))==Fp12.ONE (single tx)',
        lockingBytecode: hexToBin(v.lockingOK),
        unlockingBytecode: hexToBin(v.unlocking),
        checkpoint: 'verify',
      },
    ];
    const invalid: Step[][] = [
      [{ ...valid[0]!, unlockingBytecode: hexToBin(v.invalidUnlocking) }],
    ];
    const extraValidProofs: Step[][] = mp.proofs
      .filter((p) => !p.committed)
      .map((p) => [{ ...valid[0]!, unlockingBytecode: hexToBin(p.unlocking) }]);

    return { valid, invalid, extraValidProofs };
  },
};
