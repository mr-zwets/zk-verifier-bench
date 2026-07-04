// The SMALLEST source-REPRODUCIBLE BN254 Groth16 verifier: a single-tx contract whose
// entire locking bytecode is 4,292 bytes. Same curve and the SAME complete EIP-197
// verification as bch-groth16-singleton, but the final-exponentiation is done GENPOW:
// a textbook full final exponentiation f^E with E = (p^12 - 1)/r derived IN-SOURCE
// (the Lean-licensed E-derivation, ederive-deriv.mjs), i.e. the verify equation is
//
//   finalExpPow(millerProduct) == Fp12.ONE            (f^E == 1)
//
// where millerProduct = e(-A,B)*e(alpha,beta)*e(vk_x,gamma)*e(C,delta) is the RAW
// product of the four optimal-ate Miller loops (NO per-loop final exp). The whole
// pairing check collapses to one square-and-multiply ladder over the fixed exponent E.
// The byte win comes from a Karatsuba->schoolbook lever: below the Fp2 mul crossover
// the schoolbook multiplier is fewer bytes, and it is Lean-proven equivalent to the
// Karatsuba path (fp2Sqr/fp12Sqr/sqrFp === mul-on-the-diagonal, all inputs, any modulus).
//
// FULL EIP-197 SOUNDNESS -- the crown carries the complete BN254 verifier, NOT a
// subgroup-skipping shortcut. It performs explicit on-curve checks on A, C (G1) and B (G2),
// AND the explicit EIP-197 G2 SUBGROUP MEMBERSHIP check [6x^2]B == psi(B) (the
// endomorphism/Frobenius test). Non-malleability rests on two independent facts, stated
// precisely: (a) BN254 G1 has cofactor 1 -- the G1 order over F_p equals r, so NO
// off-subgroup G1 points exist at all and A, C cannot be shifted (a property of the curve,
// unlike BLS12-381 whose G1 cofactor h1 > 1); (b) the G2 subgroup check is present and
// confirmed to REJECT an off-subgroup B in our tests -- belt-and-suspenders EIP-197
// conformance, NOT a claim of catching a forgery nothing else catches: for the single-B
// Groth16 witness the pairing over F_p^2 already rejects an off-subgroup B, so we do NOT
// claim a cofactor-shifted B that a subgroup-skipping verifier would accept. vk_x is
// recomputed on-chain (IC0 + in0*IC1 + in1*IC2), so a swapped proof or tampered public
// input fails f^E == 1.
//
// Like every singleton, the full monolithic verify does NOT fit one BCH standard input's
// op-cost budget -- it is op-cost-WAIVED / non-runnable-as-one-input on the real 2026 VM,
// and at 4,292 B it is >201 B non-standard. The win is purely on-chain BYTE footprint:
// 4,292 B vs the 8,756-score mr-zwets deployed opcode-optimized singleton and 21,661 B (baseline cashc).
//
// REPRODUCIBILITY (the headline): unlike the prior 4,156 record this crown is byte-exact
// reproducible FROM SOURCE. cashc(schoolbook genpow-src) -> baseline 11,964 B; replay.mjs
// + the shipped witness nodeorders.json -> the 5,248 B replay output; a deterministic tail
// (stackcert cse/inline/renumber passes) -> the 4,292 B crown, sha256 61c451d0...8494c83.
// Packaged as ONE command: tools/singleton-artifact/pipeline-sub6k/reproduce.sh asserts the
// byte count at each step and the final sha256 (the stackcert optimizer is a separate repo,
// located via $SC). gate.mjs 3-check --lineage OVERALL PASS (CHECK 1 runs in STRUCTURAL mode
// -- block-DAG not established; assurance via CHECK 2 26/26 + CHECK 3). See
// PR-bn254-singleton-genpow.md for the exact commands.
//
// Source + provenance (verifier.cash master 871671d):
//   tools/singleton-artifact/genpow-src/  (groth16.cash + lib: Miller, Fp/Fp2/Fp6/Fp12,
//                                          FinalExpPow, G1, Htower -- the genpow verifier)
//   tools/singleton-artifact/ederive-deriv.mjs   (Lean-licensed E=(p^12-1)/r derivation)
//   tools/singleton-artifact/pipeline-sub6k/{replay.mjs,nodeorders.json}  (witness replay)
//   tools/singleton-artifact/gate.mjs            (self-verifying 3-check reproducibility gate)
// Shipped crown: pipeline-sub6k/singleton-4651-locking4292-searchmain.hex
//   locking sha256 (4,292 B): 61c451d0bf8835e6ab850a02c325775d3769dbff92b87ba2d564c8f1f8494c83
//
// Vectors: src/bch/groth16-singleton-genpow-vectors.json (committed valid + tampered) and
// -multiproof-vectors.json (4 distinct proofs under the SAME crown, runtime-generality).
// These are the gate.mjs DEFAULT_VECTORS the crown actually accepts (verified accept-valid
// 4/4, reject-invalid 4/4 on the loosened BCH-2026 VM, crown-vs-baseline differential 4/4).
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

const v = JSON.parse(readFileSync('src/bch/groth16-singleton-genpow-vectors.json', 'utf8')) as {
  lockingOK: string;
  unlocking: string;
  invalidUnlocking: string;
};

// Extra DISTINCT proofs minted under the SAME VK (same locking), to confirm this verifier
// is runtime-general (one program verifies many proofs). committed:true is the primary
// vector already in `v`; the rest are the extra runtime proofs.
const mp = JSON.parse(readFileSync('src/bch/groth16-singleton-genpow-multiproof-vectors.json', 'utf8')) as {
  lockingOK: string;
  proofs: { publicInputs: string[]; unlocking: string; invalidUnlocking: string; committed: boolean }[];
};

export const bchGroth16SingletonGenpow: Implementation = {
  id: 'bch-groth16-singleton-genpow',
  name: 'BCH Groth16 verifier singleton, BN254 genpow (full final-exp f^E, full EIP-197 incl. G2 subgroup, source-reproducible 4,292 B)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'BCH-native CashScript: the SMALLEST source-REPRODUCIBLE complete Groth16 verifier ' +
    'on BN254 (genpow-src/groth16.cash, genpow). Computes vk_x = IC0 + in0*IC1 + in1*IC2 ' +
    'on-chain, forms the RAW product of four optimal-ate Miller loops ' +
    'e(-A,B)*e(alpha,beta)*e(vk_x,gamma)*e(C,delta), and require()s a textbook full final ' +
    'exponentiation finalExpPow(product) == Fp12.ONE (f^E, E = (p^12-1)/r derived in-source ' +
    'via the Lean-licensed ederive-deriv.mjs). Byte win from a Karatsuba->schoolbook lever, ' +
    'Lean-proven equivalent (sqr === mul-on-the-diagonal). FULL EIP-197 soundness: explicit ' +
    'on-curve checks on A, C (G1) and B (G2) AND the G2 SUBGROUP membership check ' +
    '[6x^2]B == psi(B) -- so the verifier is NON-MALLEABLE, a STRICTLY STRONGER posture ' +
    'than the BLS singleton and than subgroup-skipping verifiers. Sound (vk_x recomputed ' +
    'on-chain; a swapped proof or tampered input fails f^E==1). Locking 4,292 B (sha256 ' +
    '61c451d0...8494c83) vs the 8,756-score mr-zwets opcode-optimized singleton and 21,661 B (baseline ' +
    'cashc). Byte-exact reproducible from source: cashc -> 11,964 baseline; replay.mjs + ' +
    'nodeorders.json -> optimized_search.hex; deterministic cse/inline/renumber tail -> ' +
    '4,292; gate.mjs 3-check --lineage OVERALL PASS. Like every singleton it does NOT fit ' +
    'one standard input, so it is op-cost-waived / non-runnable-as-one-input and >201 B ' +
    'non-standard -- the win is purely byte size. Verified accept-valid 4/4, reject-invalid ' +
    '4/4, crown-vs-baseline differential 4/4 on the loosened BCH-2026 VM.',
  load: async () => {
    const valid: Step[] = [
      {
        label: 'full BN254 Groth16 verify (genpow, full EIP-197 incl. G2 subgroup): vk_x on-chain + finalExpPow(e(-A,B)*e(a,b)*e(vk_x,g)*e(C,d))==Fp12.ONE (single tx)',
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
