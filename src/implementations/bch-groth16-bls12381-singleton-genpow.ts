// BLS12-381 Groth16 genpow singleton, recovered symbolic source and compact IDs.
//
// Full final exponentiation f^E == Fp12.ONE, E = (p^12-1)/r, over the raw
// four-pair Miller product. vk_x is recomputed on-chain. The unlocking carries
// compressed proof coordinates and two public inputs; no residue witness or
// Fiat-Shamir polynomial-identity test is introduced.
//
// Locking: 3,415 bytes; official score: 3,705 bytes; committed operations:
// 20,711,247,449. Relative to the exact 3,425-byte/3,715-score leader: -10 bytes
// and -2,356,540 operations, with the same 67,211,610 instruction count.
// Four supplied proofs accept and the official changed-input mutation rejects.
// No dense fixture or isolated input-validation fixtures are supplied.
// Current-BCH compatibility and standardness remain false: this is a singleton
// byte-footprint result evaluated with the official resource ceilings lifted.
//
// The recovered source declares all 51 function bodies and the main program;
// it builds the original locking byte-for-byte. Compact output only reassigns
// fieldPrime 1->0, fp6Add 17->1 and fp6Mul 18->-1, rebuilding every immediate
// call. All 311 calls are static and the arithmetic/stack instructions are
// unchanged. Function-table keys are raw bytes; empty and 0x81 keys are valid.
//
// Recovered program source:
//   singleton/bls12-381/leader-recovered/program.mjs
// Candidate builder/exporter: compact.mjs / export.mjs in the same directory.
// Source revision: da85bde1a3918e653e545e3d588f8e3c7a58cd0f
// This is recovered symbolic Script source. The original CashScript compiler
// revision, search witness, replay and stackcert pipeline remain unavailable.
// The supplied witness/public-input bytes are unchanged from the original
// official genpow vectors. The source exporter records their hashes and the
// recovered-source hashes in both vector files.
//
// The original entry omits G1/G2 subgroup checks and declares cofactor-equivalent
// proof semantics. This identifier-only change preserves that posture; it does
// not establish a new malformed-point theorem or an input-validation grade.
//
// Baseline locking SHA256:
//   44d79298047a012b2a1d132949f55c1bbd1c803d28197b2e63366eb54614e4c1
// Candidate locking SHA256:
//   b982a3db459ec4bbb0a9742b54c2181919881af4d3af24b456e5b5825ba85558
// groth16-bls12381-singleton-genpow-vectors.json SHA256:
//   6bb11665750ee24b383ba4a92eb0d07c82c633b9dd3903e7f4ca25bc3f1196f0
// groth16-bls12381-singleton-genpow-multiproof-vectors.json SHA256:
//   e12fe62c2a4d421b7c5b3433e5be3b21e333070e52939e08c0a6b2becab8912e
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
  name: 'BCH Groth16 verifier singleton, BLS12-381 genpow (full final-exp, 3,415 B, recovered symbolic source)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'BLS12-381 Groth16 genpow singleton with on-chain vk_x, the raw four-pair Miller ' +
    'product, and full final exponentiation f^((p^12-1)/r) == Fp12.ONE. The unlocking ' +
    'contains compressed proof coordinates and two public inputs; no residue witness ' +
    'or Fiat-Shamir PIT is added. Recovered symbolic Script source reproduces the ' +
    'original 3,425-byte leader exactly; three function-ID reassignments reduce it to ' +
    '3,415 bytes (official score 3,705) and 20,711,247,449 committed operations. ' +
    'All four supplied proof witnesses are unchanged. The original CashScript ' +
    'compiler/search-witness/replay pipeline remains unavailable. Current BCH and ' +
    'standardness limits are exceeded. The original no-G1/G2-subgroup-check and ' +
    'cofactor-equivalent proof posture is preserved; no new malformed-point theorem ' +
    'or isolated input-validation grade is claimed.',
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
