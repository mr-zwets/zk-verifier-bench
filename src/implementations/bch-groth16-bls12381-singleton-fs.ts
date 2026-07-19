// Fiat-Shamir PIT BCH-native BLS12-381 Groth16 verifier singleton.
//
// The bch-groth16-bls12381-intratx-fs construction (qsplit tail-22) emitted as ONE
// contract: the Fiat-Shamir commitment roots and the beta/alpha challenges are
// recomputed in-script over the witness blobs, the 32 public-VK GT-table Merkle
// authentications run inline against the baked window roots, and the 21 Miller
// blocks chain through locals instead of cross-input reads. The witness blobs are
// byte-identical to the transaction entry's statement, block payloads, and logical
// 132-coefficient quotient.
//
// This is the FS-family op-cost oracle on the loosened VM, the counterpart of the
// unconditional bch-groth16-bls12381-singleton-minop (149.2M op): 61,147 B locking,
// 60,575,949 worst-case op-cost across the ten-fixture corpus (58,690,636 on the
// committed fixture). One identical proof-independent contract serves all ten
// fixtures; twelve changed-field mutations per fixture are rejected.
//
// Security model: the Fp6/torus relations are verified by polynomial identity
// testing at SHA-256-derived challenges (union bound below 161/2^256 in the
// random-oracle model), not computed exactly — the separate Fiat-Shamir PIT
// category defined in groth16_cashscript/verifiers.md. A/C are on-curve with
// cofactor-equivalent encodings (no unique-G1-encoding grade); B receives the
// exact psi G2 subgroup check.
//
// Source: groth16_cashscript/chunked/bls12-381/measure_fs_singleton.mjs
// Vectors: groth16_cashscript/chunked/bls12-381/export_fs_singleton_vectors.mjs ->
//          src/bch/groth16-bls12381-singleton-fs-vectors.json
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

const v = JSON.parse(readFileSync('src/bch/groth16-bls12381-singleton-fs-vectors.json', 'utf8')) as {
  lockingOK: string;
  proofs: {
    fixture: string;
    publicInputs: string[];
    committed: boolean;
    unlocking: string;
  }[];
  worstCaseProof: { fixture: string; unlocking: string };
  invalidUnlockings: { label: string; unlocking: string }[];
};

export const bchGroth16Bls12381SingletonFs: Implementation = {
  id: 'bch-groth16-bls12381-singleton-fs',
  name: 'BCH Groth16 verifier singleton, BLS12-381 — Fiat-Shamir PIT (single-script qsplit tail-22)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'BCH-native CashScript: the complete qsplit tail-22 BLS12-381 Groth16 verification in ' +
    'ONE contract. The script rebuilds the Fiat-Shamir commitment and quotient Merkle roots ' +
    'over its own witness arguments with OP_SHA256 and requires the beta/alpha challenges ' +
    'to equal the tagged hashes of those roots; the Fp6/torus Miller relations are checked ' +
    'by polynomial identity testing at those challenges with one prover-supplied ' +
    '132-coefficient quotient (Fiat-Shamir PIT security model — see ' +
    'groth16_cashscript/verifiers.md). The 32-window public-VK GT table is Merkle-' +
    'authenticated inline against baked window roots with leaf indices bound to the ' +
    'committed public-input bytes; the G2 walk, slope equations, psi subgroup check, and ' +
    'the lambda = p+|x| residue terminal stay exact. One identical proof-independent ' +
    'contract serves the full ten-fixture corpus. 60.58M worst-case op-cost vs the ' +
    'unconditional minop oracle’s 149.2M. Still over the 10,000 B / per-input op limits.',
  load: async () => {
    const committed = v.proofs.find((proof) => proof.committed);
    if (committed === undefined) throw new Error('missing committed fs singleton fixture');
    const base: Step = {
      label: 'FS singleton BLS12-381 Groth16 verify: in-script Fiat-Shamir + PIT relations + inline GT-table auth (single tx)',
      lockingBytecode: hexToBin(v.lockingOK),
      unlockingBytecode: hexToBin(committed.unlocking),
      checkpoint: 'verify',
    };
    const valid: Step[] = [base];
    const extraValidProofs: Step[][] = v.proofs
      .filter((proof) => !proof.committed)
      .map((proof) => [{
        ...base,
        label: `${base.label} (${proof.fixture})`,
        unlockingBytecode: hexToBin(proof.unlocking),
      }]);
    const invalid: Step[][] = v.invalidUnlockings.map(({ label, unlocking }) => [{
      ...base,
      label: `${base.label} (${label})`,
      unlockingBytecode: hexToBin(unlocking),
    }]);
    const worstCaseProof: Step[] = [{
      ...base,
      label: `${base.label} (worst case: ${v.worstCaseProof.fixture})`,
      unlockingBytecode: hexToBin(v.worstCaseProof.unlocking),
    }];
    return { valid, invalid, extraValidProofs, worstCaseProof };
  },
};
