// Locking bytecode SHA-256: 030d83d4300c74b7c96fda27e0104301ca309c91a9399ed8cb77c8216a116cbe
// Fiat-Shamir PIT BCH-native BLS12-381 Groth16 verifier singleton.
//
// The bch-groth16-bls12381-intratx-fs construction (qsplit tail-22) emitted as ONE
// contract: the Fiat-Shamir commitment roots and the beta/alpha challenges are
// recomputed in-script over the witness blobs, the 32 public-VK GT-table Merkle
// authentications run inline against the baked window roots, and the 21 Miller
// blocks chain through locals instead of cross-input reads. Witness blobs
// omit the public delta Miller coefficients, which the program reinserts before
// hashing the original payloads. Statement, quotient and transcript bytes stay exact.
//
// This is the FS-family op-cost oracle on the loosened VM, the counterpart of the
// unconditional bch-groth16-bls12381-singleton-minop (149.2M op): 53,825 B locking,
// 40,107,855 worst-case op-cost across the ten-fixture corpus (38,716,391 on the
// committed fixture). One identical proof-independent contract serves all ten
// fixtures; twelve changed-field mutations per fixture are rejected.
//
// Security model: the Fp6/torus relations are verified by polynomial identity
// testing at SHA-256-derived challenges, not computed exactly — the separate
// Fiat-Shamir PIT category defined in groth16_cashscript/verifiers.md. Bound in the
// SHA-256 random-oracle model: the argument of groth16_cashscript
// chunked/bls12-381/README.md section 5 (same 24 relations, beta degree <= 23,
// alpha identity degree <= 137, one 132-coefficient quotient, same transcript
// frames; the PIC factors are flat affine 1+u*W, degree <= 5) with this
// singleton's query accounting:
//   eps_SZ + eps_binding = (23*q_beta + 160*q_alpha)/2^256 + 3*N(N-1)/2^257,
// q = adversary + verifier SHA-256 queries (q_beta + q_alpha <= q), N = N0 + q.
// Setup N0 < 2^22 (only the 32 GT window trees; the window roots are baked, so no
// batch commitments or fixed-blob hash; locking is bare as benchmarked, a P2SH32
// deployment would add 1 setup + 2 verifier hashes). Verifier q_V = 1,104 per spend
// (48 transcript, 32 GT leaves, 1,024 GT path hashes: the compiled program evaluates
// two SHA-256 per level, 32 x 16 x 2; counted by an instrumented VM; all loops and trees
// are fixed-shape), so with no adversary queries the bound is below 2^-211. A/C are on-curve
// with cofactor-equivalent encodings (no unique-G1-encoding grade); B receives the
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
  // where the claimed public inputs live (public-input binding gate, harness/gates.ts): 32-byte
  // fields packed in the statement push, located by the maintainers
  publicInputs: [
    { input: 0, push: 22, offset: 193, encoding: 'le32', name: 'n0' },
    { input: 0, push: 22, offset: 225, encoding: 'le32', name: 'n1' },
  ],
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
    'contract serves the full ten-fixture corpus. 40.11M worst-case op-cost vs the ' +
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
