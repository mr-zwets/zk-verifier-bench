// Redeem bytecode SHA-256: deaa210eae267022b23d816ad24f72c3277dafc1bc9d511f2dd6611d90da09fd
// BLS12-381 Groth16 FS-PIT singleton for the proposed bch-spec VM.
// Public VK delta slopes occupy 6,528 bytes; existing exact affine G2 helpers
// reconstruct the original 13,056-byte line table before transcript hashing.
// Fixed proof, witness field, root, quotient and challenge values are unchanged.
// The 47,879-byte redeem script and 49,949-byte witness travel together in a
// 97,831-byte P2SH32 unlocking script. This targets bch-spec, not current BCH.
// Source: chunked/bls12-381/measure_fs_singleton.mjs, FS_FIXED_VK=slopes,
// FS_RESCHEDULE=on and FS_CASHC pointing to zk-language compiler efc6ab80.
// FS-PIT and exact-G2/cofactor-equivalent-G1 security claims match the FS family.
import { readFileSync } from 'node:fs';
import { encodeDataPush, encodeLockingBytecodeP2sh32, hash256, hexToBin } from '@bitauth/libauth';
import type { Implementation, Step } from '../harness/types.js';
import { bls12381FsSingletonProofInputs } from './groth16-proof-inputs.js';

const v = JSON.parse(readFileSync('src/bch/groth16-bls12381-singleton-fs-spec-vectors.json', 'utf8')) as {
  lockingOK: string;
  proofs: { fixture: string; committed: boolean; unlocking: string }[];
  worstCaseProof: { fixture: string; unlocking: string };
  invalidUnlockings: { label: string; unlocking: string }[];
};
const redeem = hexToBin(v.lockingOK);
const locking = encodeLockingBytecodeP2sh32(hash256(redeem));
const wrap = (unlocking: string): Uint8Array => {
  const witness = hexToBin(unlocking);
  const push = encodeDataPush(redeem);
  const result = new Uint8Array(witness.length + push.length);
  result.set(witness);
  result.set(push, witness.length);
  return result;
};
const step = (unlocking: string, label: string): Step => ({
  label,
  lockingBytecode: locking,
  unlockingBytecode: wrap(unlocking),
  checkpoint: 'verify',
});

export const bchGroth16Bls12381SingletonFsSpec: Implementation = {
  id: 'bch-groth16-bls12381-singleton-fs-spec',
  publicInputs: [
    { input: 0, push: 22, offset: 193, encoding: 'le32', name: 'n0' },
    { input: 0, push: 22, offset: 225, encoding: 'le32', name: 'n1' },
  ],
  name: 'BCH Groth16 BLS12-381 FS-PIT singleton, public slope table (bch-spec, P2SH32)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  proofInputs: bls12381FsSingletonProofInputs,
  vm: 'bch-spec',
  source: 'Single-script qsplit tail-22 FS-PIT verification. Fixed public VK delta slopes ' +
    'and the public G2 point reconstruct every original Miller line coefficient with ' +
    'the exact affine doubling/addition helpers. The original payload bytes are restored ' +
    'before in-script Fiat-Shamir commitment and challenge hashing. Public inputs remain ' +
    'bound by inline authenticated 32-window GT tables; quotient-torus relations use ' +
    'SHA-256-derived polynomial identity testing. The G2 psi subgroup check and residue ' +
    'terminal remain exact; G1 encodings are cofactor-equivalent rather than unique. ' +
    'One fixed proof-independent redeem script is secured by P2SH32. Requires the proposed ' +
    'bch-spec script and compute limits; not valid on current BCH.',
  load: async () => {
    const committed = v.proofs.find((proof) => proof.committed);
    if (committed === undefined) throw new Error('missing committed fs spec singleton fixture');
    return {
      valid: [step(committed.unlocking, 'FS-PIT BLS12-381 singleton (bch-spec)')],
      extraValidProofs: v.proofs.filter((proof) => !proof.committed)
        .map((proof) => [step(proof.unlocking, proof.fixture)]),
      invalid: v.invalidUnlockings.map((invalid) => [step(invalid.unlocking, invalid.label)]),
      worstCaseProof: [step(v.worstCaseProof.unlocking, v.worstCaseProof.fixture)],
    };
  },
};
