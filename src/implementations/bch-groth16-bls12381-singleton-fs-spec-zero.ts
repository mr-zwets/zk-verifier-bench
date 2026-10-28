// BLS12-381 FS-PIT, one P2SH32 input, proposed bch-spec only.
// Source 5dbdbfd2ef51d3511d2386e588ffe55696931fdb; builder SHA256 3fceea5887b630b5a3a854cf8bb68ee1bb041e991b870f2fc17960e66be928e9; codec SHA256 60f9c1c85e3d8a808ca178f4a633e00b8dc341179dfff82144f25269e660a9d6.
// Redeem SHA256 560b4882ec7a4fcd618b4c48f8b1a42b4ea6e84e43e61ab702d857abc287649c; 23,784 B, 324 more than shared-code variant.
// FS_FIXED_VK=slopes, FS_RESCHEDULE=on, FS_SHARE_PIC=1, FS_SHARE_REGULAR=1, FS_ZERO_PIC_FACTORS=1.
// Primary:41,309 witness +23,784 redeem +3 push =65,096 unlocking B;
// 35 locking +65,096 unlocking +87 overhead =65,218 score (-8,318 B).
// Primary real-spec consensus/standard:57,009,659/57,344,379; budget60,076,800.
// Supplied max real-spec consensus/standard:58,430,796/58,765,516; minimum margin2,336,338.
// Dense witnesses omit no factors:73,860 B; retain old73,536 and97,955 alternatives.
// Restored pre-transcript bytes and all cryptographic values fixed; wire encoding changes.
// Native decoder kernel:1,522 C/STD contexts (384accept,1,138reject); whole spec qualification separate.
// Ten normal exports,120legacy control origins +4codec controls,9public mutations, CLI/type pass.
// No new security/input-validation/red-team grade, native or universal resource/soundness claim.
import { readFileSync } from 'node:fs';
import { encodeDataPush, encodeLockingBytecodeP2sh32, hash256, hexToBin } from '@bitauth/libauth';
import type { Implementation, Step } from '../harness/types.js';
import { bls12381FsSingletonProofInputs } from './groth16-proof-inputs.js';

const v = JSON.parse(readFileSync('src/bch/groth16-bls12381-singleton-fs-spec-zero-vectors.json', 'utf8')) as {
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

export const bchGroth16Bls12381SingletonFsSpecZero: Implementation = {
  id: 'bch-groth16-bls12381-singleton-fs-spec-zero',
  publicInputs: [
    { input: 0, push: 22, offset: 193, encoding: 'le32', name: 'n0' },
    { input: 0, push: 22, offset: 225, encoding: 'le32', name: 'n1' },
  ],
  name: 'BCH Groth16 BLS12-381 FS-PIT singleton, zero PIC factors (bch-spec, P2SH32)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  proofInputs: bls12381FsSingletonProofInputs,
  vm: 'bch-spec',
  source: 'Same fixed BLS12-381 FS-PIT statement and VK as the shared-code singleton. ' +
    'FS_ZERO_PIC_FACTORS=1 omits the six all-zero Fp6 limbs for zero public-digit pairs. ' +
    'Every 512-byte Merkle path remains. A source-owned decoder reconstructs the exact ' +
    '288 zero bytes before public-VK table insertion, original transcript hashing and all ' +
    'field checks. Both scalar bytes are read from the same committed statement; fixed ' +
    'window/prefix arguments and exact wire consumption bind each record. The original ' +
    'proof, root, quotient, challenge and auxiliary values are preserved. Savings depend ' +
    'on the public inputs: primary score 65,218 bytes, dense supplied fixtures 73,860. ' +
    'The 73,536-byte shared entry remains available at lower cost and fewer dense bytes. ' +
    'One proof-independent P2SH32 redeem program accepts all ten archived proofs; all ' +
    '120 legacy invalid origins and four codec controls reject. Existing FS-PIT, exact-G2 ' +
    'and cofactor-equivalent-G1 claims and isolated-input-validation grades are unchanged. ' +
    'This is a proposed-bch-spec entry; no current-native admission, universal resource ' +
    'or cryptographic theorem, or maintainer red-team authorship is claimed.',
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
