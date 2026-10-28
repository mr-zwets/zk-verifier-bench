// BLS12-381 FS-PIT, one P2SH32 input, proposed bch-spec only.
// Source 9053adee092d2616b4ebd641f942e6025ab230c6; builder SHA256 c549a0cc468ba61b025af60261920a589a49326cdaa6aefd924b52a1f353a3af.
// Generated CashScript SHA256 87802e82d85d56b69cfa8f8ffcf1d6d6221909ff988b1259c0a114eb0c4d1fe1; compiler efc6ab80d9cbbea06c3c364b8fd5e915b9da84b4.
// FS_FIXED_VK=slopes, FS_RESCHEDULE=on, FS_SHARE_PIC=1, FS_SHARE_REGULAR=1.
// Locking redeem SHA256 fe1b1fea6d0cc462c6e1e0d7c368e5490a9a6c2c9a6647ba9343691712e85d2f; 23460 redeem bytes.
// Same 49,949 witness bytes; 35 locking +73,412 unlocking +89 overhead =73,536 score.
// Prior 97,955-byte spec point retained as the slightly lower-cost alternative.
// Actual spec primary consensus/standard: 56490540/56824620.
// Maximum supplied spec consensus/standard: 57882037/58216117.
// Exact default-off source/artifact reproduction; all ten normal source exports match.
// 120 source negative controls retain every original label/witness; no new red-team authorship.
// Current-BCH native resources are not claimed; existing FS/input-validation grades remain.
import { readFileSync } from 'node:fs';
import { encodeDataPush, encodeLockingBytecodeP2sh32, hash256, hexToBin } from '@bitauth/libauth';
import type { Implementation, Step } from '../harness/types.js';
import { bls12381FsSingletonProofInputs } from './groth16-proof-inputs.js';

const v = JSON.parse(readFileSync('src/bch/groth16-bls12381-singleton-fs-spec-shared-vectors.json', 'utf8')) as {
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

export const bchGroth16Bls12381SingletonFsSpecShared: Implementation = {
  id: 'bch-groth16-bls12381-singleton-fs-spec-shared',
  publicInputs: [
    { input: 0, push: 22, offset: 193, encoding: 'le32', name: 'n0' },
    { input: 0, push: 22, offset: 225, encoding: 'le32', name: 'n1' },
  ],
  name: 'BCH Groth16 BLS12-381 FS-PIT singleton, shared PIC/stage code (bch-spec, P2SH32)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  proofInputs: bls12381FsSingletonProofInputs,
  vm: 'bch-spec',
  source: 'Complete qsplit tail-22 FS-PIT verifier for the proposed bch-spec VM. ' +
    'Public VK slopes reconstruct the exact original line table before transcript hashing. ' +
    'FS_SHARE_PIC=1 shares the 32 identical Merkle authentications; FS_SHARE_REGULAR=1 ' +
    'shares all sixteen identical regular Miller-stage bodies after an exact source-shape guard. ' +
    'The stage function explicitly carries the four point coordinates, chart evaluation/flag, ' +
    'relation power and total. The original statement, transcript leaves, beta/alpha derivations, ' +
    'quotient, point checks and terminal relation remain. All original proof/witness values ' +
    'are fixed, including every byte of the ten archived valid witnesses. The G2 psi subgroup ' +
    'check and cofactor-equivalent G1 semantics match the existing FS family; no new security ' +
    'or isolated-input-validation grade is claimed. One fixed P2SH32 redeem program accepts ' +
    'all ten supplied proofs; 120 source regression controls and generic public-input ' +
    'mutations qualify a finite corpus, not a universal soundness/resource or live-relay theorem.',
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
