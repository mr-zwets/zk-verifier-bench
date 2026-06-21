// PROOF-AGNOSTIC chunked BLS12-381 vk_x aggregation, multi-transaction.
//
//   vk_x = IC0 + in0*IC1 + in1*IC2                         (Shamir/Straus, G1)
//
// The public-input aggregation (the multi-scalar-mult over the IC points) split so
// EVERY step fits one BCH input -- on the SAME curve as nchain (BLS12-381). Like
// bch-vkx-chunked-covenant (BN254), this is a GENERIC covenant: the Jacobian
// accumulator + the public inputs live in the spent/created token's NFT commitment,
// checked by introspection, so ONE fixed set of lockings aggregates ANY public
// inputs.
//
// MAGNITUDE-INDEPENDENT (full-width, EVM-equivalent): the MSM tiles all 255
// scalar-field bit positions and the chunk windows are sized against a worst-case
// all-bits-set input, so the deployed lockings verify ANY public input < r -- not
// only small inputs. The same property as Ethereum's ecMul precompile (flat cost,
// no small-input optimization). Runtime-general confirmed via extraValidProofs =
// a distinct public-input pair against identical lockings.
//
// Vectors: groth16_contract/chunked/bls12-381/build_vectors.mjs ->
// src/bch/vkx-bls12381-chunked-covenant-vectors.json.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep {
  label: string; locking: string; unlocking: string; invalidUnlocking: string; checkpoint?: string;
  covenant?: { category: string; capability: 'none' | 'mutable' | 'minting'; inCommitment: string; outCommitment: string; outLockingBytecode: string };
}
const v = JSON.parse(readFileSync('src/bch/vkx-bls12381-chunked-covenant-vectors.json', 'utf8')) as {
  steps: RawStep[]; extraValidProofs?: RawStep[][];
};

const toStep = (s: RawStep): Step => ({
  label: s.label,
  lockingBytecode: hexToBin(s.locking),
  unlockingBytecode: hexToBin(s.unlocking),
  checkpoint: s.checkpoint,
  covenant: s.covenant && {
    category: hexToBin(s.covenant.category),
    capability: s.covenant.capability,
    inCommitment: hexToBin(s.covenant.inCommitment),
    outCommitment: hexToBin(s.covenant.outCommitment),
    outLockingBytecode: hexToBin(s.covenant.outLockingBytecode),
  },
});

export const bchVkxBls12381ChunkedCovenant: Implementation = {
  id: 'bch-vkx-bls12381-chunked-covenant',
  name: 'BCH vk_x aggregation chunked covenant, BLS12-381 (Groth16 checkpoint #1, multi-tx, runtime-general)',
  proofSystem: 'Groth16 vk_x (BCH-native)',
  field: 'BLS12-381',
  structure: 'multi-tx',
  // GENERIC covenant: accumulator + public inputs in the token NFT commitment, NOT
  // baked. Full-width (all 255 scalar positions, worst-case-sized windows) so one
  // fixed set of lockings aggregates ANY public inputs < r -- confirmed via
  // extraValidProofs = distinct inputs. (Token-safety pinning is a separate step;
  // tokenSafetyEnforced left at default.)
  proofBinding: 'runtime',
  source:
    'BCH-native CashScript: vk_x = IC0 + in0*IC1 + in1*IC2 (Shamir/Straus G1 ' +
    'double-and-add over the public-input bits) on BLS12-381, split across ' +
    'transactions so every step fits one BCH input. GENERIC covenant — the Jacobian ' +
    'accumulator and the public inputs ride in the token NFT commitment (no baked ' +
    'instance), so one fixed locking aggregates ANY public inputs. MAGNITUDE-' +
    'INDEPENDENT: tiles all 255 scalar-field positions with worst-case-sized windows ' +
    '(EVM ecMul-equivalent, full-width). The BLS12-381 counterpart of ' +
    'bch-vkx-chunked-covenant; same curve as nchain.',
  load: async () => {
    const valid: Step[] = v.steps.map(toStep);
    const extraValidProofs: Step[][] = (v.extraValidProofs ?? []).map((run) => run.map(toStep));
    const tampered = (i: number): Step[] => [{ ...valid[i]!, unlockingBytecode: hexToBin(v.steps[i]!.invalidUnlocking) }];
    const invalid: Step[][] = [tampered(0), tampered(valid.length - 1)];
    return { valid, extraValidProofs, invalid };
  },
};
