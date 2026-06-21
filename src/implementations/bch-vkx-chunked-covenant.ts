// PROOF-AGNOSTIC chunked vk_x aggregation, multi-transaction.
//
//   vk_x = IC0 + in0*IC1 + in1*IC2                         (Shamir/Straus, G1)
//
// The public-input aggregation (the multi-scalar-mult over the IC points) split so
// EVERY step fits one BCH input. Unlike bch-vkx-chunked-shamir (which bakes each
// step's state commitment -> instance-specific), this is a GENERIC covenant: the
// Jacobian accumulator + the public inputs live in the spent/created token's NFT
// commitment, checked by introspection, so ONE fixed set of lockings aggregates
// ANY public inputs. These are exactly the first 3 chunks of bch-groth16-chunked.
//
// Vectors: groth16_contract/chunked/pairing/build_vectors.mjs ->
// src/bch/vkx-chunked-covenant-vectors.json.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep {
  label: string; locking: string; unlocking: string; invalidUnlocking: string; checkpoint?: string;
  covenant?: { category: string; capability: 'none' | 'mutable' | 'minting'; inCommitment: string; outCommitment: string; outLockingBytecode: string };
}
const v = JSON.parse(readFileSync('src/bch/vkx-chunked-covenant-vectors.json', 'utf8')) as {
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

export const bchVkxChunkedCovenant: Implementation = {
  id: 'bch-vkx-chunked-covenant',
  name: 'BCH vk_x aggregation chunked covenant (Groth16 checkpoint #1, multi-tx, runtime-general)',
  proofSystem: 'Groth16 vk_x (BCH-native)',
  field: 'BN254',
  structure: 'multi-tx',
  // GENERIC covenant: accumulator + public inputs in the token NFT commitment, NOT
  // baked. One fixed set of lockings aggregates any public inputs (confirmed via
  // extraValidProofs = distinct inputs). (Token-safety pinning is a separate step;
  // tokenSafetyEnforced left at default.)
  proofBinding: 'runtime',
  source:
    'BCH-native CashScript: vk_x = IC0 + in0*IC1 + in1*IC2 (Shamir/Straus G1 ' +
    'double-and-add over the public-input bits) split across transactions so every ' +
    'step fits one BCH input. GENERIC covenant — the Jacobian accumulator and the ' +
    'public inputs ride in the token NFT commitment (no baked instance), so one ' +
    'fixed locking aggregates ANY public inputs. The runtime-general counterpart of ' +
    'bch-vkx-chunked-shamir; identical to the first 3 chunks of bch-groth16-chunked.',
  load: async () => {
    const valid: Step[] = v.steps.map(toStep);
    const extraValidProofs: Step[][] = (v.extraValidProofs ?? []).map((run) => run.map(toStep));
    const tampered = (i: number): Step[] => [{ ...valid[i]!, unlockingBytecode: hexToBin(v.steps[i]!.invalidUnlocking) }];
    const invalid: Step[][] = [tampered(0), tampered(valid.length - 1)];
    return { valid, extraValidProofs, invalid };
  },
};
