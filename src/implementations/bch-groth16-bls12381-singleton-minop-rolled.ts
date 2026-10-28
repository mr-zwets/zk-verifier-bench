// Rolled min-op singleton (Track 2 "frontier middle" design T2, BLS12-381): the reviewed
// bch-groth16-bls12381-singleton-minop with only the Miller section changed. The unrolled SSA schedule becomes ONE
// rolled CashScript loop over the 64 NAF digits of |x| (baked digit string), and the 828 baked gamma/delta line
// coefficients are replaced by on-chain gamma/delta walks from their baked affine points, through the same library
// pointDouble / pointAdd / line bodies used for B. Unchanged and emitted by the same generator code: input validation
// (coordinates < p, inputs < r), A/C on-curve checks (cofactor malleability only, as the reviewed minop), the GLV
// vk_x with gated k-decomposition and zInv witnesses, the e(alpha, beta) torus constant, the fused psi G2 endpoint
// check (with R_B Z != 0) and the quotient-torus residue terminal (lambda = p + |x|, [0:0] rejected).
// Packaged as ONE P2SH32 input (redeem pushed last, so the op-cost budget counts it): redeem 7,840 B and unlocking
// 8,590 B fit the BCH 2026 script-size caps; it needs a much looser op-cost density than bch-2026, so it is NOT
// bch-compatible as shipped (same status as the singletons).
// The spend() interface is the reviewed minop's, so its EXISTING vectors run unchanged (with the redeem appended):
// committed proof, multiproof extras, the dense worst case, invalidUnlocking, the range-invalid set and the multiproof
// and worst-case invalidUnlockings (tampered public inputs).
// Owning source: research/frontier-middle/bls12381/minop-rolled in groth16_cashscript (gen_minop_rolled.mjs ->
// groth16_minop_rolled.cash, compiled redeem sha256 d9dd1e4f...b736 = src/bch/groth16-bls12381-singleton-minop-rolled-redeem.hex).
import { readFileSync } from 'node:fs';
import { encodeDataPush, hash256, hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';
import { bls12381MinopRolledProofInputs } from './groth16-proof-inputs.js';

const redeem = hexToBin(readFileSync('src/bch/groth16-bls12381-singleton-minop-rolled-redeem.hex', 'utf8').trim());
const locking = Uint8Array.from([0xaa, 0x20, ...hash256(redeem), 0x87]); // OP_HASH256 <hash256(redeem)> OP_EQUAL
const withRedeem = (hex: string): Uint8Array => Uint8Array.from([...hexToBin(hex), ...encodeDataPush(redeem)]);

const v = JSON.parse(readFileSync('src/bch/groth16-bls12381-singleton-minop-vectors.json', 'utf8')) as {
  unlocking: string;
  invalidUnlocking: string;
  rangeInvalidUnlockings: { label: string; unlocking: string }[];
};

const mp = JSON.parse(readFileSync('src/bch/groth16-bls12381-singleton-minop-multiproof-vectors.json', 'utf8')) as {
  proofs: { unlocking: string; invalidUnlocking?: string; committed: boolean }[];
  worstCaseProof?: { unlocking: string; invalidUnlocking?: string };
};

const LABEL = 'rolled min-op BLS12-381 Groth16 verify: one rolled NAF loop, on-chain gamma/delta walks (single P2SH32 input)';
const step = (unlocking: string, label = LABEL): Step => ({
  label,
  lockingBytecode: locking,
  unlockingBytecode: withRedeem(unlocking),
  checkpoint: 'verify',
});

export const bchGroth16Bls12381SingletonMinOpRolled: Implementation = {
  id: 'bch-groth16-bls12381-singleton-minop-rolled',
  // same push indices as the reviewed minop (the P2SH32 redeem push is appended last); the unlocking
  // carries each input twice
  publicInputs: [{ input: 0, push: 4, name: 'n0' }, { input: 0, push: 12, name: 'n0' }, { input: 0, push: 2, name: 'n1' }, { input: 0, push: 11, name: 'n1' }],
  name: 'BCH Groth16 verifier singleton, BLS12-381 — rolled min-op (one NAF loop, on-chain gamma/delta walks, P2SH32)',
  vm: 'bch-2026',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  proofInputs: bls12381MinopRolledProofInputs,
  source:
    'BCH-native CashScript BLS12-381 Groth16 verifier in ONE P2SH32 input: the reviewed min-op singleton (lazy tower, ' +
    'quotient-torus residue terminal, fused psi G2 check, GLV vk_x, A/C on-curve) with its Miller section rolled into ' +
    'one loop over the NAF digits of |x| and the baked gamma/delta lines replaced by on-chain walks through the same ' +
    'library point and line bodies (research/frontier-middle/bls12381/minop-rolled). Fits the BCH 2026 script-size ' +
    'caps; over the per-input op-cost budget.',
  load: async () => {
    const valid = [step(v.unlocking)];
    const extraValidProofs = mp.proofs.filter((p) => !p.committed).map((p) => [step(p.unlocking)]);
    const worstCaseProof = mp.worstCaseProof ? [step(mp.worstCaseProof.unlocking, `${LABEL} (worst case, dense inputs)`)] : undefined;
    const invalid: Step[][] = [
      [step(v.invalidUnlocking, `${LABEL} (invalidUnlocking)`)],
      ...v.rangeInvalidUnlockings.map(({ label, unlocking }) => [step(unlocking, `${LABEL} (${label})`)]),
      // the committed multiproof entry's invalidUnlocking is the same run as invalidUnlocking above
      ...mp.proofs.flatMap((p, i) => (p.invalidUnlocking && p.invalidUnlocking !== v.invalidUnlocking ? [[step(p.invalidUnlocking, `${LABEL} (multiproof ${i} invalidUnlocking)`)]] : [])),
      ...(mp.worstCaseProof?.invalidUnlocking ? [[step(mp.worstCaseProof.invalidUnlocking, `${LABEL} (worst-case invalidUnlocking)`)]] : []),
    ];
    return { valid, extraValidProofs, worstCaseProof, invalid };
  },
};
