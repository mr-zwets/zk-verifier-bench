// OP-OPTIMIZED BCH-native BLS12-381 Groth16 verifier singleton.
//
// Same complete verification as bch-groth16-bls12381-singleton (same curve as the
// nChain reference), with every op-lowering optimization from the BN254 min-op
// variant ported to BLS12-381:
//   - LAZY field tower for the Miller loop (deferred reductions);
//   - witnessed-residue final exponentiation (ePrint 2024/640 adapted to BLS12-381:
//     lambda = p + |x|, tail fF*w == frob(c,1); the witness scaling group is mu_27A,
//     A = (|x|+1)/3, verified on-chain via ((w^|x|)*w)^9 == 1);
//   - ONE batched c^-|x|-fused Miller on the UNCONJUGATED boundary: only (-A,B) runs
//     on-chain G2 arithmetic; e(alpha,beta) baked; (vk_x,gamma)/(C,delta) lines baked;
//   - psi(B) == [-x]B G2 subgroup check (64-bit walk, witness-free);
//   - phi(P) == [-x^2]P G1 subgroup checks for A and C (BLS12-381 G1 cofactor != 1,
//     unlike BN254 — two sparse |x|-walks per point; sound because z^2+z+1 at -x^2
//     equals r, which no cofactor prime divides);
//   - GLV vk_x: 4-scalar 128-bit Straus over a baked subset-sum table (gated k-decomp
//     + zInv witnesses).
//
// Source: groth16_contract/singleton/bls12-381/groth16_minop.cash (generated)
// Vectors: groth16_contract/singleton/bls12-381/build_vectors_groth16_minop.mjs ->
//          src/bch/groth16-bls12381-singleton-minop-vectors.json
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

const v = JSON.parse(readFileSync('src/bch/groth16-bls12381-singleton-minop-vectors.json', 'utf8')) as {
  lockingOK: string;
  unlocking: string;
  invalidUnlocking: string;
};

const mp = JSON.parse(readFileSync('src/bch/groth16-bls12381-singleton-minop-multiproof-vectors.json', 'utf8')) as {
  proofs: { publicInputs: string[]; unlocking: string; invalidUnlocking: string; committed: boolean }[];
  worstCaseProof?: { unlocking: string };
};

export const bchGroth16Bls12381SingletonMinOp: Implementation = {
  id: 'bch-groth16-bls12381-singleton-minop',
  name: 'BCH Groth16 verifier singleton, BLS12-381 — op-optimized (lazy tower + residue + psi/phi checks + GLV)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'BCH-native CashScript: the COMPLETE BLS12-381 Groth16 verifier in ONE contract, ' +
    'op-optimized — same curve as nchain. Lazy field tower for the Miller loop; witnessed-' +
    'residue final exponentiation (ePrint 2024/640 adapted to BLS12-381: lambda = p+|x|, ' +
    'w gated to mu_27A on-chain) replacing the hard part; e(alpha,beta) baked and the ' +
    '(vk_x,gamma)/(C,delta) line coefficients baked (only (-A,B) runs on-chain G2 math); ' +
    'psi 64-bit G2 subgroup check; phi(P)==[-x^2]P G1 subgroup checks for A and C (the G1 ' +
    'cofactor is nontrivial on BLS12-381); GLV 4-scalar vk_x. All extra inputs (c,cInv,w; ' +
    'GLV k-decomposition + zInv) are prover-supplied and gated on-chain. Sound (vk_x ' +
    'recomputed on-chain; all proof points curve- and subgroup-checked). Verified vs ' +
    '@noble/curves bls12-381. Single-tx like bch-groth16-bls12381-singleton but ~78% less ' +
    'op-cost. Still over the 10,000 B / per-input op limits.',
  load: async () => {
    const valid: Step[] = [
      {
        label: 'op-optimized BLS12-381 Groth16 verify: lazy fused Miller + residue + psi/phi + GLV (single tx)',
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
    // worst-case run: dense (near-r) proof through the SAME locking; GLV vk_x is proof-dependent, so
    // this is the apples-to-apples op-cost vs the chunked BLS entries.
    const worstCaseProof: Step[] | undefined = mp.worstCaseProof
      ? [{ ...valid[0]!, unlockingBytecode: hexToBin(mp.worstCaseProof.unlocking) }]
      : undefined;
    return { valid, invalid, extraValidProofs, worstCaseProof };
  },
};
