// Track 2 (frontier middle) research designs, BLS12-381. NOT registered in the leaderboard (src/harness/benchmark.ts
// REGISTRY is untouched); run.ts benchmarks them with the harness's own benchmark() for measurement only.
// Sources: groth16_cashscript branch wip/frontier-middle-build-bls12381, research/frontier-middle/bls12381/.
import { readFileSync } from 'node:fs';
import { hexToBin, encodeDataPush, hash256 } from '@bitauth/libauth';
import type { Implementation, Step } from '../../../src/harness/types.js';

const here = new URL('./', import.meta.url).pathname;
interface RawStep { label: string; locking: string; unlocking: string; checkpoint?: string }
interface Vectors { steps: RawStep[]; extraValidProofs?: RawStep[][]; worstCaseProof?: RawStep[]; invalid?: RawStep[][] }

// T1: SI-GLS with an on-chain projective delta walk and an all-projective B walk (sigls-dproj), one P2SH32 input,
// bch-spec sizes; needs an op budget about 1.7x bch-spec. Vectors: sigls-dproj/export.mjs (same classes as the
// reviewed SI-GLS export minus the affine-slope class).
const dv = JSON.parse(readFileSync(here + 'sigls-dproj-vectors.json', 'utf8')) as Vectors;
const toRun = (raw: RawStep[]): Step[] => {
  const inputs = raw.map((s) => ({ lockingBytecode: hexToBin(s.locking), unlockingBytecode: hexToBin(s.unlocking), valueSatoshis: 1000n, sequenceNumber: 0 }));
  return raw.map((s, index) => ({ label: s.label, lockingBytecode: inputs[index]!.lockingBytecode, unlockingBytecode: inputs[index]!.unlockingBytecode,
    checkpoint: s.checkpoint, valueSatoshis: 1000n, sequenceNumber: 0, intraTx: { index, inputs } }));
};
export const researchBls12381SiglsDproj: Implementation = {
  id: 'research-bls12381-t1-sigls-dproj',
  publicInputs: [
    { input: 0, push: 1, name: 'n0', offset: 384, encoding: 'le32' },
    { input: 0, push: 1, name: 'n1', offset: 416, encoding: 'le32' },
  ],
  name: 'RESEARCH (not ranked) BLS12-381 SI-GLS with on-chain projective delta walk, all-projective B (bch-spec sizes, loosened op budget)',
  vm: 'bch-spec', proofSystem: 'Groth16', field: 'BLS12-381', structure: 'single-tx', proofBinding: 'runtime',
  source: 'groth16_cashscript wip/frontier-middle-build-bls12381 research/frontier-middle/bls12381/sigls-dproj',
  load: async () => ({ valid: toRun(dv.steps), extraValidProofs: (dv.extraValidProofs ?? []).map(toRun),
    worstCaseProof: dv.worstCaseProof ? toRun(dv.worstCaseProof) : undefined, invalid: (dv.invalid ?? []).map(toRun) }),
};

// T2: rolled minop. Same spend() interface as bch-groth16-bls12381-singleton-minop, so the EXISTING minop vectors
// (valid, 3 extra proofs, dense worst case, invalid + range-invalid set) run unchanged against the new program.
// WRAP = 'p2sh32' (default): the redeem is pushed last and locked by OP_HASH256 <h> OP_EQUAL, so the op budget
// counts it (the policy-relevant packaging); WRAP = 'bare': the program is the locking, like the reviewed minop.
const redeem = hexToBin(readFileSync(here + 'minop-rolled-redeem.hex', 'utf8').trim());
const mv = JSON.parse(readFileSync('src/bch/groth16-bls12381-singleton-minop-vectors.json', 'utf8')) as { unlocking: string; invalidUnlocking: string; rangeInvalidUnlockings: { label: string; unlocking: string }[] };
const mp = JSON.parse(readFileSync('src/bch/groth16-bls12381-singleton-minop-multiproof-vectors.json', 'utf8')) as { proofs: { unlocking: string; invalidUnlocking: string; committed: boolean }[]; worstCaseProof?: { unlocking: string; invalidUnlocking: string } };
export const rolledPackaging = (wrap: 'p2sh32' | 'bare') => {
  const locking = wrap === 'bare' ? redeem : Uint8Array.from([0xaa, 0x20, ...hash256(redeem), 0x87]);
  const unl = (hex: string) => (wrap === 'bare' ? hexToBin(hex) : Uint8Array.from([...hexToBin(hex), ...encodeDataPush(redeem)]));
  return { locking, unl };
};
export const researchBls12381MinopRolled = (wrap: 'p2sh32' | 'bare' = 'p2sh32'): Implementation => {
  const { locking, unl } = rolledPackaging(wrap);
  const step = (label: string, hex: string): Step => ({ label, lockingBytecode: locking, unlockingBytecode: unl(hex), checkpoint: 'verify' });
  return {
    id: `research-bls12381-t2-minop-rolled-${wrap}`,
    // same push indices as the reviewed minop (the P2SH32 redeem push is appended last)
    publicInputs: [{ input: 0, push: 4, name: 'n0' }, { input: 0, push: 12, name: 'n0' }, { input: 0, push: 2, name: 'n1' }, { input: 0, push: 11, name: 'n1' }],
    name: `RESEARCH (not ranked) BLS12-381 rolled minop: one NAF loop, on-chain gamma/delta walks (${wrap})`,
    proofSystem: 'Groth16', field: 'BLS12-381', structure: 'single-tx', proofBinding: 'runtime',
    source: 'groth16_cashscript wip/frontier-middle-build-bls12381 research/frontier-middle/bls12381/minop-rolled',
    load: async () => ({
      valid: [step('rolled minop verify (committed)', mv.unlocking)],
      extraValidProofs: mp.proofs.filter((p) => !p.committed).map((p) => [step('rolled minop extra proof', p.unlocking)]),
      worstCaseProof: mp.worstCaseProof ? [step('rolled minop worst case (dense inputs)', mp.worstCaseProof.unlocking)] : undefined,
      invalid: [[step('invalidUnlocking', mv.invalidUnlocking)], ...mv.rangeInvalidUnlockings.map((x) => [step(x.label, x.unlocking)])],
    }),
  };
};
