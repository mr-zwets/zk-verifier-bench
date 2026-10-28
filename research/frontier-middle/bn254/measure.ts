// Track 2 (frontier middle), BN254 research designs: measurement glue. NOT a leaderboard entry: the
// Implementation objects below are never added to REGISTRY; they only feed the harness's own benchmark()
// (the same gates and op-cost accounting the registered entries get: loosened BCH 2026 VM for op-cost,
// real VMs for compatibility, the existing invalid-vector classes, the public-input gate).
//   pnpm exec tsx research/frontier-middle/bn254/measure.ts [design-id ...]  -> prints JSON + writes results.json here
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { decodeAuthenticationInstructions, hexToBin } from '@bitauth/libauth';
import { benchmark } from '../../../src/harness/benchmark.js';
import type { Implementation, Step } from '../../../src/harness/types.js';
import { createLoosenedVm, createRealVm, createRealVmSpec, createStandardVm, createStandardVmSpec, evaluatePair } from '../../../src/harness/vm.js';

const DIR = 'research/frontier-middle/bn254';
interface RawStep { label: string; locking: string; unlocking: string; checkpoint?: string }
interface Vectors { steps: RawStep[]; extraValidProofs?: RawStep[][]; worstCaseProof?: RawStep[]; invalid?: RawStep[][] }
const toRun = (raw: RawStep[]): Step[] => {
  const inputs = raw.map((s) => ({ lockingBytecode: hexToBin(s.locking), unlockingBytecode: hexToBin(s.unlocking), valueSatoshis: 1000n, sequenceNumber: 0 }));
  return raw.map((s, index) => ({ label: s.label, lockingBytecode: inputs[index]!.lockingBytecode, unlockingBytecode: inputs[index]!.unlockingBytecode,
    checkpoint: s.checkpoint, valueSatoshis: 1000n, sequenceNumber: 0, intraTx: { index, inputs } }));
};
const DESIGNS: Record<string, { file: string; vm: 'bch-spec' | 'bch-2026'; name: string; source: string; publicInputs?: Implementation['publicInputs'] }> = {
  'research-bn254-t1-sigls-dproj': {
    file: 't1-sigls-dproj-vectors.json', vm: 'bch-spec', name: 'RESEARCH T1 SI-GLS + on-chain projective delta walk (BN254, one input)',
    source: 'groth16_cashscript wip/frontier-middle-build-bn254 research/frontier-middle/bn254/sigls-dproj (research artifact, not ranked)',
    publicInputs: [{ input: 0, push: 1, name: 'n0', offset: 256, encoding: 'le32' }, { input: 0, push: 1, name: 'n1', offset: 288, encoding: 'le32' }],
  },
  'research-bn254-t1-sigls-dproj-inline': {
    file: 't1-sigls-dproj-inline-vectors.json', vm: 'bch-spec', name: 'RESEARCH T1 variant: inline delta doubling + bound BADD/DADD',
    source: 'same, DPROJ_SHARED=0',
    publicInputs: [{ input: 0, push: 1, name: 'n0', offset: 256, encoding: 'le32' }, { input: 0, push: 1, name: 'n1', offset: 288, encoding: 'le32' }],
  },
  'research-bn254-t2-rolled-residue': {
    file: 't2-rolled-residue-vectors.json', vm: 'bch-2026', name: 'RESEARCH T2 rolled residue singleton (BN254, one input, exact class identity)',
    source: 'groth16_cashscript wip/frontier-middle-build-bn254 research/frontier-middle/bn254/rolled-residue (research artifact, not ranked)',
    publicInputs: [{ input: 0, push: 0, name: 'n0', offset: 256, encoding: 'le32' }, { input: 0, push: 0, name: 'n1', offset: 288, encoding: 'le32' }],
  },
};
// executed OP_DEFINE body bytes of one unlocking (P2SH32: the last push is the redeem; every OP_DEFINE runs once)
const defineBodyBytes = (unlocking: Uint8Array): number => {
  const pushes = decodeAuthenticationInstructions(unlocking); const redeem = (pushes.at(-1) as { data?: Uint8Array }).data!;
  const ins = decodeAuthenticationInstructions(redeem) as { opcode: number; data?: Uint8Array }[];
  let n = 0; ins.forEach((x, i) => { if (x.opcode === 0x89) { const body = ins[i - 2]; if (!body?.data) throw new Error('OP_DEFINE without a pushed body'); n += body.data.length; } });
  return n;
};
const ids = process.argv.slice(2).length ? process.argv.slice(2) : Object.keys(DESIGNS);
const out: Record<string, unknown> = existsSync(`${DIR}/results.json`) ? JSON.parse(readFileSync(`${DIR}/results.json`, 'utf8')) : {};
const K = [1, 2, 5, 10, 25, 50, 100];
for (const id of ids) {
  const d = DESIGNS[id]!; if (!existsSync(`${DIR}/${d.file}`)) { console.error('skip (no vectors)', id); continue; }
  const v = JSON.parse(readFileSync(`${DIR}/${d.file}`, 'utf8')) as Vectors;
  const impl: Implementation = { id, name: d.name, vm: d.vm, proofSystem: 'Groth16', field: 'BN254', structure: 'single-tx', proofBinding: 'runtime', source: d.source,
    publicInputs: d.publicInputs,
    load: async () => ({ valid: toRun(v.steps), extraValidProofs: (v.extraValidProofs ?? []).map(toRun), worstCaseProof: v.worstCaseProof ? toRun(v.worstCaseProof) : undefined, invalid: (v.invalid ?? []).map(toRun) }) } as Implementation;
  const scen = await impl.load();
  const r = benchmark(impl, scen);
  // per proof: op-cost (loosened BCH 2026 VM = the harness's op-cost VM), bch-spec strict verdicts, k_min
  const loose = createLoosenedVm(), spec = d.vm === 'bch-spec' ? createRealVmSpec() : createRealVm(), specStd = d.vm === 'bch-spec' ? createStandardVmSpec() : createStandardVm();
  const proofs = [['fixture0', scen.valid], ...(scen.extraValidProofs ?? []).map((x, i) => [`extra${i + 1}`, x]), ...(scen.worstCaseProof ? [['worstCase', scen.worstCaseProof]] : [])] as [string, Step[]][];
  const perProof = proofs.map(([label, run]) => {
    const s = run[0]!; const L = evaluatePair(loose, s.lockingBytecode, s.unlockingBytecode, undefined, s.intraTx);
    const S = evaluatePair(spec, s.lockingBytecode, s.unlockingBytecode, undefined, s.intraTx), SS = evaluatePair(specStd, s.lockingBytecode, s.unlockingBytecode, undefined, s.intraTx);
    const len = s.unlockingBytecode.length, defs = defineBodyBytes(s.unlockingBytecode);
    return { label, accepted: L.accepted, opCost: L.operationCost, opCostBchn: L.operationCost + defs, defineBodyBytes: defs, unlockingBytes: len,
      strictVm: { vm: d.vm, consensus: S.accepted, standard: SS.accepted, error: S.error },
      kMinBch2026: (L.operationCost + defs) / ((41 + len) * 800), kMinBchSpec: (L.operationCost + defs) / ((10000 + len) * 800) };
  });
  const invalidRejected = (scen.invalid ?? []).filter((run) => !evaluatePair(loose, run[0]!.lockingBytecode, run[0]!.unlockingBytecode, undefined, run[0]!.intraTx).accepted).length;
  const bytes = r.totalBytes + r.totalTxOverheadBytes; const inputs = 1;
  const op0 = perProof[0]!.opCost, opB = perProof[0]!.opCostBchn, opWorst = Math.max(...perProof.map((x) => x.opCostBchn));
  const E = (op: number) => Object.fromEntries(K.map((k) => [k, Math.max(bytes, Math.ceil(op / (800 * k) - 41 * inputs))]));
  const res = { id, bytes, scriptBytes: r.totalBytes, txOverhead: r.totalTxOverheadBytes, inputs, opCost: op0, opCostBchnAdjusted: opB, worstProofOpCostBchn: opWorst,
    harness: { validPassed: r.validPassed, proofsPassed: `${r.proofsPassed}/${r.proofsTested}`, invalidRejected: `${r.invalidRejected}/${r.invalidTotal}`, invalidRejectedLoose: `${invalidRejected}/${(scen.invalid ?? []).length}`,
      publicInputs: r.publicInputs, pass: r.pass, fitsStandardBudget: r.fitsStandardBudget, inputsForHeaviestStep: r.inputsForHeaviestStep },
    perProof, Ek_fixture0: E(opB), Ek_worstProof: E(opWorst),
    kMin: { bch2026: Math.max(...perProof.map((x) => x.kMinBch2026)), bchSpec: Math.max(...perProof.map((x) => x.kMinBchSpec)) } };
  out[id] = res; console.log(JSON.stringify(res, null, 1));
}
writeFileSync(`${DIR}/results.json`, JSON.stringify(out, null, 1) + '\n');
