// Measure the Track 2 BLS12-381 research designs with the harness's benchmark() (correctness on the loosened VM,
// invalid-vector rejection, public-input binding gate, layout gate, real-VM verdict, score) plus a loosened-budget
// check: each valid / extra / worst-case run on the real target VM with operationCostBudgetPerByte = 800 k at the
// smallest k (2 decimals) that admits it, and E_k. Not part of the leaderboard; nothing on main is touched.
//   npx tsx research/frontier-middle/bls12381/run.ts [out.json]     (from the bench root)
import { writeFileSync } from 'node:fs';
import { createVirtualMachine, createInstructionSetBch2026, createInstructionSetBchSpec, ConsensusBch2025, ripemd160, secp256k1, sha1, sha256, decodeAuthenticationInstructions } from '@bitauth/libauth';
import { benchmark } from '../../../src/harness/benchmark.js';
import { evaluatePair, consensusBch2026 } from '../../../src/harness/vm.js';
import type { Implementation, Step } from '../../../src/harness/types.js';
import { researchBls12381SiglsDproj, researchBls12381MinopRolled } from './impls.js';

const specConsensus = { ...consensusBch2026, densityControlBaseLength: 10_000, maximumBytecodeLength: 100_000, maximumStackItemLength: 100_000, maximumStandardUnlockingBytecodeLength: 100_000, maximumVmNumberByteLength: 100_000 };
const vmK = (spec: boolean, k: number, standard: boolean) => {
  const base = spec ? specConsensus : consensusBch2026; const consensus = { ...base, operationCostBudgetPerByte: Math.floor(800 * k) };
  return createVirtualMachine((spec ? createInstructionSetBchSpec : createInstructionSetBch2026)(standard, { consensus, ripemd160, secp256k1, sha1, sha256 } as never));
};
// BCHN charges each executed OP_DEFINE body as pushed bytes (libauth: 100); all OP_DEFINEs of both designs sit in a
// straight-line prologue of the executed program (the P2SH redeem / the bare locking), so each runs exactly once.
const defBodyBytes = (program: Uint8Array) => { const ins = decodeAuthenticationInstructions(program); let b = 0; ins.forEach((x, i) => { if (x.opcode === 0x89) b += (ins[i - 2] as { data?: Uint8Array }).data?.length ?? 0; }); return b; };
const programOf = (s: Step) => (s.lockingBytecode.length === 35 ? decodeAuthenticationInstructions(s.unlockingBytecode).at(-1) as { data: Uint8Array } : { data: s.lockingBytecode }).data;
const TODAY: Record<number, number> = { 1: 32.5, 2: 26.5, 5: 26.5, 10: 26.5, 25: 26.5, 50: 24.8, 100: 12.4 }; // best reviewed BLS E_k (KB), model-output.md
const E = (bytes: number, op: number, inputs: number, k: number) => Math.max(bytes, op / (800 * k) - 41 * inputs) / 1000;

const out: Record<string, unknown> = {};
const designs: [Implementation, boolean, string][] = [
  [researchBls12381SiglsDproj, true, 'bls12381-t1-sigls-dproj'],
  [researchBls12381MinopRolled('p2sh32'), false, 'bls12381-t2-minop-rolled'],
  [researchBls12381MinopRolled('bare'), false, 'bls12381-t2-minop-rolled (bare locking, as the reviewed minop)'],
];
for (const [impl, spec, name] of designs) {
  const sc = await impl.load(); const r = benchmark(impl, sc);
  const runs: [string, Step][] = [['valid', sc.valid[0]!], ...(sc.extraValidProofs ?? []).map((x, i) => [`extra#${i + 1}`, x[0]!] as [string, Step]), ...(sc.worstCaseProof ? [['worstCase', sc.worstCaseProof[0]!] as [string, Step]] : [])];
  const def = defBodyBytes(programOf(sc.valid[0]!));
  const rows = runs.map(([label, s]) => {
    const op = evaluatePair(vmK(spec, 1e6, false), s.lockingBytecode, s.unlockingBytecode, undefined, s.intraTx).operationCost;
    const base = (spec ? 10_000 : 41) + s.unlockingBytecode.length; const kMin = Math.ceil((100 * (op + def)) / (base * 800)) / 100; // BCHN-adjusted
    const acc = (k: number, std: boolean) => evaluatePair(vmK(spec, k, std), s.lockingBytecode, s.unlockingBytecode, undefined, s.intraTx).accepted;
    return { label, unlockingBytes: s.unlockingBytecode.length, opCost: op, bchnAdjusted: op + def, kMinBchnAdjusted: kMin,
      acceptedAtKmin: { consensus: acc(kMin, false), standard: acc(kMin, true) }, rejectedAtKmin_0_99: !acc(kMin * 0.99 - 0.001, false) || kMin <= 1, stockVm: acc(1, false) };
  });
  const c = rows[0]!, w = rows.find((x) => x.label === 'worstCase') ?? c;
  const score = r.totalBytes + r.totalTxOverheadBytes; // results.json score (scripts + tx overhead)
  const Ek = Object.fromEntries([1, 2, 5, 10, 25, 50, 100].map((k) => [k, { committed: +E(score, c.bchnAdjusted, 1, k).toFixed(2), worst: +E(score, w.bchnAdjusted, 1, k).toFixed(2), today: TODAY[k], change: `${(100 * (E(score, c.bchnAdjusted, 1, k) / TODAY[k]! - 1)).toFixed(0)}%`, changeWorst: `${(100 * (E(score, w.bchnAdjusted, 1, k) / TODAY[k]! - 1)).toFixed(0)}%` }]));
  out[name] = { id: impl.id, harness: { pass: r.pass, validPassed: r.validPassed, invalid: `${r.invalidRejected}/${r.invalidTotal}`, proofs: `${r.proofsPassed}/${r.proofsTested}`, runtimeGeneral: r.runtimeGeneral,
    worstCase: r.worstCase, publicInputs: r.publicInputs, layout: r.layout, redTeam: r.redTeam, inputValidation: r.inputValidation, score, totalBytes: r.totalBytes, txOverhead: r.totalTxOverheadBytes,
    lockingBytes: r.steps[0]?.lockingBytes, unlockingBytes: r.steps[0]?.unlockingBytes, opCost: r.totalOperationCost, fitsStandardBudget: r.fitsStandardBudget, bchCompatible: r.bchCompatible, bchIncompatibleReason: r.bchIncompatibleReason,
    securePackaging: r.securePackaging, packagingType: r.packagingType },
    opDefineBodyBytes: def, runs: rows, Ek };
  console.log(name, JSON.stringify(out[name], null, 1).slice(0, 4000));
}
if (process.argv[2]) writeFileSync(process.argv[2], JSON.stringify(out, null, 1) + '\n');
