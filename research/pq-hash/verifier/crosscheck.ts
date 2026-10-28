// Independent cross-check of the pq-hash verifier (groth16_cashscript wip/pq-hash-verifier, research/pq-hash/verifier)
// with this harness's own VM wrappers (src/harness/vm.ts). Research only: nothing here is registered.
//   layout (b): one P2SH32 input, evaluated with evaluatePair on the bch-spec VM (standard, consensus) and on TXv5 as
//               written (BCH 2026 + 100,000 B items, density base 41; standard, consensus);
//   layout (a): every input of every transaction on the real BCH 2026 VM (standard, consensus).
// usage: PQ_VERIFIER_SRC=<path to groth16_cashscript>/research/pq-hash/verifier tsx research/pq-hash/verifier/crosscheck.ts
//        (default: the sibling worktree work/pq-hash/verifier)
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  createRealVm, createRealVmSpec, createRealVmTxv5, createStandardVm, createStandardVmSpec, createStandardVmTxv5,
  evaluatePair, isP2sh32Locking, MAX_STANDARD_TRANSACTION_SIZE, MAX_STANDARD_UNLOCKING_BYTECODE, realOpCostBudget, specOpCostBudget,
} from '../../../src/harness/vm.js';

const SRC = process.env.PQ_VERIFIER_SRC ?? resolve(import.meta.dirname, '../../../../verifier/research/pq-hash/verifier');
const VEC = resolve(SRC, '../prover/vectors');
const sets = ['P100', 'P128', 'U100', 'C100', 'C128'];
const vectors = sets.flatMap((s) => (s.startsWith('P') ? [0, 1, 2, 3] : [0, 1]).map((k) => `${s}-${k}.json`));

const lb = await import(resolve(SRC, 'layout-b.mjs'));
const la = await import(resolve(SRC, 'layout-a.mjs'));
const ga = await import(resolve(SRC, 'grade-a.mjs'));
const vm = {
  specStd: createStandardVmSpec(), specCons: createRealVmSpec(), txv5Std: createStandardVmTxv5(), txv5Cons: createRealVmTxv5(),
  bchStd: createStandardVm(), bchCons: createRealVm(),
};
const rows: Record<string, unknown>[] = [];
for (const file of vectors) {
  const { prm, proof } = lb.loadVector(resolve(VEC, file));
  const sp = lb.spendB(prm, Uint8Array.from(proof.subarray(0, 16)), proof);
  if (!isP2sh32Locking(sp.locking)) throw new Error('not P2SH32');
  const L = sp.unlocking.length;
  const b = Object.fromEntries((['specStd', 'specCons', 'txv5Std', 'txv5Cons'] as const).map((k) => [k, evaluatePair(vm[k] as never, sp.locking, sp.unlocking)]));
  const txB = L + 4 + 1 + 36 + (L < 65536 ? 3 : 5) + 4 + 1 + 34 + 4;
  // layout (a)
  const { txs } = ga.gradeA(prm, proof, { fast: true });
  const a = txs.map((tx: { unl: Uint8Array[]; transaction: unknown; sourceOutputs: unknown; txBytes: number }) => tx.unl.map((u: Uint8Array, i: number) => {
    const prog = { inputIndex: i, sourceOutputs: tx.sourceOutputs, transaction: tx.transaction };
    const s = vm.bchStd.evaluate(prog as never), c = vm.bchCons.evaluate(prog as never);
    const ok = (st: { error?: string; stack: Uint8Array[] }) => st.error === undefined && st.stack.length === 1 && st.stack[0]!.length === 1 && st.stack[0]![0] === 1;
    return { unlocking: u.length, std: ok(s), cons: ok(c), op: s.metrics.operationCost, budget: realOpCostBudget(u.length), iters: s.metrics.hashDigestIterations };
  }));
  const row = {
    vector: file, proofBytes: proof.length,
    b: { unlocking: L, txBytes: txB, opStd: b.specStd!.operationCost, opTxv5Std: b.txv5Std!.operationCost, iters: b.specStd!.hashDigestIterations,
      spec: [b.specStd!.accepted, b.specCons!.accepted], txv5: [b.txv5Std!.accepted, b.txv5Cons!.accepted],
      specBudgetPct: +(100 * b.specStd!.operationCost / specOpCostBudget(L)).toFixed(1), txv5BudgetPct: +(100 * b.txv5Std!.operationCost / realOpCostBudget(L)).toFixed(1),
      standardTx: txB <= MAX_STANDARD_TRANSACTION_SIZE },
    a: { transactions: txs.length, inputs: a.flat().length, totalBytes: txs.reduce((x: number, t: { txBytes: number }) => x + t.txBytes, 0),
      allAccepted: a.flat().every((x: { std: boolean; cons: boolean }) => x.std && x.cons),
      maxInputPct: Math.max(...a.flat().map((x: { op: number; budget: number }) => 100 * x.op / x.budget)).toFixed(1),
      inputsWithinCap: a.flat().every((x: { unlocking: number }) => x.unlocking <= MAX_STANDARD_UNLOCKING_BYTECODE),
      txsWithinCap: txs.every((t: { txBytes: number }) => t.txBytes <= MAX_STANDARD_TRANSACTION_SIZE) },
  };
  rows.push(row);
  console.log(`${file.padEnd(12)} b: unl ${L} tx ${txB} op ${row.b.opStd} spec ${row.b.spec} (${row.b.specBudgetPct}%) txv5 ${row.b.txv5} (${row.b.txv5BudgetPct}%) | a: ${row.a.transactions} tx ${row.a.inputs} in ${row.a.totalBytes} B accepted ${row.a.allAccepted} max ${row.a.maxInputPct}%`);
}
writeFileSync(resolve(import.meta.dirname, 'crosscheck.json'), JSON.stringify(rows, null, 1) + '\n');
void la;
