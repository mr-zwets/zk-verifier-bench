// Copy of research/opcost-timing/kernels/libauth-steady.ts with the VM chosen by gen.ts profile (worst-case-timing).
// libauth steady-state timing (no forced GC): per unit, warm up, then --batches batches of at least
// --batchtime ms of evaluation each (at least one evaluation); a batch's value is its mean eval time,
// so garbage-collection cost is amortized as it is inside one long evaluation. Reported: median of
// batch means (evalMedianNs), batch means, min/max single evaluation. Every evaluation's verdict and
// op-cost are checked against the unit.
// Why: libauth-time.ts calls gc() before each repetition; for evaluations of a few ms that makes
// libauth 2-3x slower per op-cost than the same work inside a 2 s singleton evaluation (measured on
// the bn-opt f18 kernel: 6.3 ms median with gc() per rep, 2.1-2.3 ms without).
// Usage: node --import tsx libauth-time.ts <units.json> <out.json> [--only s] [--batches 7] [--batchtime 300] [--warmtime 300]
import { readFileSync, writeFileSync } from 'node:fs';
import {
  createInstructionSetBch2026, createInstructionSetBchSpec, createVirtualMachine, decodeTransactionBch,
  decodeTransactionOutputs, hexToBin, ripemd160, secp256k1, sha1, sha256,
} from '@bitauth/libauth';
import { vmFor as profileVm } from "../worst-case-timing/gen.js";

const args = process.argv.slice(2);
const [unitsPath, outPath] = args as [string, string];
const opt = (k: string, d: string) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1]! : d; };
const ONLY = opt('--only', '');
const BATCHES = Number(opt('--batches', '7'));
const BATCH_NS = Number(opt('--batchtime', '300')) * 1e6;
const WARM_NS = Number(opt('--warmtime', '300')) * 1e6;
// worst-case-timing: modes are gen.ts profiles (today, txv5-100k, txv5-150k, +num); consensus-mode VM
const vms = new Map<string, any>();
const vmFor = (m: string) => { if (!vms.has(m)) { const num = m.endsWith("+num"); const b = num ? m.slice(0, -4) : m; const cap = b === "today" ? 10000 : b === "txv5-100k" ? 100000 : 150000; vms.set(m, profileVm({ name: m, itemCap: cap, numCap: num ? cap : 10000, unlockCap: cap }, false)); } return vms.get(m); };
const now = () => Number(process.hrtime.bigint());
const median = (xs: number[]) => { const s = [...xs].sort((a, b) => a - b); const n = s.length; return n % 2 ? s[n >> 1]! : (s[n / 2 - 1]! + s[n / 2]!) / 2; };
const results: any[] = [];
for (const u of JSON.parse(readFileSync(unitsPath, 'utf8')) as any[]) {
  if (ONLY && !`${u.name} ${u.group}`.includes(ONLY)) continue;
  const vm = vmFor(u.mode);
  const t0 = now();
  const transaction = decodeTransactionBch(hexToBin(u.txHex)) as any;
  const so = decodeTransactionOutputs(hexToBin(u.sourceOutputsHex)) as any;
  const setupNs = now() - t0;
  const sourceOutputs = so.result ?? so;
  const inputs: number[] = u.inputs ?? transaction.inputs.map((_: unknown, i: number) => i);
  const want: number[] = u.libauthOpCosts ?? u.expectOpCost;
  let opCost = 0;
  const once = () => {
    let ns = 0, ok = true, first = ''; const costs: number[] = [];
    for (const i of inputs) {
      const te = now();
      const st = vm.evaluate({ inputIndex: i, sourceOutputs, transaction });
      const s = vm.stateSuccess(st);
      ns += now() - te;
      costs.push(st.metrics.operationCost);
      if (s !== true) { ok = false; if (!first) first = `input ${i}: ${s}`; }
    }
    if (ok !== u.expectAccept) { console.error(`VERDICT MISMATCH ${u.name}: ${ok} ${first}`); process.exit(2); }
    if (u.expectAccept) want.forEach((c, k) => { if (c >= 0 && costs[k] !== c) { console.error(`OPCOST MISMATCH ${u.name} #${k}: ${costs[k]} != ${c}`); process.exit(3); } });
    opCost = costs.reduce((a, b) => a + b, 0);
    return ns;
  };
  for (let w = once(); w < WARM_NS; ) w += once();
  const means: number[] = [], evals: number[] = []; let mn = Infinity, mx = 0;
  for (let b = 0; b < BATCHES; b++) {
    let sum = 0, n = 0;
    while (sum < BATCH_NS || n === 0) { const ns = once(); sum += ns; n++; mn = Math.min(mn, ns); mx = Math.max(mx, ns); }
    means.push(sum / n); evals.push(n);
  }
  const res = { name: u.name, group: u.group, mode: u.mode, accepted: u.expectAccept, opCost, setupNs, batchMeansNs: means, batchEvals: evals, evalMedianNs: median(means), evalMinNs: mn, evalMaxNs: mx, nsPerOpCost: median(means) / opCost };
  console.error(`${u.name.padEnd(56)} ${u.mode.padEnd(8)} cost=${opCost} eval=${(res.evalMedianNs / 1e6).toFixed(3)}ms ns/cost=${res.nsPerOpCost.toFixed(3)} batches=${evals.join(',')}`);
  results.push(res);
  writeFileSync(outPath, JSON.stringify(results, null, 1));
}
