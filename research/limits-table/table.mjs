#!/usr/bin/env node
// Limits sensitivity table: prints (1) the measured Track 10 G2 layout a' grid from raw/g2-*.json and (2) the
// MODELLED cells (layout arithmetic from measured per-input sizes and op-costs). Reads only committed result files.
// usage: node table.mjs [G16_BUILD_JSON] [B2_JSON]   (defaults: the copies in raw/)
import {readFileSync, readdirSync} from 'node:fs';

const here = new URL('.', import.meta.url).pathname;
const G16 = process.argv[2] ?? `${here}raw/src-bn-native-sound-build.json`;   // copy of groth16_cashscript db1860d chunked/bn254/bn-native-sound/build.json
const B2 = process.argv[3] ?? `${here}raw/src-g2-grade-b2.json`;   // copy of groth16_cashscript db1860d research/pq-wrap/onchain/results/g2/grade-b2.json
const J = (p) => JSON.parse(readFileSync(p, 'utf8'));
const budget = (unl) => (41 + unl) * 800;
const fmt = (n) => n.toLocaleString('en-US');

// ---- (1) measured G2 a' grid ----
console.log('## Track 10 G2, layout a\' (grade-lim.mjs, libauth 3.1.0-next.8 + BCHN DEFINE adjustment), vector g2-0\n');
console.log('| layout | unlocking limit | tx limit | txs | inputs | bytes | per-tx bytes | q/QRY | worst input % | reason the plan search stopped at the next-fewer txs |');
console.log('|---|--:|--:|--:|--:|--:|---|--:|--:|---|');
const files = readdirSync(`${here}raw`).filter((f) => /^g2-(opt|base)-u\d+-t\d+\.json$/.test(f));
const key = (f) => { const [, o, u, t] = f.match(/^g2-(opt|base)-u(\d+)-t(\d+)/); return [o === 'opt' ? 0 : 1, +u, +t]; };
files.sort((a, b) => { const x = key(a), y = key(b); return x[0] - y[0] || x[1] - y[1] || x[2] - y[2]; });
for (const f of files) {
  const [o, u, t] = key(f); const r = J(`${here}raw/${f}`).rows[0];
  const lay = o ? 'baseline' : 'opt sib,lad,state,cap=3';
  if (!r.plan && r.plan !== undefined) { console.log(`| ${lay} | ${fmt(u)} | ${t >= 1e6 ? '1,000,000 (consensus only)' : fmt(t)} | no plan | | | | | | |`); continue; }
  const T = r.txs, per = r.txsDetail.map((x) => x.bytes);
  // why not T-1: the last tried entry with T-1 transactions
  const prev = r.tried.filter((x) => x.T === T - 1 && x.per === r.per).pop();
  const why = T === 1 ? '—' : prev?.invalid ? prev.invalid : prev?.txBytes ? `tx bytes ${prev.txBytes.map(fmt).join(' + ')} > ${fmt(t)}` : prev?.maxUnlocking ? `input ${fmt(prev.maxUnlocking)} B > ${fmt(u)}` : 'n/a';
  console.log(`| ${lay} | ${fmt(u)} | ${t >= 1e6 ? '1,000,000 (consensus only)' : fmt(t)} | ${T} | ${r.inputs} | ${fmt(r.totalBytes)} | ${per.map(fmt).join(' + ')} | ${r.per} | ${r.maxPct} | ${why} |`);
}

// ---- (2) modelled cells ----
console.log('\n## Modelled cells\n');
// (a) Groth16 BN254 sound-native as ONE input (not built): unlocking ~ sum of the 3 inputs' unlockings (the two 224 B
// hand-overs and the extra push headers would go, so this over-counts); op-cost = the bench worst case (3 inputs,
// libauth) plus the OP_DEFINE body bytes once (codeBytes, an upper bound on the define bodies of one input).
{
  const b = J(G16); const unl = b.fixture0.unlockingTotal; const op = 20_804_423; const def = b.codeBytes;
  console.log(`- Groth16 sound-native as 1 input: unlocking <= ${fmt(unl)} B (needs unlocking limit >= ${fmt(unl)}); op-cost <= ${fmt(op)} + ${fmt(def)} DEFINE = ${fmt(op + def)} vs budget ${fmt(budget(unl))} -> ${(100 * (op + def) / budget(unl)).toFixed(1)}% (worst-case proof; results.json benchmarks.worstCase.opCost). Tx stays 1; only the input count changes (3 -> 1).`);
}
// (b) G2 layout b3 (three inputs, b2's loader pattern with a second loader input; not built), from the measured b2 split
// QA = 19 / 24 of Q = 43. Bytes: per-query bytes from input 1 (queries only), input 0's fixed part = lib + PT/statement.
{
  const r = J(B2).rows[0]; const [i0, i1] = r.inputs; const Q = 43, QA = r.QA;
  const perQ = i1.unlockingBytes / (Q - QA); const fixed0 = i0.unlockingBytes - QA * perQ;
  for (const U of [100_000]) {   // at 150,000 the two-input b2 is measured (grade-b2.json, r150 regime)
    const q0 = Math.floor((U - fixed0) / perQ); const rest = Q - q0; const q1 = Math.ceil(rest / 2), q2 = rest - q1;
    const u0 = Math.round(fixed0 + q0 * perQ), u1 = Math.round(q1 * perQ), u2 = Math.round(q2 * perQ);
    // tx bytes: b2's tx + one more input (outpoint 36 + sequence 4 + length varint 3 + push headers ~ 3 per query blob, bounded by 64)
    const tx = r.txBytes + 36 + 4 + 3 + 64;
    // op-cost bound: an input with fewer queries than b2's input of the same role costs no more than it (same code path,
    // fewer query loops); input 0 <= b2 input 0, inputs 1 and 2 <= b2 input 1.
    const ok = [[u0, i0.opBchnAdjusted], [u1, i1.opBchnAdjusted], [u2, i1.opBchnAdjusted]].map(([u, op]) => `${fmt(u)} B, op <= ${fmt(op)} (${(100 * op / budget(u)).toFixed(1)}%)`);
    console.log(`- G2 layout b3 at unlocking limit ${fmt(U)}: queries ${q0}/${q1}/${q2}; inputs ${ok.join('; ')}; stack item = input 0 unlocking ${fmt(u0)} <= ${fmt(U)}: ${u0 <= U}; tx about ${fmt(tx)} B -> 1 tx iff tx limit >= about ${fmt(tx)}.`);
  }
  console.log(`  (b2 measured: lib ${fmt(r.libBytes)} B, per-query ${perQ.toFixed(0)} B, input-0 fixed part ${fmt(Math.round(fixed0))} B, proof ${fmt(r.proofBytes)} B.)`);
  // (c) lower bound on transactions for any layout that carries the proof bytes once: T >= ceil(proof / X)
  for (const X of [100_000, 200_000, 400_000, 1_000_000]) console.log(`- G2 lower bound at tx limit ${fmt(X)}: >= ${Math.ceil(r.proofBytes / X)} tx (proof ${fmt(r.proofBytes)} B must be pushed once)`);
}
