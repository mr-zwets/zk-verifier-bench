// Export a Track 5 STARK (Plonky3) layout (a) plan, today's standard rules, as node-check workloads.
//   G16=<groth16_cashscript checkout> node export-stark.mjs <vector name, e.g. mimc-S128-0> <category internal hex> <out.json>
// Same plan, program and pads as grade-a.mjs gradeA() (its loop is copied here so that the NFT thread category can be
// set to a real genesis outpoint txid on the node: the redeem pins the category; with a different category of the same
// length the plan, sizes and pads are unchanged). Emits:
//   valid: every transaction of the plan as its own workload, with its source outputs; for T > 1, tx k >= 1's input 0
//          is marked fromTx {tx: 0, vout: k} (the thread NFT minted by tx0), so the policy run can replay the real chain;
//   reject sample: 6 prover tamper cases spread over the list, 6 witness manipulations and (T > 1) 3 thread cases from
//          test-a.mjs; each as the first transaction in which libauth (consensus) rejects an input.
import {writeFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
const G16 = process.env.G16 ?? '/home/mrzwets/BCH-projects/verifier.cash/work/node-check/g16';
const V = `${G16}/research/pq-stark/verifier`;
const imp = (f) => import(pathToFileURL(`${V}/${f}`).href);
const {loadVector, programA, witnessesA, txsA, evaluateTx, verifyTx, encodeA} = await imp('layout-a.mjs');
const {planAndProgram} = await imp('grade-a.mjs');
const {casesOf} = await imp('layout-b.mjs');
const {threadCommit} = await imp('gen-a.mjs');
const {p2sh32} = await imp('vm.mjs');
const {sha} = await imp('model.mjs');

const [name, catHex, outFile] = process.argv.slice(2);
const {v, vk, proof, pis} = loadVector(`${G16}/research/pq-stark/prover/vectors/${name}.json`);
const {plan, pg: pg0} = planAndProgram(vk, pis, {});
const nc = pg0.nc;
if (plan.thread) plan.thread.category = Buffer.from(catHex, 'hex');
const pg = plan.thread ? programA(vk, pis, plan, {codeBlobs: nc}) : pg0;
if (pg.redeem.length !== pg0.redeem.length) throw new Error('redeem size changed with the category');
const enc = encodeA(vk, proof, pis);
const defineBytes = pg.code.reduce((a, c) => a + c.length, 0) + [...pg.fns.values()].reduce((a, f) => a + f.body.length, 0);
// ---- pads: gradeA's least fixpoint (BCHN-adjusted standard op-cost <= 94% of budget, hash iterations) ----
const MARGIN = 0.94; const pads = {};
let txs;
for (let it = 0; it < 12; it++) {
  txs = txsA(vk, plan, pg, witnessesA(vk, plan, pg, enc, pads), enc.G);
  const res = txs.map((tx) => evaluateTx(tx, 'looseStd')); let changed = false;
  res.forEach((rs, t) => rs.forEach((r, i) => {
    if (i >= 1 && i <= pg.nc) return;
    const need = Math.max(Math.ceil((r.opCost + defineBytes) / (800 * MARGIN)) - 41, Math.ceil(r.iters / 0.5) - 41);
    if (need > r.unlocking) { pads[`${t}:${i}`] = (pads[`${t}:${i}`] ?? 0) + need - r.unlocking; changed = true; }
  }));
  if (!changed) break;
}
if (txs.some((t) => t.txBytes > 100_000)) throw new Error('a padded transaction exceeds 100,000 B (gradeA would re-plan; not handled here)');
const T = plan.txs.length;
const hex = (b) => Buffer.from(b).toString('hex');
const tokJ = (t) => t && {categoryHex: hex(t.category), amount: String(t.amount), ...(t.nft ? {nft: {capability: t.nft.capability, commitmentHex: hex(t.nft.commitment)}} : {})};
const outJ = (o) => ({lockingHex: hex(o.lockingBytecode), valueSatoshis: String(o.valueSatoshis), ...(o.token ? {token: tokJ(o.token)} : {})});
const role = (t, i) => (i === 0 ? 'HEAD' : i <= pg.nc ? 'CODE' : 'QRY');
const lib = (tx, t) => { const s = evaluateTx(tx, 'bchStd'), c = evaluateTx(tx, 'bchCons');
  return {std: verifyTx(tx, 'bchStd') === true, cons: verifyTx(tx, 'bchCons') === true, consErr: verifyTx(tx, 'bchCons') === true ? null : String(verifyTx(tx, 'bchCons')).slice(0, 160),
    perInput: s.map((x, i) => ({role: role(t, i), unlocking: x.unlocking, opStd: x.opCost, opCons: c[i].opCost, budget: x.budget, iters: x.iters}))}; };
const txJ = (tx, t, label, link) => ({label, version: tx.transaction.version, locktime: tx.transaction.locktime,
  inputs: tx.transaction.inputs.map((inp, i) => ({source: outJ(tx.sourceOutputs[i]), unlockingHex: hex(inp.unlockingBytecode), sequenceNumber: inp.sequenceNumber,
    ...(link && i === 0 && t > 0 ? {fromTx: {tx: 0, vout: t}} : {})})),
  outputs: tx.transaction.outputs.map(outJ)});
const wls = [];
const add = (id, kind, expect, tx, t, extra = {}) => { const l = lib(tx, t);
  if ((expect === 'accept') !== l.cons) console.error(`WARN ${id}: libauth consensus ${l.cons} vs expect ${expect} ${l.consErr ?? ''}`);
  wls.push({id: `stark-${name}:${id}`, group: `stark-${name}`, kind, description: id, expect, defBytes: defineBytes, libauth: l, ...extra, txs: [txJ(tx, t, `tx${t}`, kind === 'valid')]}); };
txs.forEach((tx, t) => add(`valid-tx${t}`, 'valid', 'accept', tx, t, {chainIndex: t, chainLength: T}));
console.error(`${name}: ${T} txs, inputs ${txs.map((x) => x.unl.length).join('+')}, bytes ${txs.map((x) => x.txBytes).join('+')}, pads ${JSON.stringify(pads)}, def ${defineBytes}`);
// ---- reject sample ----
const firstRej = (ts) => { for (const [t, tx] of ts.entries()) if (verifyTx(tx, 'bchCons') !== true) return [tx, t]; return [ts[0], 0]; };
const build = (e, {g = pg, mutate, G} = {}) => { let wit = witnessesA(vk, plan, g, e, pads); if (mutate) wit = mutate(wit); return txsA(vk, plan, g, wit, G ?? e.G); };
const cases = casesOf(v).slice(1); const step = Math.ceil(cases.length / 6);
for (const c of cases.filter((_, i) => i % step === 0).slice(0, 6)) {
  const g = programA(vk, c.pis, plan, {codeBlobs: nc}); const e = encodeA(vk, c.proof, c.pis);
  if (e.malformed) { console.error(`skip ${c.name}: encoder flags it (${e.malformed})`); continue; }
  const [tx, t] = firstRej(build(e, {g})); add(`tampered:${c.name}`, 'tampered', 'reject', tx, t);
}
const q0 = nc + 1; const flip = (b, i) => { const x = Buffer.from(b); x[i < 0 ? x.length + i : i] ^= 1; return x; };
const mut = (nm, f) => { const [tx, t] = firstRej(build(enc, {mutate: f})); add(`manip:${nm}`, 'manipulation', 'reject', tx, t); };
mut('qry: L byte (row)', (w) => { w[0][q0][0] = flip(w[0][q0][0], 3); return w; });
mut('qry: path byte (input tree)', (w) => { w[0][q0][1] = flip(w[0][q0][1], 100); return w; });
mut('qry: input missing', (w) => { w[0].splice(q0 + 1, 1); return w; });
mut('head: OOD byte', (w) => { const k = pg.ptOrder.indexOf('OOD'); w[0][0][k] = flip(w[0][0][k], 5); return w; });
mut('code: byte', (w) => { w[0][1][0] = flip(w[0][1][0], 200); return w; });
{ const ts = build(enc); ts[0].sourceOutputs[q0] = {...ts[0].sourceOutputs[q0], lockingBytecode: p2sh32(Uint8Array.of(0x51))}; add('manip:graph: one input under a foreign locking', 'manipulation', 'reject', ts[0], 0); }
if (plan.thread) {
  { const ts = build(enc, {G: sha(Buffer.from('another proof'))}); add('thread: tx1 NFT committed to another G', 'thread', 'reject', ts[1], 1); }
  { const ts = build(enc); ts[0].transaction.outputs = ts[0].transaction.outputs.slice(0, 1); add('thread: tx0 without the thread NFT', 'thread', 'reject', ts[0], 0); }
  { const ts = build(enc); const so = ts[1].sourceOutputs[0];
    ts[1].sourceOutputs[0] = {...so, token: {...so.token, nft: {...so.token.nft, commitment: threadCommit(enc.G, 2)}}}; add('thread: tx1 holds the NFT of another k', 'thread', 'reject', ts[1], 1); }
}
writeFileSync(outFile, JSON.stringify({vector: name, transactions: T, defBytes: defineBytes, redeemBytes: pg.redeem.length, codeBytes: pg.code.map((c) => c.length), pads, workloads: wls}) + '\n');
console.error(`${wls.length} workloads -> ${outFile}`);
