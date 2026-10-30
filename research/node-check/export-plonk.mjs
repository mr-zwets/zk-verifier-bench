// Export the Track 7 PLONK/KZG today's-rules chain (10 inputs, one tx) as node-check workloads.
//   G16=<groth16_cashscript checkout> node export-plonk.mjs <circuit> <out.json>
// Uses groth16_cashscript research/plonk-kzg/verifier (chain.mjs / chaintest.mjs logic, unchanged). Emits:
//   valid  : every valid proof (5), expect accept;
//   tampered sample: 8 tampered proofs spread over the vector list (adaptive witness when the reference can build one,
//            else proof 0's witness with the tampered proof/PI swapped in, as chaintest.mjs does);
//   manipulation sample: 12 of chaintest.mjs's chain manipulations of valid proof 0;
//   define probes: valid proof 0 with one filled input's FILL shrunk so that its budget (41 + unlocking) * 800 sits
//            one byte below (probe-under) or at/above (probe-over) libauth consensus op-cost + the OP_DEFINE body bytes.
//            libauth accepts both; if BCHN charges the DEFINE bodies it rejects probe-under and accepts probe-over.
// Each tx is shaped as vm.mjs's program(): sources 100,000 sat under the shared P2SH32 locking, sequence 0, one
// OP_RETURN output of 1,000 sat.
import {writeFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
const G16 = process.env.G16 ?? '/home/mrzwets/BCH-projects/verifier.cash/work/node-check/g16';
const V = `${G16}/research/plonk-kzg/verifier`;
const imp = (f) => import(pathToFileURL(`${V}/${f}`).href);
const {loadVectors, parseVK, Reject, verifyPlonk} = await imp('plonk.mjs');
const {aff, G1} = await imp('math.mjs');
const {makePlan, buildMulti, multiWitness, planOpts} = await imp('multi.mjs');
const {chainTx, sizeFills} = await imp('chain.mjs');
const {spendTx, verifyTx} = await imp('vm.mjs');

const [circuit = 'mul2', outFile = `plonk-${circuit}.json`] = process.argv.slice(2);
const d = loadVectors(circuit); const vk = parseVK(d.vk.hex);
const plan = makePlan(vk, planOpts(vk, circuit)); const built = buildMulti(vk, plan);
const hex = (b) => Buffer.from(b).toString('hex');
const wls = [];
const toTx = (tx) => ({version: 2, locktime: 0,
  inputs: tx.map((x) => ({source: {lockingHex: hex(x.locking), valueSatoshis: '100000'}, unlockingHex: hex(x.unlocking), sequenceNumber: 0})),
  outputs: [{lockingHex: '6a', valueSatoshis: '1000'}]});
const lib = (tx) => { const s = spendTx('bch2026', 'standard', tx), c = spendTx('bch2026', 'consensus', tx);
  return {std: verifyTx('bch2026', 'standard', tx).accepted, cons: verifyTx('bch2026', 'consensus', tx).accepted,
    perInput: s.map((x, i) => ({role: plan.roles[i]?.kind ?? 'extra', unlocking: x.unlockingLen, opStd: x.opCost, opCons: c[i].opCost, budget: x.budget}))}; };
const add = (id, kind, expect, tx, extra = {}) => {
  const l = lib(tx);
  if ((expect === 'accept') !== l.cons && !extra.expectLibauth) console.error(`WARN ${id}: libauth consensus ${l.cons} vs expect ${expect}`);
  wls.push({id: `plonk-${circuit}:${id}`, group: `plonk-${circuit}`, kind, description: extra.description ?? id, expect, defBytes: built.defBytes, libauth: l, ...extra, txs: [{label: 'tx0', ...toTx(tx)}]});
};
// ---- valid ----
let base;
for (const [i, pr] of d.valid.entries()) {
  const w = multiWitness(vk, plan, built, pr.proof, pr.publicInputs); const fills = sizeFills(vk, plan, built, w.pushes); const tx = chainTx(vk, plan, built, w.pushes, fills);
  if (i === 0) base = {w, fills, tx};
  add(`valid${i}`, 'valid', 'accept', tx, {fills, nq: w.S.nq});
  console.error(`valid ${i} done`);
}
// ---- tampered sample ----
const pick = (arr, n) => arr.filter((_, i) => i % Math.ceil(arr.length / n) === 0).slice(0, n);
for (const t of pick(d.tampered, 8)) {
  let ps, fl, how;
  try { const w = multiWitness(vk, plan, built, t.proof, t.publicInputs); ps = w.pushes; how = 'adaptive'; fl = sizeFills(vk, plan, built, ps, {strict: false}); }
  catch (e) { if (!(e instanceof Reject) && !/exceptional|singular|chain MSM|deepEqual|Expected/.test(e.message)) throw e;
    ps = base.w.pushes.map((x) => x.slice()); const st = ps[plan.iST]; const f = plan.roles[plan.iST].fixed.map((x) => x[0]);
    st[f.indexOf('PROOF')] = Buffer.from(t.proof, 'hex'); st[f.indexOf('PI')] = Buffer.concat(t.publicInputs.map((h) => Buffer.from(h, 'hex'))); how = 'reused'; fl = base.fills; }
  add(`tampered:${t.name}`, 'tampered', 'reject', chainTx(vk, plan, built, ps, fl), {how});
}
console.error('tampered done');
// ---- manipulation sample (chaintest.mjs definitions) ----
const P = () => base.w.pushes.map((ps) => ps.map((b) => Buffer.from(b)));
const fi = (ix, name) => plan.roles[ix].fixed.findIndex((x) => x[0] === name);
const iMA = plan.roles.findIndex((r) => r.kind === 'MA' && !r.conv), iSI2 = plan.roles.findIndex((r) => r.kind === 'SI' && !r.first);
const man = (name, f, mutate) => { const ps = P(); f(ps); let tx = chainTx(vk, plan, built, ps, base.fills); if (mutate) tx = mutate(tx); add(`manip:${name}`, 'manipulation', 'reject', tx); };
man('MA hand-over word + 1', (ps) => { ps[iMA][fi(iMA, 'HAND')][0] ^= 1; });
man('SI hand-over R word flipped', (ps) => { const b = ps[iSI2][fi(iSI2, 'HAND')]; b[b.length - 5] ^= 4; });
man('slope bit flip (MA)', (ps) => { ps[iMA][plan.roles[iMA].fixed.length + 2][7] ^= 1; });
man('TV entry bit flip', (ps) => { ps[plan.iTV][fi(plan.iTV, 'TV')][500] ^= 1; });
man('WS state bit flip', (ps) => { ps[plan.iST][fi(plan.iST, 'WS')][3000] ^= 1; });
man('code blob C0 byte flip', (ps) => { ps[0][0][2000] ^= 1; });
if (plan.m) man('WQc word flipped', (ps) => { ps[plan.iWQc][fi(plan.iWQc, 'WQc')][100] ^= 1; });
man('two MA inputs swapped', () => {}, (tx) => { const t = tx.slice(); [t[iMA], t[iMA + 1]] = [t[iMA + 1], t[iMA]]; return t; });
man('extra foreign input', () => {}, (tx) => [...tx, {locking: Uint8Array.of(0x51), unlocking: Uint8Array.of()}]);
man('input dropped (last SI)', () => {}, (tx) => tx.slice(0, -1));
{ const pr = d.valid[0]; const Vv = verifyPlonk(vk, pr.proof, pr.publicInputs); const w = multiWitness(vk, plan, built, pr.proof, pr.publicInputs, {lam: aff(Vv.lamTrue.double())});
  add("manip:adaptive: Lambda' = 2 Lambda", 'manipulation', 'reject', chainTx(vk, plan, built, w.pushes, sizeFills(vk, plan, built, w.pushes, {strict: false}))); }
{ const w = multiWitness(vk, plan, built, d.valid[1].proof, d.valid[0].publicInputs);
  add('manip:adaptive: proof 1 with the public inputs of proof 0', 'manipulation', 'reject', chainTx(vk, plan, built, w.pushes, sizeFills(vk, plan, built, w.pushes, {strict: false}))); }
console.error('manipulations done');
// ---- DEFINE probes on valid proof 0 ----
{
  const iP = base.fills.indexOf(Math.max(...base.fills));
  const at = (fill) => { const fl = base.fills.slice(); fl[iP] = fill; const tx = chainTx(vk, plan, built, base.w.pushes, fl); const c = spendTx('bch2026', 'consensus', tx); return {fl, tx, c: c[iP].opCost, u: c[iP].unlockingLen}; };
  // FILL with budget (41 + u) * 800 just below / at-or-above c + defBytes (fixpoint: c moves with the FILL's own push)
  const solve = (under) => { let f = base.fills[iP];
    for (let it = 0; it < 6; it++) { const r = at(f); const target = r.c + built.defBytes; const uWant = under ? Math.ceil(target / 800) - 41 - 1 : Math.ceil(target / 800) - 41; const nf = f + (uWant - r.u); if (nf === f) break; f = nf; }
    if (f < 0) throw new Error('probe needs a negative FILL'); return at(f); };
  for (const under of [true, false]) {
    const r = solve(under); const budget = (41 + r.u) * 800;
    add(`define-probe-${under ? 'under' : 'over'}`, 'define-probe', under ? 'reject' : 'accept', r.tx, {expectLibauth: 'accept', probeInput: iP, probeFill: r.fl[iP],
      description: `input ${iP} (${plan.roles[iP].kind}) FILL ${r.fl[iP]}: budget ${budget}, libauth consensus op ${r.c}, + DEFINE bodies ${built.defBytes} = ${r.c + built.defBytes} (${under ? 'over' : 'within'} budget by ${Math.abs(budget - r.c - built.defBytes)})`});
  }
}
writeFileSync(outFile, JSON.stringify({circuit, defBytes: built.defBytes, redeemBytes: built.redeem.length, workloads: wls}) + '\n');
console.error(`${wls.length} workloads -> ${outFile}`);
