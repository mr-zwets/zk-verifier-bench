// Export the optimized Track 10 G2 layout a' (groth16_cashscript main, research/pq-wrap/onchain, --nc 3
// --opt sib,lad,state,cap=3) as node-check workloads (nc.ts json: format). Copy of export-g2.mjs, adapted to opt.state
// (transactions t >= 1 run under R1: STATE, LIB, TOP, QRY; per-transaction OP_DEFINE bytes).
//   G16=<groth16_cashscript checkout at main + the limits-table scratch patch (grade-lim.mjs, LIMITS_UNL in gena.mjs,
//   registerRegime in vm.mjs)> node export-t10opt.mjs --cat <category internal hex> --out <dir> [--cases <dir>]
//   [--rej 0] VECTOR.json...
// Per vector, two plans:
//   o4  the standard plan: grade-a2.mjs planFor (X = 100,000 B): 4 transactions linked by the thread NFT, built with
//       the node's faucet category (tx k >= 1: input 0 is fromTx {tx: 0, vout: k}). Checked against the graded build
//       (test category): same sizes and per-input op-cost.
//   o1  the one-transaction plan: limits-table grade-lim.mjs planFor at U = 10,000, X = 1,000,000 (consensus only):
//       1 transaction, no thread. Every input is standard on its own; the transaction is over the 100,000 B standard
//       size, so relay policy must reject it and consensus must accept it.
//   rej (vectors in --rej) a reject sample of the o4 plan (the g2n2 families of export-g2.mjs, plus opt-specific
//       state and cap-layer cases from test-a2.mjs) and three of the o1 plan; each as the first transaction that the
//       libauth consensus VM rejects.
import {writeFileSync, existsSync, mkdirSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
const G16 = process.env.G16 ?? '/home/mrzwets/BCH-projects/verifier.cash/work/nc-t10opt/g16';
const D = `${G16}/research/pq-wrap/onchain`;
const args = process.argv.slice(2);
const opt = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const catHex = opt('--cat'), outDir = opt('--out'), casesDir = opt('--cases');
const REJ = new Set((opt('--rej', '0')).split(',').filter(Boolean).map(Number));
const files = args.filter((a, i) => !a.startsWith('--') && !['--cat', '--out', '--cases', '--rej'].includes(args[i - 1]));
if (!catHex || !outDir) throw new Error('--cat and --out required');
if ((process.env.LIMITS_UNL ?? '10000') !== '10000') throw new Error('LIMITS_UNL must be unset or 10000');
// grade-a2.mjs and grade-lim.mjs read their settings from process.argv at import
process.argv = [process.argv[0], process.argv[1], '--nc', '3', '--unl', '10000', '--tx', '1000000', '--pers', '3,2,1'];
const imp = (f) => import(pathToFileURL(`${D}/${f}`).href);
const {readVector} = await imp('layoutn.mjs');
const {vkxA, P, sha} = await imp('modela.mjs');
const {applyTamper} = await imp('modeln.mjs');
const {spendA, evaluateTxA, verifyTxA, parseOpt} = await imp('layouta.mjs');
const {threadCommit} = await imp('gena.mjs');
const A2 = await imp('grade-a2.mjs');
const LIM = await imp('grade-lim.mjs');
const OPT = parseOpt('sib,lad,state,cap=3');
mkdirSync(outDir, {recursive: true});
const NODECAT = Buffer.from(catHex, 'hex');
const hex = (b) => Buffer.from(b).toString('hex');
const h16 = (b) => createHash('sha256').update(b).digest('hex').slice(0, 16);
const tokJ = (t) => t && {categoryHex: hex(t.category), amount: String(t.amount), ...(t.nft ? {nft: {capability: t.nft.capability, commitmentHex: hex(t.nft.commitment)}} : {})};
const outJ = (o) => ({lockingHex: hex(o.lockingBytecode), valueSatoshis: String(o.valueSatoshis), ...(o.token ? {token: tokJ(o.token)} : {})});
const txJ = (transaction, sourceOutputs, t, link) => ({label: `tx${t}`, version: transaction.version, locktime: transaction.locktime,
  inputs: transaction.inputs.map((inp, i) => ({source: outJ(sourceOutputs[i]), unlockingHex: hex(inp.unlockingBytecode), sequenceNumber: inp.sequenceNumber,
    ...(link && i === 0 && t > 0 ? {fromTx: {tx: 0, vout: t}} : {})})),
  outputs: transaction.outputs.map(outJ)});
const lib = (tx, plan, t, defineBytes) => { const s = evaluateTxA(tx, 'bchStd'), c = evaluateTxA(tx, 'bchCons'); const w = verifyTxA(tx, 'bchCons'), ws = verifyTxA(tx, 'bchStd');
  return {cons: w === true, consErr: w === true ? null : String(w).slice(0, 200), std: ws === true, stdErr: ws === true ? null : String(ws).slice(0, 200),
    perInput: s.map((x, i) => ({role: A2.roleOf(plan, i, t), unlocking: x.unlocking, opStd: x.opCost, opCons: c[i].opCost, defineBytes, budget: x.budget,
      bchnAdj: Math.max(x.opCost, c[i].opCost) + defineBytes, std: x.accepted, consOk: c[i].accepted}))}; };
const outputsOf = (v) => v.s4_outputs.map((o) => ({lockingBytecode: Uint8Array.from(Buffer.from(o.lockingBytecode, 'hex')), valueSatoshis: BigInt(o.valueSatoshis)}));
const altOutputs = (outs) => outs.map((o, i) => (i === 0 ? {...o, valueSatoshis: o.valueSatoshis - 1n} : o));
const flip = (b, at) => { const c = Buffer.from(b); c[at < 0 ? c.length + at : at] ^= 1; return c; };
const cloneWit = (w) => w.map((tx) => tx.map((it) => it.map((x) => Buffer.from(x))));
const cloneTxs = (txs) => txs.map((tx) => ({...tx, transaction: {...tx.transaction, inputs: [...tx.transaction.inputs], outputs: [...tx.transaction.outputs]}, sourceOutputs: [...tx.sourceOutputs]}));
const log = [];
const say = (s) => { console.error(s); log.push(s); };

// the reject sample of one plan: cases C (family, nm, {buf, pv, outs, mutate, txMutate}) -> workloads
function rejects(tag, vname, vk, plan, proof, pis, outs, GO, C, wls) {
  let n = 0; const honestG = spendA(vk, plan, proof, pis, outs, GO).enc.G;
  for (const c of C) {
    let r;
    try { r = spendA(vk, plan, c.buf ?? proof, c.pv ?? pis, c.outs ?? outs, GO, c.mutate); } catch (e) { say(`skip ${tag} ${c.nm}: generator refused (${String(e.message).slice(0, 120)})`); continue; }
    if (r.enc.malformed && (/truncated|trailing/.test(r.enc.malformed) || r.enc.G.equals(honestG)) && !c.mutate && !c.txMutate) { say(`skip ${tag} ${c.nm}: encoder-only (${r.enc.malformed})`); continue; }
    let txs = r.txs; if (c.txMutate) txs = c.txMutate(cloneTxs(txs), r) ?? txs;
    const t = txs.findIndex((tx) => verifyTxA(tx, 'bchCons') !== true);
    if (t < 0) { say(`WARN ${tag} ${vname} ${c.nm}: libauth accepts every transaction; not exported`); continue; }
    const tx = txs[t]; const defB = A2.defineBytesOf(r, t); const l = lib(tx, plan, t, defB);
    const rejIn = l.perInput.findIndex((x) => !x.consOk);
    wls.push({id: `${tag}-${vname}:${c.family}:${c.nm}`, group: `${tag}-${vname}`, kind: c.family.startsWith('tampered') ? 'tampered' : 'manipulation', description: `${c.family}: ${c.nm} (tx${t})`,
      expect: 'reject', defBytes: defB, g2: {cons: false, consErr: l.consErr, rejectingInput: rejIn, rejectingRole: rejIn >= 0 ? l.perInput[rejIn].role : 'whole-tx', tx: t, txBytes: tx.txBytes},
      txs: [txJ(tx.transaction, tx.sourceOutputs, t, false)]});
    n++;
  }
  return n;
}
function tamperedCases(add, vname, v) {
  const cf = casesDir ? `${casesDir}/${vname}.json` : null;
  if (!cf || !existsSync(cf)) return;
  const cv = readVector(cf);
  if (cv.proof_hex !== v.proof_hex) throw new Error(`${cf}: another proof`);
  for (const fam of ['cap', 'ood', 'random', 'pow', 'final', 'row', 'salt', 'sibling', 'fri_value']) {
    const t = (cv.tampered ?? []).find((x) => x.family === fam && !x.public_values && x.expect !== true);
    if (t) add(`tampered:${fam}`, t.name, {buf: applyTamper(v.proof_hex, t)});
  }
}

for (const f of files) {
  const v = readVector(f), vname = f.split('/').pop().replace(/\.json$/, ''), sIdx0 = +vname.match(/-(\d+)-Z128/)[1];
  const vk = vkxA(v), pis = v.public_values.flat().map(BigInt), outs = outputsOf(v), proof = Buffer.from(v.proof_hex, 'hex');
  const wls = [];
  const nb = vname.replace(/-(\d+)-(Z128.*)$/, (_, i, s) => `-${(+i + 1) % 2}-${s}`); const p2 = `${f.split('/').slice(0, -1).join('/')}/${nb}.json`;
  const ov = existsSync(p2) ? readVector(p2) : null;
  // ---------------- o4: the standard 4-transaction plan
  const pf = A2.planFor(vk, proof, pis, outs, {nc: 3, opt: OPT});
  if (!pf.plan) throw new Error(`${vname}: no o4 plan`);
  const planG = pf.plan, spG = pf.sp;
  const GO = {gen: {nodeCategory: catHex}};   // a distinct programA cache key (the category itself is plan.thread)
  const plan = {...planG, thread: {category: NODECAT}};
  const sp = spendA(vk, plan, proof, pis, outs, GO);
  const T = sp.txs.length;
  if (Buffer.compare(Buffer.from(sp.pg.redeem), Buffer.from(spG.pg.redeem)) === 0) throw new Error('node build reused the graded program');
  if (sp.pg.redeem.length !== spG.pg.redeem.length || sp.pg.defineBytes !== spG.pg.defineBytes || sp.pg.R1?.defineBytes !== spG.pg.R1?.defineBytes) throw new Error('node category changed the program size');
  sp.txs.forEach((tx, t) => {
    const defB = A2.defineBytesOf(sp, t);
    if (tx.txBytes !== spG.txs[t].txBytes) throw new Error(`${vname} tx${t}: node build ${tx.txBytes} B, graded ${spG.txs[t].txBytes} B`);
    const l = lib(tx, plan, t, defB); if (!l.cons || !l.std) throw new Error(`${vname} tx${t}: libauth rejects the node build: ${l.consErr ?? l.stdErr}`);
    const g = lib(spG.txs[t], planG, t, defB); const opDiff = l.perInput.filter((x, i) => x.opStd !== g.perInput[i].opStd).length;
    wls.push({id: `o4-${vname}:valid-tx${t}`, group: `o4-${vname}`, kind: 'valid', description: `opt a' standard plan, valid tx${t} of ${T}`, expect: 'accept', defBytes: defB,
      chainIndex: t, chainLength: T, g2: {...l, opStdDiffVsGraded: opDiff, txBytes: tx.txBytes, per: pf.per, pad: plan.pad, opt: OPT},
      txs: [txJ(tx.transaction, tx.sourceOutputs, t, true)]});
  });
  const inputs4 = sp.txs.reduce((a, x) => a + x.transaction.inputs.length, 0);
  say(`${vname} o4: ${T} tx, ${inputs4} inputs, ${sp.txs.map((x) => x.txBytes).join(' + ')} = ${sp.txs.reduce((a, x) => a + x.txBytes, 0)} B, define R0 ${sp.pg.defineBytes} R1 ${sp.pg.R1?.defineBytes}`);
  // ---------------- o1: the one-transaction plan (consensus only)
  const p1 = LIM.planFor(vk, proof, pis, outs, {nc: 3, opt: OPT});
  if (!p1.plan || p1.sp.txs.length !== 1) throw new Error(`${vname}: no 1-tx plan`);
  const tx1 = p1.sp.txs[0]; const def1 = p1.sp.pg.defineBytes;
  const l1 = lib(tx1, p1.plan, 0, def1);
  if (!l1.cons) throw new Error(`${vname} o1: libauth consensus rejects: ${l1.consErr}`);
  if (l1.std) throw new Error(`${vname} o1: libauth standard accepts a ${tx1.txBytes} B tx?`);
  wls.push({id: `o1-${vname}:valid-tx0`, group: `o1-${vname}`, kind: 'valid', description: `opt a' one-transaction plan (${tx1.txBytes} B > 100,000 B standard): consensus-valid, non-standard`,
    expect: 'accept', expectPolicy: 'reject', defBytes: def1, chainIndex: 0, chainLength: 1,
    g2: {...l1, txBytes: tx1.txBytes, per: p1.per, pad: p1.plan.pad, opt: OPT, inputsAllStd: l1.perInput.every((x) => x.std)}, txs: [txJ(tx1.transaction, tx1.sourceOutputs, 0, false)]});
  say(`${vname} o1: 1 tx, ${tx1.transaction.inputs.length} inputs, ${tx1.txBytes} B, define ${def1}, libauth cons ${l1.cons}, std ${l1.std} (${l1.stdErr}), every input std ${l1.perInput.every((x) => x.std)}, max BCHN-adj ${Math.max(...l1.perInput.map((x) => x.bchnAdj / x.budget)).toFixed(4)}`);
  // ---------------- reject samples
  let nrej4 = 0, nrej1 = 0;
  if (REJ.has(sIdx0)) {
    const nc = plan.nc, FIN = nc + 1, Q0 = nc + 2;
    const fo = plan.pad ? 1 : 0, qo = plan.pad ? 1 : 0;
    const CAPL = plan.opt?.cap ? +plan.opt.cap : 0, nTr = vk.trees.length;
    const SIB = !!plan.opt?.sib, nS = vk.pathB / 32 - nTr * CAPL;
    const flipPath = (a, k, off) => { if (!SIB) { a[k + 1] = flip(a[k + 1], off); return; } const o = off < 0 ? 32 * nS + off : off; const i = k + 1 + Math.floor(o / 32); a[i] = flip(a[i], o % 32); };
    const hIdx = (k) => ['ROOTS', 'OOD', 'BPOW', 'FROOTS', 'CPOW', 'QPOW', 'NF', 'CTXW'].indexOf(k);
    const STV = !!plan.opt?.state && T > 1;
    const sNames = ['ROOTS', 'FROOTS', 'FIN', 'TBL', ...(plan.opt?.lad ? ['LAD'] : []), 'NF', 'CTXW', 'G'];
    const sIdx = (k) => sNames.indexOf(k);
    const in0Idx = (t, k) => (STV && t > 0 ? sIdx(k) : hIdx(k));
    const Q0of = (t) => (STV && t > 0 ? (CAPL ? 3 : 2) : Q0);
    const m = (fn) => (w) => { const x = cloneWit(w); fn(x); return x; };
    const tok = (cap, commit) => ({amount: 0n, category: Uint8Array.from(NODECAT).reverse(), nft: {capability: cap, commitment: Uint8Array.from(commit)}});
    const C = []; const add = (family, nm, o) => C.push({family, nm, ...o});
    tamperedCases(add, vname, v);
    add('tx', `tx${T - 1} (final): output value - 1 sat (CTX differs)`, {outs: altOutputs(outs)});
    { const r = [...pis]; r[3] = (r[3] + 1n) % P; add('root', 'script ROOT[3] + 1', {pv: r}); }
    add('constants', 'FIN: TBL byte 0 flipped', {mutate: m((x) => { x[0][FIN][1 + fo] = flip(x[0][FIN][1 + fo], 0); })});
    add('constants', 'HEAD and STATE: NF lane 0 byte 0 flipped', {mutate: m((x) => { x.forEach((tx, t) => { tx[0][in0Idx(t, 'NF')] = flip(tx[0][in0Idx(t, 'NF')], 0); }); })});
    add('input', 'HEAD: OOD byte 100 flipped', {mutate: m((x) => { x[0][0][hIdx('OOD')] = flip(x[0][0][hIdx('OOD')], 100); })});
    const hintOff = vk.blob.total - 8;
    add('input', 'QRY: hint T + 1', {mutate: m((x) => { const b = Buffer.from(x[0][Q0][qo]); b.writeBigUInt64LE((b.readBigUInt64LE(hintOff) + 1n) % P, hintOff); x[0][Q0][qo] = b; })});
    add('input', 'QRY: path byte (input tree) flipped', {mutate: m((x) => { flipPath(x[0][Q0], qo, 100); })});
    if (plan.pad?.qry?.[0]?.[0]) add('pad', 'QRY: pad byte 0 set to 1', {mutate: m((x) => { x[0][Q0][0] = flip(x[0][Q0][0], 0); })});
    else add('pad', 'QRY: empty pad replaced by one byte 0x01', {mutate: m((x) => { x[0][Q0][0] = Buffer.from([1]); })});
    if (plan.pad?.fin) add('pad', 'FIN: pad last byte set to 1', {mutate: m((x) => { x[0][FIN][0] = flip(x[0][FIN][0], -1); })});
    else add('pad', 'FIN: empty pad replaced by one byte 0x01', {mutate: m((x) => { x[0][FIN][0] = Buffer.from([1]); })});
    add('graph', 'CODE 1: code blob byte flipped', {mutate: m((x) => { x[0][1][0] = flip(x[0][1][0], 500); })});
    add('graph', 'two QRY inputs swapped (order)', {txMutate: (txs) => { const tx = txs[0]; const i = tx.transaction.inputs; [i[Q0], i[Q0 + 1]] = [i[Q0 + 1], i[Q0]]; [tx.sourceOutputs[Q0], tx.sourceOutputs[Q0 + 1]] = [tx.sourceOutputs[Q0 + 1], tx.sourceOutputs[Q0]]; return txs; }});
    add('graph', 'one input with another locking (R + one byte)', {txMutate: (txs) => { const so = txs[0].sourceOutputs; so[Q0] = {...so[Q0], lockingBytecode: Uint8Array.from([...so[Q0].lockingBytecode, 0x61])}; return txs; }});
    if (ov) {
      const op = ov.public_values.flat().map(BigInt);
      const ow = () => spendA(vk, plan, Buffer.from(ov.proof_hex, 'hex'), op, outputsOf(ov), GO).wit;
      add('mix', `one QRY input from another statement (${nb})`, {mutate: (w) => { const x = cloneWit(w), y = ow(); x[0][Q0 + 1] = y[0][Q0 + 1]; return x; }});
      add('mix', 'transaction 1 (all inputs) from another statement, the NFT of this proof (replay)', {mutate: (w) => { const x = cloneWit(w), y = ow(); x[1] = y[1]; return x; }});
    }
    add('thread', 'tx1: spends an NFT minted for another proof (commitment of another G)', {txMutate: (txs) => { const so = txs[1].sourceOutputs; so[0] = {...so[0], token: tok('none', threadCommit(sha(Buffer.from('another proof')), 1))}; return txs; }});
    add('thread', 'tx1: input 0 without the NFT', {txMutate: (txs) => { const so = txs[1].sourceOutputs; const {token, ...rest} = so[0]; void token; so[0] = rest; return txs; }});
    add('thread', `tx${T - 1}: a QRY input of tx0 instead of its own`, {mutate: m((x) => { x[T - 1][Q0of(T - 1)] = x[0][Q0]; })});
    add('thread', 'tx0: baton not returned (output 0 is the NFT only)', {txMutate: (txs) => { txs[0].transaction.outputs.shift(); return txs; }});
    // opt-specific (test-a2.mjs state / layer families)
    add('state', 'tx1 STATE: TBL byte 3 flipped', {mutate: m((x) => { x[1][0][sIdx('TBL')] = flip(x[1][0][sIdx('TBL')], 3); })});
    add('state', 'tx1: library blob byte flipped', {mutate: m((x) => { x[1][1][0] = flip(x[1][1][0], 700); })});
    add('state', 'tx1: input 0 (STATE, with its NFT) locked to R0', {txMutate: (txs, r) => { const so = txs[1].sourceOutputs; so[0] = {...so[0], lockingBytecode: r.pg.redeem}; return txs; }});
    add('layer', 'HEAD: LAYER tree 0 node 0 byte 0 flipped', {mutate: m((x) => { x[0][0][8] = flip(x[0][0][8], 0); })});
    add('layer', 'tx1 TOP: LAYER byte 100 flipped', {mutate: m((x) => { x[1][2][0] = flip(x[1][2][0], 100); })});
    nrej4 = rejects('o4', vname, vk, plan, proof, pis, outs, GO, C, wls);
    // o1: three cases (a tampered proof, the outputs, a QRY input)
    const plan1 = p1.plan, Q01 = plan1.nc + 2, qo1 = plan1.pad ? 1 : 0;
    const C1 = []; const add1 = (family, nm, o) => C1.push({family, nm, ...o});
    tamperedCases((fam, nm, o) => { if (fam === 'tampered:fri_value') add1(fam, nm, o); }, vname, v);
    add1('tx', 'output value - 1 sat (CTX differs)', {outs: altOutputs(outs)});
    add1('input', 'QRY: hint T + 1', {mutate: m((x) => { const b = Buffer.from(x[0][Q01][qo1]); b.writeBigUInt64LE((b.readBigUInt64LE(hintOff) + 1n) % P, hintOff); x[0][Q01][qo1] = b; })});
    nrej1 = rejects('o1', vname, vk, plan1, proof, pis, outs, {}, C1, wls);
  }
  const out = `${outDir}/t10opt-${vname}.json`;
  writeFileSync(out, JSON.stringify({vector: vname, o4: {transactions: T, inputs: inputs4, txBytes: sp.txs.map((x) => x.txBytes), defBytesR0: sp.pg.defineBytes, defBytesR1: sp.pg.R1?.defineBytes},
    o1: {transactions: 1, inputs: tx1.transaction.inputs.length, txBytes: [tx1.txBytes], defBytes: def1}, category: catHex, workloads: wls}) + '\n');
  say(`${vname}: ${wls.length} workloads (${nrej4} o4 rejects, ${nrej1} o1 rejects) -> ${out} (sha256 ${h16(JSON.stringify(wls))})`);
}
writeFileSync(`${outDir}/export-t10opt.log`, log.join('\n') + '\n');
