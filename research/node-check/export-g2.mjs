// Export Track 10 gate G2 (shape twin; groth16_cashscript wip/t10-gates research/pq-wrap) as node-check workloads.
//   G16=<groth16_cashscript checkout with research/pq-wrap> node export-g2.mjs --cat <category internal hex> --out <dir>
//       [--cases <case files dir>] [--rej 0] VECTOR.json...      (the cap-0 twin vectors)
// Per vector:
//   a'  the plan of grade-a2.mjs planFor (3 CODE inputs, pads, T transactions linked by the NFT thread), built with
//       the node's faucet category (the thread NFT category must be a real genesis outpoint); every transaction is a
//       valid workload (tx k >= 1: input 0 is fromTx {tx: 0, vout: k}). Checked first against the graded build (Track
//       10's test category): same sizes and per-input op-cost.
//   b2  the one b2 transaction (two inputs of 125-135 KB). It needs raised per-input limits (150,000 B) and a raised
//       transaction size, so under today's rules it is expected to be rejected by BCHN and by libauth's BCH 2026 VM.
//   rej (vectors in --rej) a reject sample of the a' families (test-a2.mjs), each as the first transaction that the
//       libauth consensus VM rejects.
// Workload json: nc.ts's json: format. Uses the checkout's libauth (3.1.0-next.8, unpatched) for the per-input figures
// (op-cost + defineBytes = BCHN-adjusted, Track 8a).
import {writeFileSync, existsSync, mkdirSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
const G16 = process.env.G16 ?? '/home/mrzwets/BCH-projects/verifier.cash/work/t10-gates/code';
const D = `${G16}/research/pq-wrap/onchain`;
const imp = (f) => import(pathToFileURL(`${D}/${f}`).href);
const {readVector, vkxN, stmtFor, spendB2} = await imp('layoutn.mjs');
const {vkxA, P, sha} = await imp('modela.mjs');
const {applyTamper} = await imp('modeln.mjs');
const {spendA, evaluateTxA, verifyTxA} = await imp('layouta.mjs');
const {threadCommit} = await imp('gena.mjs');
const {planFor} = await imp('grade-a2.mjs');
const {evaluate} = await imp('vm.mjs');

const args = process.argv.slice(2);
const opt = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const catHex = opt('--cat'), outDir = opt('--out'), casesDir = opt('--cases');
const REJ = new Set((opt('--rej', '0')).split(',').filter(Boolean).map(Number));
const files = args.filter((a, i) => !a.startsWith('--') && !['--cat', '--out', '--cases', '--rej'].includes(args[i - 1]));
if (!catHex || !outDir) throw new Error('--cat and --out required');
mkdirSync(outDir, {recursive: true});
const NODECAT = Buffer.from(catHex, 'hex');
const roleOf = (plan, i) => (i === 0 ? 'HEAD' : i <= plan.nc ? `CODE${i}` : i === plan.nc + 1 ? 'FIN' : 'QRY');
const hex = (b) => Buffer.from(b).toString('hex');
const h16 = (b) => createHash('sha256').update(b).digest('hex').slice(0, 16);
const tokJ = (t) => t && {categoryHex: hex(t.category), amount: String(t.amount), ...(t.nft ? {nft: {capability: t.nft.capability, commitmentHex: hex(t.nft.commitment)}} : {})};
const outJ = (o) => ({lockingHex: hex(o.lockingBytecode), valueSatoshis: String(o.valueSatoshis), ...(o.token ? {token: tokJ(o.token)} : {})});
const txJ = (transaction, sourceOutputs, t, link) => ({label: `tx${t}`, version: transaction.version, locktime: transaction.locktime,
  inputs: transaction.inputs.map((inp, i) => ({source: outJ(sourceOutputs[i]), unlockingHex: hex(inp.unlockingBytecode), sequenceNumber: inp.sequenceNumber,
    ...(link && i === 0 && t > 0 ? {fromTx: {tx: 0, vout: t}} : {})})),
  outputs: transaction.outputs.map(outJ)});
const lib = (tx, plan, defineBytes) => { const s = evaluateTxA(tx, 'bchStd'), c = evaluateTxA(tx, 'bchCons'); const w = verifyTxA(tx, 'bchCons');
  return {cons: w === true, consErr: w === true ? null : String(w).slice(0, 200), std: verifyTxA(tx, 'bchStd') === true,
    perInput: s.map((x, i) => ({role: roleOf(plan, i), unlocking: x.unlocking, opStd: x.opCost, opCons: c[i].opCost, defineBytes, budget: x.budget,
      bchnAdj: Math.max(x.opCost, c[i].opCost) + defineBytes, std: x.accepted, consOk: c[i].accepted}))}; };
const outputsOf = (v) => v.s4_outputs.map((o) => ({lockingBytecode: Uint8Array.from(Buffer.from(o.lockingBytecode, 'hex')), valueSatoshis: BigInt(o.valueSatoshis)}));
const altOutputs = (outs) => outs.map((o, i) => (i === 0 ? {...o, valueSatoshis: o.valueSatoshis - 1n} : o));
const flip = (b, at) => { const c = Buffer.from(b); c[at < 0 ? c.length + at : at] ^= 1; return c; };
const cloneWit = (w) => w.map((tx) => tx.map((it) => it.map((x) => Buffer.from(x))));
const cloneTxs = (txs) => txs.map((tx) => ({...tx, transaction: {...tx.transaction, inputs: [...tx.transaction.inputs], outputs: [...tx.transaction.outputs]}, sourceOutputs: [...tx.sourceOutputs]}));
const log = [];
const say = (s) => { console.error(s); log.push(s); };

for (const f of files) {
  const v = readVector(f), vname = f.split('/').pop().replace(/\.json$/, ''), sIdx = +vname.match(/-(\d+)-Z128/)[1];
  const vk = vkxA(v), pis = v.public_values.flat().map(BigInt), outs = outputsOf(v), proof = Buffer.from(v.proof_hex, 'hex');
  const wls = [];
  // 1. a': the graded plan (test category), then the node build (node category)
  const pf = planFor(vk, proof, pis, outs, {nc: 3});
  if (!pf.plan) throw new Error(`${vname}: no a' plan`);
  const planG = pf.plan, spG = pf.sp;
  const GO = {gen: {nodeCategory: catHex}};
  const plan = {...planG, thread: {category: NODECAT}};
  const sp = spendA(vk, plan, proof, pis, outs, GO);
  if (Buffer.compare(Buffer.from(sp.pg.redeem), Buffer.from(spG.pg.redeem)) === 0) throw new Error('node build reused the graded program');
  if (sp.pg.redeem.length !== spG.pg.redeem.length || sp.pg.defineBytes !== spG.pg.defineBytes) throw new Error('node category changed the program size');
  const defineBytes = sp.pg.defineBytes;
  const libs = sp.txs.map((tx) => lib(tx, plan, defineBytes));
  sp.txs.forEach((tx, t) => {
    if (tx.txBytes !== spG.txs[t].txBytes) throw new Error(`${vname} tx${t}: node build ${tx.txBytes} B, graded ${spG.txs[t].txBytes} B`);
    const l = libs[t]; if (!l.cons || !l.std) throw new Error(`${vname} tx${t}: libauth rejects the node build: ${l.consErr}`);
    const g = lib(spG.txs[t], planG, defineBytes); const opDiff = l.perInput.filter((x, i) => x.opStd !== g.perInput[i].opStd).length;
    wls.push({id: `g2-a-${vname}:valid-tx${t}`, group: `g2-a-${vname}`, kind: 'valid', description: `a' valid tx${t} of ${sp.txs.length}`, expect: 'accept', defBytes: defineBytes,
      chainIndex: t, chainLength: sp.txs.length, g2: {...l, opStdDiffVsGraded: opDiff, txBytes: tx.txBytes, per: pf.per, pad: plan.pad},
      txs: [txJ(tx.transaction, tx.sourceOutputs, t, true)]});
  });
  say(`${vname} a': ${sp.txs.length} tx, ${sp.txs.map((x) => x.txBytes).join(' + ')} = ${sp.txs.reduce((a, x) => a + x.txBytes, 0)} B, def ${defineBytes}, max BCHN-adj ${Math.max(...libs.flatMap((l) => l.perInput.map((x) => x.bchnAdj / x.budget))).toFixed(4)}`);
  // 2. b2: one transaction, expected rejected under today's rules (libauth BCH 2026 consensus and BCHN)
  {
    const vk0 = vkxN(v, {stmt: 'pool'});
    const mk = (qa) => spendB2(vk0, stmtFor(vk0, pis, {mode: 'pool', ctx: 'tx'}), qa, proof, pis, outs);
    let QA = Math.ceil(vk0.Q / 2), b = mk(QA);
    const perQ = (b.unlocking0.length + b.unlocking1.length) / vk0.Q;
    const qa2 = Math.max(1, Math.min(vk0.Q - 1, QA - Math.round((b.unlocking0.length - b.unlocking1.length) / (2 * perQ))));
    if (qa2 !== QA) { const b2 = mk(qa2); if (Math.max(b2.unlocking0.length, b2.unlocking1.length) < Math.max(b.unlocking0.length, b.unlocking1.length)) { b = b2; QA = qa2; } }
    const defB = [...b.built.g.fns.values()].reduce((a, x) => a + x.body.length, 0);
    const per = [0, 1].map((i) => { const r150 = evaluate('r150Std', null, null, b.progs[i]), today = evaluate('bchCons', null, null, b.progs[i]);
      return {unlocking: i ? b.unlocking1.length : b.unlocking0.length, r150: r150.accepted, opStd: r150.opCost, bchnAdj: r150.opCost + defB, today: today.accepted, todayErr: String(today.error ?? '').slice(0, 160)}; });
    wls.push({id: `g2-b2-${vname}:tx`, group: `g2-b2-${vname}`, kind: 'b2-raised-limits', description: `b2 (QA ${QA}): valid only with per-input limits >= ${Math.max(per[0].unlocking, per[1].unlocking)} B and tx size raised; today's rules reject`,
      expect: 'reject', expectLibauth: 'reject', defBytes: defB, g2: {QA, perInput: per, txBytes: Buffer.from((await import(pathToFileURL(`${G16}/node_modules/@bitauth/libauth/build/index.js`).href)).encodeTransactionBch(b.tx)).length},
      txs: [txJ(b.tx, b.sourceOutputs, 0, false)]});
    say(`${vname} b2: QA ${QA}, unlocking ${per[0].unlocking} + ${per[1].unlocking}, r150 ${per.map((x) => x.r150)}, today ${per.map((x) => x.today)} (${per[0].todayErr})`);
  }
  // 3. reject sample (a' families)
  let nrej = 0;
  if (REJ.has(sIdx)) {
    const nc = plan.nc, FIN = nc + 1, Q0 = nc + 2, T = plan.txs.length, qo = 1, fo = 1;
    const hIdx = (k) => ['ROOTS', 'OOD', 'BPOW', 'FROOTS', 'CPOW', 'QPOW', 'NF', 'CTXW'].indexOf(k);
    const m = (fn) => (w) => { const x = cloneWit(w); fn(x); return x; };
    const C = [];
    const add = (family, nm, o) => C.push({family, nm, ...o});
    const cf = casesDir ? `${casesDir}/${vname}.json` : null;
    if (cf && existsSync(cf)) {
      const cv = readVector(cf);
      if (cv.proof_hex !== v.proof_hex) throw new Error(`${cf}: another proof`);
      for (const fam of ['cap', 'ood', 'random', 'pow', 'final', 'row', 'salt', 'sibling', 'fri_value']) {
        const t = (cv.tampered ?? []).find((x) => x.family === fam && !x.public_values && x.expect !== true);
        if (t) add(`tampered:${fam}`, t.name, {buf: applyTamper(v.proof_hex, t)});
      }
    }
    add('tx', 'output value - 1 sat (CTX differs)', {outs: altOutputs(outs)});
    { const r = [...pis]; r[3] = (r[3] + 1n) % P; add('root', 'script ROOT[3] + 1', {pv: r}); }
    add('constants', 'FIN: TBL byte 0 flipped', {mutate: m((x) => { x[0][FIN][1 + fo] = flip(x[0][FIN][1 + fo], 0); })});
    add('constants', 'HEAD: NF lane 0 byte 0 flipped', {mutate: m((x) => { for (const tx of x) tx[0][hIdx('NF')] = flip(tx[0][hIdx('NF')], 0); })});
    add('input', 'HEAD: OOD byte 100 flipped', {mutate: m((x) => { x[0][0][hIdx('OOD')] = flip(x[0][0][hIdx('OOD')], 100); })});
    const hintOff = vk.blob.total - 8;
    add('input', 'QRY: hint T + 1', {mutate: m((x) => { const b = Buffer.from(x[0][Q0][qo]); b.writeBigUInt64LE((b.readBigUInt64LE(hintOff) + 1n) % P, hintOff); x[0][Q0][qo] = b; })});
    add('input', 'QRY: path byte (input tree) flipped', {mutate: m((x) => { x[0][Q0][qo + 1] = flip(x[0][Q0][qo + 1], 100); })});
    add('pad', 'QRY: pad byte 0 set to 1', {mutate: m((x) => { x[0][Q0][0] = flip(x[0][Q0][0], 0); })});
    add('pad', 'FIN: pad last byte set to 1', {mutate: m((x) => { x[0][FIN][0] = flip(x[0][FIN][0], -1); })});
    add('graph', 'CODE 1: code blob byte flipped', {mutate: m((x) => { x[0][1][0] = flip(x[0][1][0], 500); })});
    add('graph', 'two QRY inputs swapped (order)', {txMutate: (txs) => { const tx = txs[0]; const i = tx.transaction.inputs; [i[Q0], i[Q0 + 1]] = [i[Q0 + 1], i[Q0]]; [tx.sourceOutputs[Q0], tx.sourceOutputs[Q0 + 1]] = [tx.sourceOutputs[Q0 + 1], tx.sourceOutputs[Q0]]; return txs; }});
    add('graph', 'one input with another locking (R + one byte)', {txMutate: (txs) => { const so = txs[0].sourceOutputs; so[Q0] = {...so[Q0], lockingBytecode: Uint8Array.from([...so[Q0].lockingBytecode, 0x61])}; return txs; }});
    { const nb = vname.replace(/-(\d+)-(Z128.*)$/, (_, i, s) => `-${(+i + 1) % 2}-${s}`); const p2 = `${f.split('/').slice(0, -1).join('/')}/${nb}.json`;
      if (existsSync(p2)) { const ov = readVector(p2), op = ov.public_values.flat().map(BigInt);
        const ow = () => spendA(vk, plan, Buffer.from(ov.proof_hex, 'hex'), op, outputsOf(ov), GO).wit;
        add('mix', `one QRY input from another statement (${nb})`, {mutate: (w) => { const x = cloneWit(w), y = ow(); x[0][Q0 + 1] = y[0][Q0 + 1]; return x; }});
        if (T > 1) add('mix', 'transaction 1 (all inputs) from another statement, the NFT of this proof (replay)', {mutate: (w) => { const x = cloneWit(w), y = ow(); x[1] = y[1]; return x; }}); } }
    if (T > 1) {
      const tok = (cap, commit) => ({amount: 0n, category: Uint8Array.from(plan.thread.category).reverse(), nft: {capability: cap, commitment: Uint8Array.from(commit)}});
      add('thread', 'tx1: spends an NFT minted for another proof (commitment of another G)', {txMutate: (txs) => { const so = txs[1].sourceOutputs; so[0] = {...so[0], token: tok('none', threadCommit(sha(Buffer.from('another proof')), 1))}; return txs; }});
      add('thread', 'tx1: input 0 without the NFT', {txMutate: (txs) => { const so = txs[1].sourceOutputs; const {token, ...rest} = so[0]; void token; so[0] = rest; return txs; }});
      add('thread', `tx${T - 1}: a QRY input of tx0 instead of its own`, {mutate: m((x) => { x[T - 1][Q0] = x[0][Q0]; })});
      add('thread', 'tx0: baton not returned (output 0 is the NFT only)', {txMutate: (txs) => { txs[0].transaction.outputs.shift(); return txs; }});
    }
    for (const c of C) {
      const r = spendA(vk, plan, c.buf ?? proof, c.pv ?? pis, c.outs ?? outs, GO, c.mutate);
      if (r.enc.malformed && (/truncated|trailing/.test(r.enc.malformed) || r.enc.G.equals(sp.enc.G)) && !c.mutate && !c.txMutate) { say(`skip ${c.nm}: encoder-only (${r.enc.malformed})`); continue; }
      let txs = r.txs; if (c.txMutate) txs = c.txMutate(cloneTxs(txs)) ?? txs;
      const t = txs.findIndex((tx) => verifyTxA(tx, 'bchCons') !== true);
      if (t < 0) { say(`WARN ${vname} ${c.nm}: libauth accepts every transaction; not exported`); continue; }
      const tx = txs[t]; const l = lib(tx, plan, defineBytes);
      const rejIn = l.perInput.findIndex((x) => !x.consOk);
      wls.push({id: `g2-a-${vname}:${c.family}:${c.nm}`, group: `g2-a-${vname}`, kind: c.family.split(':')[0] === 'tampered' ? 'tampered' : 'manipulation', description: `${c.family}: ${c.nm} (tx${t})`,
        expect: 'reject', defBytes: defineBytes, g2: {cons: false, consErr: l.consErr, rejectingInput: rejIn, rejectingRole: rejIn >= 0 ? l.perInput[rejIn].role : 'whole-tx', tx: t, txBytes: tx.txBytes},
        txs: [txJ(tx.transaction, tx.sourceOutputs, t, false)]});
      nrej++;
    }
  }
  const out = `${outDir}/g2-${vname}.json`;
  writeFileSync(out, JSON.stringify({vector: vname, transactions: sp.txs.length, txBytes: sp.txs.map((x) => x.txBytes), defBytes: defineBytes, redeemBytes: sp.pg.redeem.length,
    category: catHex, workloads: wls}) + '\n');
  say(`${vname}: ${wls.length} workloads (${nrej} rejects) -> ${out} (sha256 ${h16(JSON.stringify(wls))})`);
}
writeFileSync(`${outDir}/export-g2.log`, log.join('\n') + '\n');
