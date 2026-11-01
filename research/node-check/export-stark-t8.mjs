// Export Track 8 (groth16_cashscript research/pq-stark-batch, layout a', M1 Z128 cap 5) as node-check workloads.
//   G16=<groth16_cashscript checkout> node export-stark-t8.mjs --cat <category internal hex> --out <dir>
//       [--cases <S7 cases dir>] [--rej 0,23] VECTOR.json...
// Per vector and plan (1tx: 12 inputs; 2tx: 11 + 5 inputs linked by the NFT thread), the transactions come from
// Track 8's own code path (layouta.mjs spendA, the plan of grade-a.mjs), with Track 8's libauth (3.1.0-next.8 as
// installed for that checkout). Checks, per vector:
//   - built with Track 8's test category (layouta.mjs CATEGORY), every transaction's size and every input's unlocking
//     length and libauth standard op-cost equal grade-a.json (results/ of the checkout): byte-for-byte the build
//     grade-a measured (1tx tx bytes 98,690; 2tx 91,059 + 40,497);
//   - 2tx is then rebuilt with the node's faucet category (the thread NFT category must be a real genesis outpoint);
//     sizes and per-input op-cost must be unchanged (only 32 category bytes inside the code differ). 1tx has no
//     token and is exported exactly as graded.
// Emits <out>/t8-<plan>-<vector>.json in nc.ts's json: format: every transaction of the plan as a valid workload
// (2tx: tx1 input 0 is fromTx {tx: 0, vout: 1}, the thread NFT minted by tx0), and for the vectors in --rej a reject
// sample of the a' sweep families (test-a.mjs), each as the first transaction in which Track 8's libauth consensus VM
// rejects an input. Each workload carries Track 8's per-input numbers (t8: unpatched libauth op-cost + defineBytes).
import {writeFileSync, readFileSync, existsSync, mkdirSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
const G16 = process.env.G16 ?? '/home/mrzwets/BCH-projects/verifier.cash/work/node-check3/g16';
const D = `${G16}/research/pq-stark-batch/onchain`;
const imp = (f) => import(pathToFileURL(`${D}/${f}`).href);
const {readVector} = await imp('layoutn.mjs');
const {vkxA, P, sha} = await imp('modela.mjs');
const {applyTamper} = await imp('modeln.mjs');
const {makePlanA, spendA, evaluateTxA, verifyTxA, CATEGORY} = await imp('layouta.mjs');
const {threadCommit} = await imp('gena.mjs');

const args = process.argv.slice(2);
const opt = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const catHex = opt('--cat'), outDir = opt('--out'), casesDir = opt('--cases', '/home/mrzwets/BCH-projects/verifier.cash/work/stark-usable/cache/s7/cases');
const REJ = new Set((opt('--rej', '0,23')).split(',').map(Number));
const files = args.filter((a, i) => !a.startsWith('--') && !['--cat', '--out', '--cases', '--rej'].includes(args[i - 1]));
if (!catHex || !outDir) throw new Error('--cat and --out required');
mkdirSync(outDir, {recursive: true});
const NODECAT = Buffer.from(catHex, 'hex');
const grade = JSON.parse(readFileSync(`${D}/results/grade-a.json`, 'utf8'));
const EXPECT_BYTES = {'1tx': [98_690], '2tx': [91_059, 40_497]};
const plans = {
  '1tx': (vk) => [Array.from({length: Math.ceil(vk.Q / 3)}, (_, i) => Math.min(3, vk.Q - 3 * i))],
  '2tx': (vk) => { const p = Array.from({length: Math.ceil(vk.Q / 3)}, (_, i) => Math.min(3, vk.Q - 3 * i)); return [p.slice(0, -1), p.slice(-1)]; },
};
const roleOf = (plan, i) => (i === 0 ? 'HEAD' : i <= plan.nc ? `CODE${i}` : i === plan.nc + 1 ? 'FIN' : 'QRY');
const hex = (b) => Buffer.from(b).toString('hex');
const h16 = (b) => createHash('sha256').update(b).digest('hex').slice(0, 16);
const tokJ = (t) => t && {categoryHex: hex(t.category), amount: String(t.amount), ...(t.nft ? {nft: {capability: t.nft.capability, commitmentHex: hex(t.nft.commitment)}} : {})};
const outJ = (o) => ({lockingHex: hex(o.lockingBytecode), valueSatoshis: String(o.valueSatoshis), ...(o.token ? {token: tokJ(o.token)} : {})});
const txJ = (tx, t, link) => ({label: `tx${t}`, version: tx.transaction.version, locktime: tx.transaction.locktime,
  inputs: tx.transaction.inputs.map((inp, i) => ({source: outJ(tx.sourceOutputs[i]), unlockingHex: hex(inp.unlockingBytecode), sequenceNumber: inp.sequenceNumber,
    ...(link && i === 0 && t > 0 ? {fromTx: {tx: 0, vout: t}} : {})})),
  outputs: tx.transaction.outputs.map(outJ)});
const t8lib = (tx, plan, defineBytes) => { const s = evaluateTxA(tx, 'bchStd'), c = evaluateTxA(tx, 'bchCons'); const w = verifyTxA(tx, 'bchCons');
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
  for (const [pname, counts] of Object.entries(plans)) {
    // 1. the graded build (Track 8's test category) against grade-a.json
    const planG = makePlanA(vk, counts(vk));
    const spG = spendA(vk, planG, proof, pis, outs);
    const row = grade.rows.find((r) => r.vector === `${vname}.json` && r.plan === pname);
    if (!row) throw new Error(`${vname} ${pname}: no grade-a.json row`);
    spG.txs.forEach((tx, t) => {
      if (tx.txBytes !== EXPECT_BYTES[pname][t] || tx.txBytes !== row.txsDetail[t].bytes) throw new Error(`${vname} ${pname} tx${t}: ${tx.txBytes} B, grade-a ${row.txsDetail[t].bytes}`);
      const s = evaluateTxA(tx, 'bchStd');
      s.forEach((x, i) => { const g = row.txsDetail[t].detail[i];
        if (x.unlocking !== g.unlocking || x.opCost !== g.opCost || !x.accepted) throw new Error(`${vname} ${pname} tx${t} in${i}: unl ${x.unlocking}/${g.unlocking} op ${x.opCost}/${g.opCost} acc ${x.accepted}`); });
    });
    // 2. the node build: 2tx with the node's category
    // programA caches by plan shape, not by thread category: a distinct (ignored) gen option keys the node build
    let plan = planG, sp = spG; const GO = pname === '2tx' ? {gen: {nodeCategory: catHex}} : {};
    if (pname === '2tx') {
      plan = {...planG, thread: {category: NODECAT}};
      sp = spendA(vk, plan, proof, pis, outs, GO);
      if (Buffer.compare(Buffer.from(sp.pg.redeem), Buffer.from(spG.pg.redeem)) === 0) throw new Error('node build reused the graded program');
      if (sp.pg.redeem.length !== spG.pg.redeem.length || sp.pg.defineBytes !== spG.pg.defineBytes) throw new Error('node category changed the program size');
    }
    const defineBytes = sp.pg.defineBytes;
    const wls = [];
    const libs = sp.txs.map((tx) => t8lib(tx, plan, defineBytes));
    sp.txs.forEach((tx, t) => {
      if (tx.txBytes !== EXPECT_BYTES[pname][t]) throw new Error(`${vname} ${pname} node build tx${t}: ${tx.txBytes} B`);
      const l = libs[t]; if (!l.cons || !l.std) throw new Error(`${vname} ${pname} node build tx${t}: Track 8 libauth rejects: ${l.consErr}`);
      const g = row.txsDetail[t].detail; const opDiff = l.perInput.filter((x, i) => x.opStd !== g[i].opCost).length;
      wls.push({id: `t8-${pname}-${vname}:valid-tx${t}`, group: `t8-${pname}-${vname}`, kind: 'valid', description: `valid tx${t}`, expect: 'accept', defBytes: defineBytes,
        chainIndex: t, chainLength: sp.txs.length, t8: {...l, opStdDiffVsGradeA: opDiff, txBytes: tx.txBytes,
          gradedTxSha16: h16(Buffer.from(spG.txs[t].transaction.inputs.map((x) => hex(x.unlockingBytecode)).join('') + hex(spG.txs[t].sourceOutputs[0].lockingBytecode)))},
        txs: [txJ(tx, t, true)]});
    });
    // 3. reject sample (test-a.mjs families), statements in --rej
    let nrej = 0;
    if (REJ.has(sIdx)) {
      const nc = plan.nc, FIN = nc + 1, Q0 = nc + 2, T = plan.txs.length;
      const hIdx = (k) => ['ROOTS', 'OOD', 'BPOW', 'FROOTS', 'CPOW', 'QPOW', 'NF', 'CTXW'].indexOf(k);
      const m = (fn) => (w) => { const x = cloneWit(w); fn(x); return x; };
      const C = [];
      const add = (family, nm, o) => C.push({family, nm, ...o});
      // prover tamper cases (S3 gen-cases families), first of each family with unchanged public values and a well-formed proof
      const cf = `${casesDir}/${vname}.json`;
      if (existsSync(cf)) {
        const cv = readVector(cf);
        if (cv.proof_hex !== v.proof_hex) throw new Error(`${cf}: another proof`);
        for (const fam of ['cap', 'ood', 'random', 'pow', 'final', 'row', 'salt', 'sibling', 'fri_value']) {
          const t = (cv.tampered ?? []).find((x) => x.family === fam && !x.public_values && x.expect !== true);
          if (t) add(`tampered:${fam}`, t.name, {buf: applyTamper(v.proof_hex, t)});
        }
        { const t = (cv.tampered ?? []).find((x) => x.family === 'statement' && x.public_values && x.public_values.flat().slice(0, 4).every((y, k) => BigInt(y) === pis[k]) && x.public_values.flat().slice(8).every((y, k) => BigInt(y) === pis[8 + k]));
          if (t) add('tampered:statement', t.name, {pv: t.public_values.flat().map(BigInt)}); }
      }
      add('tx', 'output value - 1 sat (CTX differs)', {outs: altOutputs(outs)});
      { const r = [...pis]; r[3] = (r[3] + 1n) % P; add('root', 'script ROOT[3] + 1', {pv: r}); }
      add('constants', 'FIN: TBL byte 0 flipped', {mutate: m((x) => { x[0][FIN][1] = flip(x[0][FIN][1], 0); })});
      add('constants', 'CODE: ACC_1 + 1 and ACC_2 compensated (HEAD sum unchanged)', {mutate: (w, enc) => {
        const F = vk.F, tt = enc.t; const x = cloneWit(w);
        const rd = (b) => [0, 1, 2].map((k) => b.readBigUInt64LE(8 * k));
        const wr = (a) => Buffer.concat(a.map((y) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(y); return b; }));
        const a1 = rd(x[0][1][1]), a2 = rd(x[0][2][1]); const e = BigInt(vk.C - plan.parts[0][1]); const d = F.lift(1n);
        x[0][1][1] = wr(F.add(a1, d)); x[0][2][1] = wr(F.sub(a2, F.mul(d, F.pow(tt.alpha, e)))); return x; }});
      add('constants', 'HEAD: NF lane 0 byte 0 flipped', {mutate: m((x) => { for (const tx of x) tx[0][hIdx('NF')] = flip(tx[0][hIdx('NF')], 0); })});
      add('input', 'HEAD: OOD byte 100 flipped', {mutate: m((x) => { x[0][0][hIdx('OOD')] = flip(x[0][0][hIdx('OOD')], 100); })});
      const hintOff = vk.blob.total - 8;
      add('input', 'QRY: hint T + 1', {mutate: m((x) => { const b = Buffer.from(x[0][Q0][0]); b.writeBigUInt64LE((b.readBigUInt64LE(hintOff) + 1n) % P, hintOff); x[0][Q0][0] = b; })});
      add('input', 'QRY: path byte (input tree) flipped', {mutate: m((x) => { x[0][Q0][1] = flip(x[0][Q0][1], 100); })});
      add('input', 'QRY: last query (L, path) missing', {mutate: m((x) => { x[0][Q0] = x[0][Q0].slice(0, -2); })});
      add('graph', 'CODE 1: code blob byte flipped', {mutate: m((x) => { x[0][1][0] = flip(x[0][1][0], 500); })});
      add('graph', 'two QRY inputs swapped (order)', {txMutate: (txs) => { const tx = txs[0]; const i = tx.transaction.inputs; [i[Q0], i[Q0 + 1]] = [i[Q0 + 1], i[Q0]]; [tx.sourceOutputs[Q0], tx.sourceOutputs[Q0 + 1]] = [tx.sourceOutputs[Q0 + 1], tx.sourceOutputs[Q0]]; return txs; }});
      add('graph', 'one input with another locking (R + one byte)', {txMutate: (txs) => { const so = txs[0].sourceOutputs; so[Q0] = {...so[Q0], lockingBytecode: Uint8Array.from([...so[Q0].lockingBytecode, 0x61])}; return txs; }});
      { const nb = `${vname.replace(/-(\d+)-Z128_cap5$/, (_, i) => `-${(+i + 1) % 24}-Z128_cap5`)}`; const p2 = `${f.split('/').slice(0, -1).join('/')}/${nb}.json`;
        if (existsSync(p2)) { const ov = readVector(p2), op = ov.public_values.flat().map(BigInt);
          const ow = () => spendA(vk, plan, Buffer.from(ov.proof_hex, 'hex'), op, outputsOf(ov), GO).wit;
          add('mix', `one QRY input from another statement (${nb})`, {mutate: (w) => { const x = cloneWit(w), y = ow(); x[0][Q0 + 1] = y[0][Q0 + 1]; return x; }});
          if (T > 1) add('mix', `transaction 1 (all inputs) from another statement, the NFT of this proof (replay)`, {mutate: (w) => { const x = cloneWit(w), y = ow(); x[1] = y[1]; return x; }}); } }
      if (T > 1) {
        const tok = (cap, commit) => ({amount: 0n, category: Uint8Array.from(plan.thread.category).reverse(), nft: {capability: cap, commitment: Uint8Array.from(commit)}});
        add('thread', 'tx1: spends an NFT minted for another proof (commitment of another G)', {txMutate: (txs) => { const so = txs[1].sourceOutputs; so[0] = {...so[0], token: tok('none', threadCommit(sha(Buffer.from('another proof')), 1))}; return txs; }});
        add('thread', 'tx1: input 0 NFT is mutable', {txMutate: (txs) => { const so = txs[1].sourceOutputs; so[0] = {...so[0], token: tok('mutable', so[0].token.nft.commitment)}; return txs; }});
        add('thread', 'tx1: input 0 without the NFT', {txMutate: (txs) => { const so = txs[1].sourceOutputs; const {token, ...rest} = so[0]; void token; so[0] = rest; return txs; }});
        add('thread', 'tx1: a QRY input of tx0 (queries 0-2) instead of its own', {mutate: m((x) => { x[1][Q0] = x[0][Q0]; })});
        add('thread', 'tx0: baton not returned (output 0 is the NFT only)', {txMutate: (txs) => { txs[0].transaction.outputs.shift(); return txs; }});
        add('thread', 'tx0: thread NFT minted mutable', {txMutate: (txs) => { const o = txs[0].transaction.outputs; o[1] = {...o[1], token: tok('mutable', o[1].token.nft.commitment)}; return txs; }});
      }
      for (const c of C) {
        const r = spendA(vk, plan, c.buf ?? proof, c.pv ?? pis, c.outs ?? outs, GO, c.mutate);
        // test-a.mjs: a malformed proof (truncated, trailing bytes, or leftover multiproof siblings under the valid
        // transcript) is an encoder-only case, not a node test; leftovers under another transcript are ordinary rejects
        if (r.enc.malformed && (/truncated|trailing/.test(r.enc.malformed) || r.enc.G.equals(sp.enc.G)) && !c.mutate && !c.txMutate) { say(`skip ${c.nm}: encoder-only (${r.enc.malformed})`); continue; }
        let txs = r.txs; if (c.txMutate) txs = c.txMutate(cloneTxs(txs)) ?? txs;
        // the first transaction with an input that Track 8's consensus VM rejects
        const t = txs.findIndex((tx) => verifyTxA(tx, 'bchCons') !== true);
        if (t < 0) { say(`WARN ${vname} ${pname} ${c.nm}: Track 8 libauth accepts every transaction; not exported`); continue; }
        const tx = txs[t]; const l = t8lib(tx, plan, defineBytes);
        const rejIn = l.perInput.findIndex((x) => !x.consOk);
        wls.push({id: `t8-${pname}-${vname}:${c.family}:${c.nm}`, group: `t8-${pname}-${vname}`, kind: c.family.split(':')[0] === 'tampered' ? 'tampered' : 'manipulation', description: `${c.family}: ${c.nm} (tx${t})`,
          expect: 'reject', defBytes: defineBytes, t8: {cons: false, consErr: l.consErr, rejectingInput: rejIn, rejectingRole: rejIn >= 0 ? l.perInput[rejIn].role : 'whole-tx', tx: t, txBytes: tx.txBytes}, txs: [txJ(tx, t, false)]});
        nrej++;
      }
    }
    const out = `${outDir}/t8-${pname}-${vname}.json`;
    writeFileSync(out, JSON.stringify({vector: vname, plan: pname, transactions: sp.txs.length, txBytes: sp.txs.map((x) => x.txBytes), defBytes: defineBytes, redeemBytes: sp.pg.redeem.length,
      category: pname === '2tx' ? catHex : null, workloads: wls}) + '\n');
    say(`${vname} ${pname}: ${sp.txs.map((x) => x.txBytes).join(' + ')} B (= grade-a), def ${defineBytes}, max BCHN-adj ${Math.max(...libs.flatMap((l) => l.perInput.map((x) => x.bchnAdj / x.budget))).toFixed(4)}, ${nrej} rejects -> ${out}`);
  }
}
writeFileSync(`${outDir}/export-t8.log`, log.join('\n') + '\n');
