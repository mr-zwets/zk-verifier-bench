// node-check runner: replays research verifier transactions on a stock BCHN v29.1.0 regtest node, reusing the
// Track 1 rig (research/opcost-timing/bchn/rig.ts: Rpc, Chain block building, Verify-line timing method).
// Extensions over run.ts: workloads of one or more transactions whose source outputs may carry CashTokens (an NFT
// faucet: a minting baton of one category, created by a genesis that spends coinbase(height 1):0, so its category is
// known before the node starts), per-input op-cost on both libauth modes plus the exporter's OP_DEFINE body bytes, and a
// policy mode for a node with acceptnonstdtxn=0.
//
//   npx tsx nc.ts category                         -> the faucet category (internal byte order, hex)
//   npx tsx nc.ts timing --node NAME --src json:F [--src builtin:sound-native] [--reps 11] [--filter RE] --out F.jsonl
//   npx tsx nc.ts policy --node NAME --src json:F ... --out F.jsonl      (node started with POLICY=1, see node.sh)
//
// json: format (export-plonk.mjs / export-stark.mjs): {workloads: [{id, group, kind, expect, expectLibauth?, defBytes,
//   txs: [{label, version, locktime, inputs: [{source: {lockingHex, valueSatoshis, token?}, unlockingHex, sequenceNumber,
//   fromTx?: {tx, vout}}], outputs: [{lockingHex, valueSatoshis, token?}]}]}]}; token: {categoryHex (libauth order),
//   amount, nft?: {capability, commitmentHex}}. Every workload here holds one transaction; in policy mode, fromTx
//   {tx: j, vout} spends output vout of the group's chain transaction j (the valid workload with chainIndex j) instead
//   of a funded output, so multi-transaction plans are replayed as the real chain.
import { appendFileSync, readFileSync, statSync, openSync, readSync, closeSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { binToHex, createVirtualMachineBch2026, encodeTransaction, hexToBin, sha256 } from '@bitauth/libauth';
import { Chain, Rpc, txidInternal, type Workload as RigWorkload } from '../opcost-timing/bchn/rig.js';
import { soundNative } from '../opcost-timing/bchn/workloads.js';

type Tok = { amount: bigint; category: Uint8Array; nft?: { capability: 'none' | 'mutable' | 'minting'; commitment: Uint8Array } };
interface Out { locking: Uint8Array; value: bigint; token?: Tok }
interface In { source: Out; unlocking: Uint8Array; sequenceNumber: number; fromTx?: { tx: number; vout: number } }
interface Wl { id: string; group: string; kind: string; expect: 'accept' | 'reject'; expectLibauth?: 'accept' | 'reject'; defBytes: number; chainIndex?: number; description: string;
  tx: { version: number; locktime: number; inputs: In[]; outputs: Out[] } }

const rev = (b: Uint8Array) => Uint8Array.from(b).reverse();
const OP_1 = Uint8Array.of(0x51);
const tokOf = (t: any): Tok | undefined => t && { amount: BigInt(t.amount ?? 0), category: hexToBin(t.categoryHex), ...(t.nft ? { nft: { capability: t.nft.capability, commitment: hexToBin(t.nft.commitmentHex) } } : {}) };
const outOf = (o: any): Out => ({ locking: hexToBin(o.lockingHex), value: BigInt(o.valueSatoshis ?? 0), ...(o.token ? { token: tokOf(o.token) } : {}) });
const fromJson = (w: any): Wl => {
  if (w.txs.length !== 1) throw new Error(`${w.id}: one transaction per workload expected`);
  const t = w.txs[0];
  return { id: w.id, group: w.group, kind: w.kind, expect: w.expect, expectLibauth: w.expectLibauth, defBytes: w.defBytes ?? 0, chainIndex: w.chainIndex, description: w.description ?? '',
    tx: { version: t.version ?? 2, locktime: t.locktime ?? 0, inputs: t.inputs.map((i: any) => ({ source: outOf(i.source), unlocking: hexToBin(i.unlockingHex), sequenceNumber: i.sequenceNumber ?? 0, fromTx: i.fromTx })), outputs: t.outputs.map(outOf) } };
};
const fromRig = (w: RigWorkload): Wl => ({ id: w.id, group: w.group ?? 'rig', kind: w.expect === 'accept' ? 'valid' : 'tampered', expect: w.expect, defBytes: 0, description: w.description,
  tx: { version: w.version, locktime: w.locktime, inputs: w.inputs.map((i) => ({ source: { locking: i.sourceLocking, value: i.valueSatoshis }, unlocking: i.unlocking, sequenceNumber: i.sequenceNumber })),
    outputs: w.outputs.map((o) => ({ locking: o.locking, value: o.valueSatoshis })) } });

// ---------------------------------------------------------------- libauth (both modes)
const vmCons = createVirtualMachineBch2026(false), vmStd = createVirtualMachineBch2026(true);
const libTx = (o: Out) => ({ lockingBytecode: o.locking, valueSatoshis: o.value, ...(o.token ? { token: o.token } : {}) });
const toLibauth = (wl: Wl, outpoints: { txid: Uint8Array; vout: number }[]) => ({
  version: wl.tx.version, locktime: wl.tx.locktime,
  inputs: wl.tx.inputs.map((inp, i) => ({ outpointTransactionHash: rev(outpoints[i]!.txid), outpointIndex: outpoints[i]!.vout, sequenceNumber: inp.sequenceNumber, unlockingBytecode: inp.unlocking })),
  outputs: wl.tx.outputs.map(libTx),
});
const libauthCheck = (tx: any, sourceOutputs: any[]) => {
  const res = (vm: typeof vmCons) => { const v = vm.verify({ transaction: tx, sourceOutputs } as any);
    const per = tx.inputs.map((_: any, i: number) => { const st = vm.evaluate({ inputIndex: i, sourceOutputs, transaction: tx } as any); return { op: st.metrics.operationCost, err: st.error }; });
    return { ok: v === true, error: v === true ? undefined : String(v).slice(0, 200), per }; };
  return { cons: res(vmCons), std: res(vmStd) };
};

// ---------------------------------------------------------------- faucet + funding
const CAT_HEIGHT = 1;
const faucetCategoryInternal = (chain: Chain) => txidInternal(chain.coinbase(CAT_HEIGHT));
class Funder {
  faucet?: { txid: Uint8Array; vout: number; value: bigint; token: Tok };
  constructor(public chain: Chain) {}
  async genesis() {
    const cat = faucetCategoryInternal(this.chain);
    const cb = this.chain.pool.find((u) => u.cbHeight === CAT_HEIGHT)!;
    this.chain.pool = this.chain.pool.filter((u) => u !== cb);
    const token: Tok = { amount: 0n, category: rev(cat), nft: { capability: 'minting', commitment: new Uint8Array(0) } };
    const tx = { version: 2, locktime: 0, inputs: [{ outpointTransactionHash: rev(cb.txid), outpointIndex: 0, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) }],
      outputs: [{ lockingBytecode: OP_1, valueSatoshis: 1_000_000n, token }, { lockingBytecode: OP_1, valueSatoshis: cb.value - 1_000_000n - 10_000n }] };
    const raw = encodeTransaction(tx as any); const id = txidInternal(raw);
    const s = await this.chain.submit(this.chain.buildBlock([raw]));
    if (!s.accepted) throw new Error('genesis block rejected: ' + s.result);
    this.faucet = { txid: id, vout: 0, value: 1_000_000n, token };
    this.chain.pool.push({ txid: id, vout: 1, value: cb.value - 1_010_000n, locking: OP_1 } as any);
  }
  /** fund outputs (tokens of the faucet category are minted by spending the baton), mined in one block */
  async fund(outs: Out[]) {
    const res: { txid: Uint8Array; vout: number }[] = []; const txs: Uint8Array[] = []; const change: any[] = [];
    let i = 0; let faucet = this.faucet;
    while (i < outs.length) {
      const chunk: Out[] = []; let bytes = 0;
      while (i < outs.length && chunk.length < 20000 && bytes + outs[i]!.locking.length + 120 < 900_000) { chunk.push(outs[i]!); bytes += outs[i]!.locking.length + 120; i++; }
      const needTok = chunk.some((o) => o.token);
      if (needTok) { if (!faucet) throw new Error('token output but no faucet');
        for (const o of chunk) if (o.token && binToHex(o.token.category) !== binToHex(faucet.token.category)) throw new Error('token of a foreign category'); }
      const need = chunk.reduce((s, o) => s + o.value, 0n) + 1_000_000n;
      const { picked, sum } = this.chain.spendable(need);
      const ins = [...(needTok ? [{ outpointTransactionHash: rev(faucet!.txid), outpointIndex: faucet!.vout, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) }] : []),
        ...picked.map((u) => ({ outpointTransactionHash: rev(u.txid), outpointIndex: u.vout, sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(0) }))];
      const chg = sum - need + 1_000_000n - 10_000n;
      const outsTx = [...chunk.map(libTx), { lockingBytecode: OP_1, valueSatoshis: chg }, ...(needTok ? [{ lockingBytecode: OP_1, valueSatoshis: faucet!.value, token: faucet!.token }] : [])];
      const raw = encodeTransaction({ version: 2, locktime: 0, inputs: ins, outputs: outsTx } as any); const id = txidInternal(raw);
      chunk.forEach((_, j) => res.push({ txid: id, vout: j }));
      change.push({ txid: id, vout: chunk.length, value: chg, locking: OP_1 });
      if (needTok) faucet = { ...faucet!, txid: id, vout: chunk.length + 1 };
      txs.push(raw);
    }
    // funding txs that spend the faucet form a chain inside the block: CTOR allows in-block spends in any order
    const s = await this.chain.submit(this.chain.buildBlock(txs));
    if (!s.accepted) throw new Error('funding block rejected: ' + s.result);
    this.chain.pool.push(...change); this.faucet = faucet;
    return res;
  }
}

// ---------------------------------------------------------------- bench log
const parseBench = (log: string) => ({
  verify: [...log.matchAll(/- Verify (\d+) txins: ([\d.]+)ms/g)].map((m) => ({ txins: +m[1]!, ms: +m[2]! })),
  sanity: [...log.matchAll(/- Sanity checks: ([\d.]+)ms/g)].map((m) => +m[1]!),
});
const stats = (xs: number[]) => { const s = [...xs].sort((a, b) => a - b); const n = s.length; const med = n % 2 ? s[(n - 1) / 2]! : (s[n / 2 - 1]! + s[n / 2]!) / 2;
  return { median: med, min: s[0]!, max: s[n - 1]!, n, spreadPct: med > 0 ? ((s[n - 1]! - s[0]!) / med) * 100 : 0 }; };
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const opReport = (wl: Wl, tx: any, so: any[]) => {
  const l = libauthCheck(tx, so);
  const budget = wl.tx.inputs.map((i) => (41 + i.unlocking.length) * 800);
  const per = wl.tx.inputs.map((inp, i) => ({ unlocking: inp.unlocking.length, opCons: l.cons.per[i].op, opStd: l.std.per[i].op, bchnAdjCons: l.cons.per[i].op + wl.defBytes, bchnAdjStd: l.std.per[i].op + wl.defBytes, budget: budget[i]! }));
  const worst = (k: 'opCons' | 'opStd' | 'bchnAdjCons' | 'bchnAdjStd') => Math.max(...per.map((x) => x[k] / x.budget));
  return { libauthCons: l.cons.ok, libauthConsError: l.cons.error, libauthStd: l.std.ok, libauthStdError: l.std.error, perInput: per,
    maxUnlocking: Math.max(...per.map((x) => x.unlocking)), worst: { opCons: worst('opCons'), opStd: worst('opStd'), bchnAdjCons: worst('bchnAdjCons'), bchnAdjStd: worst('bchnAdjStd') },
    opConsTotal: per.reduce((s, x) => s + x.opCons, 0) };
};

// ---------------------------------------------------------------- timing mode (one tx, K copies, as rig.ts runWorkload)
const runTiming = async (chain: Chain, f: Funder, wl: Wl, o: { reps: number; target: number; maxCopies: number; maxBlockBytes: number }) => {
  const fake = wl.tx.inputs.map((_, i) => ({ txid: sha256.hash(Uint8Array.of(i, 7)), vout: i }));
  const probe = toLibauth(wl, fake); const probeRaw = encodeTransaction(probe as any);
  const perTx = Math.max(1, libauthCheck(probe, wl.tx.inputs.map((i) => libTx(i.source))).cons.per.reduce((s: number, x: any) => s + x.op, 0));
  let K = Math.max(1, Math.min(Math.ceil(o.target / perTx), o.maxCopies, Math.floor(o.maxBlockBytes / probeRaw.length)));
  if (wl.expect === 'reject') K = 1;
  const ops = await f.fund(Array.from({ length: K }, () => wl.tx.inputs.map((i) => i.source)).flat());
  const n = wl.tx.inputs.length;
  const copies = Array.from({ length: K }, (_, k) => { const tx = toLibauth(wl, ops.slice(k * n, (k + 1) * n)); return { tx, raw: encodeTransaction(tx as any) }; });
  const so = wl.tx.inputs.map((i) => libTx(i.source));
  const rep = opReport(wl, copies[0]!.tx, so);
  const block = chain.buildBlock(copies.map((c) => c.raw)); const txins = K * n;
  let mempool: unknown;
  if (wl.expect === 'reject' || wl.kind === 'define-probe') { try { mempool = await chain.rpc.call('testmempoolaccept', [binToHex(copies[0]!.raw)]); } catch (e) { mempool = { rpcError: String((e as Error).message) }; } }
  const verifyMs: number[] = []; const repVerdicts: { ok: boolean; error?: string; verifyLine: boolean }[] = [];
  const reps = wl.expect === 'reject' ? Math.min(o.reps, 3) : o.reps;
  for (let r = 0; r < reps; r++) {
    chain.markLog(); let err: string | undefined; let res: unknown;
    try { res = await chain.rpc.call('validateblocktemplate', block.hex); } catch (e) { err = String((e as Error).message); }
    await sleep(5); const b = parseBench(chain.readLog()); const v = b.verify.find((x) => x.txins === txins);
    repVerdicts.push({ ok: err === undefined && res === true, error: err?.slice(0, 200), verifyLine: !!v }); if (v) verifyMs.push(v.ms);
  }
  chain.markLog(); const sub = await chain.submit(block); await sleep(5);
  const subVerify = parseBench(chain.readLog()).verify.find((x) => x.txins === txins)?.ms;
  const expLib = wl.expectLibauth ?? wl.expect;
  const vs = verifyMs.length ? stats(verifyMs) : undefined; const nsPerTx = vs ? (vs.median * 1e6) / K : undefined;
  return { mode: 'timing', id: wl.id, group: wl.group, kind: wl.kind, description: wl.description, expect: wl.expect, expectLibauth: expLib,
    bchnAccepted: sub.accepted, submitResult: sub.result, repVerdicts, mempool,
    asExpected: sub.accepted === (wl.expect === 'accept') && rep.libauthCons === (expLib === 'accept'),
    repsAllAsExpected: repVerdicts.every((v) => v.ok === (wl.expect === 'accept') && v.verifyLine === (wl.expect === 'accept')),
    txBytes: copies[0]!.raw.length, inputs: n, copies: K, blockBytes: block.bytes, defBytes: wl.defBytes, ...rep,
    verifyMs, verifyStats: vs, submitVerifyMs: subVerify, nsPerTx, nsPerOpCost: nsPerTx !== undefined ? nsPerTx / rep.opConsTotal : undefined };
};

// ---------------------------------------------------------------- policy mode (testmempoolaccept, acceptnonstdtxn=0)
const chainTxids = new Map<string, Map<number, { txid: Uint8Array; outputs: Out[] }>>(); // group -> chainIndex -> mined tx
// A tx whose fee is below the default relay fee (the exporters' nominal source values were never meant to pay fees) is
// retried once with every funded source value raised so that the fee is 2 sat/B; if a script introspected input values
// the retry would fail with a script error, which is reported as such.
const tokStr = (t: unknown) => JSON.stringify(t, (_, v) => (typeof v === 'bigint' ? String(v) : v instanceof Uint8Array ? binToHex(v) : v));
const policyAttempt = async (chain: Chain, f: Funder, wl0: Wl, bump: bigint) => {
  let wl = wl0;
  const toFund = wl.tx.inputs.filter((i) => !i.fromTx).map((i) => ({ ...i.source, value: i.source.value + bump }));
  const funded = toFund.length ? await f.fund(toFund) : [];
  let k = 0;
  // chained inputs spend the real output of the earlier chain transaction (its value, e.g. 1,000 sat, replaces the
  // exporter's nominal source value; locking and token must match)
  const sources = wl.tx.inputs.map((i) => { if (!i.fromTx) return { ...i.source, value: i.source.value + bump }; const t = chainTxids.get(wl.group)?.get(i.fromTx.tx); if (!t) throw new Error(`${wl.id}: chain tx ${i.fromTx.tx} not replayed yet`);
    const o = t.outputs[i.fromTx.vout]!; if (binToHex(o.locking) !== binToHex(i.source.locking) || tokStr(o.token) !== tokStr(i.source.token)) throw new Error(`${wl.id}: chained output differs from the source`);
    return o; });
  const outpoints = wl.tx.inputs.map((i) => (!i.fromTx ? funded[k++]! : { txid: chainTxids.get(wl.group)!.get(i.fromTx.tx)!.txid, vout: i.fromTx.vout }));
  wl = { ...wl, tx: { ...wl.tx, inputs: wl.tx.inputs.map((i, j) => ({ ...i, source: sources[j]! })) } };
  const tx = toLibauth(wl, outpoints); const raw = encodeTransaction(tx as any);
  let tma: any; try { tma = (await chain.rpc.call<any[]>('testmempoolaccept', [binToHex(raw)]))[0]; } catch (e) { tma = { rpcError: String((e as Error).message) }; }
  const fee = wl.tx.inputs.reduce((s, i) => s + i.source.value, 0n) - wl.tx.outputs.reduce((s, o) => s + o.value, 0n);
  return { wl, tx, raw, tma, fee, nFunded: toFund.length };
};
const runPolicy = async (chain: Chain, f: Funder, wl0: Wl) => {
  const first = await policyAttempt(chain, f, wl0, 0n);
  let last = first; let retry: any;
  if (first.tma?.allowed !== true && /fee/i.test(first.tma?.['reject-reason'] ?? '') && first.nFunded > 0) {
    const bump = (2n * BigInt(first.raw.length) - first.fee + BigInt(first.nFunded) - 1n) / BigInt(first.nFunded);
    last = await policyAttempt(chain, f, wl0, bump > 0n ? bump : 1n);
    retry = { bumpPerFundedInputSat: String(bump), testmempoolaccept: last.tma, allowed: last.tma?.allowed === true, rejectReason: last.tma?.['reject-reason'], feeSat: String(last.fee), feeRateSatPerB: Number(last.fee) / last.raw.length };
  }
  const wl = last.wl;
  const rep = opReport(wl, last.tx, wl.tx.inputs.map((i) => libTx(i.source)));
  // then mine it (consensus), so that later chain transactions can spend its outputs
  const sub = await chain.submit(chain.buildBlock([last.raw]));
  if (sub.accepted && wl.chainIndex !== undefined) { if (!chainTxids.has(wl.group)) chainTxids.set(wl.group, new Map()); chainTxids.get(wl.group)!.set(wl.chainIndex, { txid: txidInternal(last.raw), outputs: wl.tx.outputs }); }
  return { mode: 'policy', id: wl.id, group: wl.group, kind: wl.kind, expect: wl.expect, chainedInputs: wl.tx.inputs.filter((i) => i.fromTx).length,
    testmempoolaccept: first.tma, allowed: first.tma?.allowed === true, rejectReason: first.tma?.['reject-reason'], feeSat: String(first.fee), feeRateSatPerB: Number(first.fee) / first.raw.length,
    feeRetry: retry, allowedAfterFee: last.tma?.allowed === true,
    minedAfter: sub.accepted, minedResult: sub.result,
    txBytes: last.raw.length, inputs: wl.tx.inputs.length, outputs: wl.tx.outputs.length,
    maxSourceLocking: Math.max(...wl.tx.inputs.map((i) => i.source.locking.length)), ...rep };
};

// ---------------------------------------------------------------- cli
const args = process.argv.slice(2); const mode = args[0];
const opt = (k: string, d?: string) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1]! : d; };
const all = (k: string) => args.flatMap((a, i) => (a === k ? [args[i + 1]!] : []));
const DIR = process.env.OPCOST_DIR ?? '/home/mrzwets/BCH-projects/verifier.cash/work/node-check';
const load = (src: string): Wl[] => {
  if (src === 'builtin:sound-native') return soundNative().map(fromRig);
  if (src.startsWith('json:')) return JSON.parse(readFileSync(src.slice(5), 'utf8')).workloads.map(fromJson);
  throw new Error('unknown source ' + src);
};
const main = async () => {
  if (mode === 'category') { const c = new Chain(null as any, ''); console.log(binToHex(faucetCategoryInternal(c))); return; }
  const name = opt('--node')!; const out = opt('--out')!;
  const c = +execFileSync('sh', ['-c', `printf '%s' '${name}' | cksum | cut -d' ' -f1`]).toString().trim();
  const datadir = `${DIR}/bchn-${name}`;
  const chain = new Chain(new Rpc(datadir, 39300 + (c % 500) * 2), `${datadir}/regtest/debug.log`);
  await chain.init(); if (chain.height !== 0) throw new Error('fresh node expected');
  await chain.mine(220);
  const f = new Funder(chain); await f.genesis();
  const filter = opt('--filter') ? new RegExp(opt('--filter')!) : undefined;
  let wls = all('--src').flatMap(load).filter((w) => !filter || filter.test(w.id));
  // policy: every consensus-valid workload (valid txs and the DEFINE probes that libauth consensus accepts)
  if (mode === 'policy') wls = wls.filter((w) => w.expect === 'accept' || (w.kind === 'define-probe' && w.expectLibauth === 'accept'));
  console.error(`${wls.length} workloads (${mode})`);
  for (const wl of wls) {
    try {
      const r = mode === 'timing'
        ? await runTiming(chain, f, wl, { reps: +opt('--reps', '11')!, target: +opt('--target-opcost', '2e8')!, maxCopies: +opt('--max-copies', '2000')!, maxBlockBytes: +opt('--max-block-bytes', '8000000')! })
        : await runPolicy(chain, f, wl);
      appendFileSync(out, JSON.stringify(r, (_, v) => (typeof v === 'bigint' ? String(v) : v)) + '\n');
      if (mode === 'timing') { const t = r as any; console.error(`${t.asExpected ? 'ok ' : 'BAD'} ${wl.id} K=${t.copies} verify=${t.verifyStats?.median}ms ${t.bchnAccepted ? 'accepted' : 'rejected:' + t.submitResult} lib=${t.libauthCons}`); }
      else { const p = r as any; console.error(`${p.allowed ? 'ALLOWED ' : 'REJECTED'} ${wl.id} ${p.rejectReason ?? ''} mined=${p.minedAfter}`); }
    } catch (e) {
      appendFileSync(out, JSON.stringify({ mode, id: wl.id, group: wl.group, error: String((e as Error).message) }) + '\n');
      console.error(`ERR ${wl.id}: ${(e as Error).message}`);
    }
  }
};
main().catch((e) => { console.error(e); process.exit(1); });
void statSync; void openSync; void readSync; void closeSync;
