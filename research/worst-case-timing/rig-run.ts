// Driver for the worst-case kernels on stock BCHN, using Track 1's rig unchanged (research/opcost-timing/bchn/rig.ts:
// Chain, runWorkload, instantiate, fromVmb). Nodes are started and stopped with research/node-check/node.sh.
//   npx tsx rig-run.ts timing --node NAME --src json:F [--src vmb:F@accept] [--filter RE] [--reps 11] --out F.jsonl
//   npx tsx rig-run.ts policy --node NAME --src json:F ... --out F.jsonl     (node started with POLICY=1)
// json: rig format (gen.ts toRig): inputs may carry `resign`: [{rawHex} | {alg:'ecdsa'|'schnorr', keyHex, hashType}];
// the rig then builds the unlocking from these pushes and signs each input over its real outpoint (rig.ts signInputs).
import { appendFileSync, readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { binToHex, hexToBin } from '@bitauth/libauth';
import { Chain, Rpc, fromJson, fromVmb, instantiate, runWorkload, type Workload } from '../opcost-timing/bchn/rig.js';

const args = process.argv.slice(2); const mode = args[0];
const opt = (k: string, d?: string) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1]! : d; };
const all = (k: string) => args.flatMap((a, i) => (a === k ? [args[i + 1]!] : []));
const DIR = process.env.OPCOST_DIR ?? '/home/mrzwets/BCH-projects/verifier.cash/work/worst-case-timing';

const fromJsonResign = (w: any): Workload => {
  const wl = fromJson(w);
  w.inputs.forEach((i: any, k: number) => {
    if (!i.resign) return;
    (wl.inputs[k] as any).resign = i.resign.map((p: any) => ('rawHex' in p ? { raw: hexToBin(p.rawHex) } : { alg: p.alg, key: hexToBin(p.keyHex), hashType: p.hashType }));
  });
  return wl;
};
const load = (src: string): Workload[] => {
  if (src.startsWith('json:')) return JSON.parse(readFileSync(src.slice(5), 'utf8')).workloads.map(fromJsonResign);
  if (src.startsWith('vmb:')) {
    const [file, exp] = src.slice(4).split('@');
    const vs = JSON.parse(readFileSync(file!, 'utf8')) as any[][];
    return vs.flatMap((v) => { const w = fromVmb(v, (exp as any) ?? 'accept', 'vmb'); return typeof w === 'string' ? [] : [w]; });
  }
  throw new Error('unknown source ' + src);
};

const main = async () => {
  const name = opt('--node')!; const out = opt('--out')!;
  const c = +execFileSync('sh', ['-c', `printf '%s' '${name}' | cksum | cut -d' ' -f1`]).toString().trim();
  const datadir = `${DIR}/bchn-${name}`;
  const chain = new Chain(new Rpc(datadir, 39300 + (c % 500) * 2), `${datadir}/regtest/debug.log`);
  await chain.init(); if (chain.height !== 0) throw new Error('fresh node expected');
  await chain.mine(220);
  const filter = opt('--filter') ? new RegExp(opt('--filter')!) : undefined;
  const wls = all('--src').flatMap(load).filter((w) => !filter || filter.test(w.id));
  console.error(`${wls.length} workloads (${mode})`);
  for (const wl of wls) {
    try {
      if (mode === 'timing') {
        const r = await runWorkload(chain, wl, { reps: +opt('--reps', '11')!, targetOpCost: +opt('--target-opcost', '2e8')!, maxCopies: +opt('--max-copies', '2000')!, maxBlockBytes: +opt('--max-block-bytes', '8000000')! });
        appendFileSync(out, JSON.stringify(r) + '\n');
        console.error(`${r.asExpected ? 'ok ' : 'BAD'} ${wl.id} K=${r.copies} verify=${r.verifyStats?.median}ms ns/op=${r.nsPerOpCost?.toFixed(3)} ${r.bchnAccepted ? 'accepted' : 'rejected:' + r.submitResult}`);
      } else if (mode === 'policy') {
        // fund the inputs (mined), sign over the real outpoints, testmempoolaccept on a POLICY=1 node; inputs carry
        // 100,000 sat each and the only output is a 0-value OP_RETURN, so the fee is >= 1 sat/B for every workload here
        const ops = await chain.fund(wl.inputs.map((i) => ({ locking: i.sourceLocking, value: i.valueSatoshis })));
        const inst = instantiate(wl, ops);
        let tma: any; try { tma = (await chain.rpc.call<any[]>('testmempoolaccept', [binToHex(inst.raw)]))[0]; } catch (e) { tma = { rpcError: String((e as Error).message) }; }
        const r = { mode, id: wl.id, group: wl.group, txBytes: inst.raw.length, inputs: wl.inputs.length, maxUnlocking: Math.max(...inst.tx.inputs.map((i: any) => i.unlockingBytecode.length)),
          maxLocking: Math.max(...wl.inputs.map((i) => i.sourceLocking.length)), testmempoolaccept: tma, allowed: tma?.allowed === true, rejectReason: tma?.['reject-reason'] };
        appendFileSync(out, JSON.stringify(r) + '\n');
        console.error(`${r.allowed ? 'ALLOWED ' : 'REJECTED'} ${wl.id} ${r.rejectReason ?? ''}`);
      } else throw new Error('mode ' + mode);
    } catch (e) {
      appendFileSync(out, JSON.stringify({ mode, id: wl.id, error: String((e as Error).message) }) + '\n');
      console.error(`ERR ${wl.id}: ${(e as Error).message}`);
    }
  }
};
main().catch((e) => { console.error(e); process.exit(1); });
