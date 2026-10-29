// Run the Track 5 field kernels with the Track 4 harness and write results/k-field5.json.
// usage: node run.mjs [filter]   (TRIALS=n overrides the per-kernel trial count)
import {writeFileSync, mkdirSync} from 'node:fs';
import {measure, runCase} from '../../../pq-hash/kernels/lib/measure.mjs';

const cal = runCase({inputs: [Uint8Array.of(5)], body: new Uint8Array(0), outputs: [{num: 5n}]});
if (cal.opStd !== 0 || cal.instr !== 0) throw new Error('calibration failed ' + JSON.stringify(cal));
const filter = process.argv[2];
const ks = (await import('./k-field5.mjs')).default.filter((k) => !filter || k.id.startsWith(filter) || k.name.includes(filter));
const fmt = (a) => (a.min === a.max ? `${Math.round(a.min)}` : `${Math.round(a.mean)} (${Math.round(a.min)}–${Math.round(a.max)})`);
const rows = [];
for (const k of ks) {
  const t0 = Date.now();
  const r = measure(k.name, k.build, {trials: Number(process.env.TRIALS ?? k.trials ?? 8)});
  rows.push({id: k.id, group: k.group, notes: k.notes, ...r});
  console.log(`${k.id.padEnd(3)} ${k.name.padEnd(110).slice(0, 110)} std ${fmt(r.opStd).padEnd(26)} instr ${fmt(r.instr).padEnd(8)} B ${fmt(r.bodyBytes)} def ${r.defBytes} real:${r.real.join('|')} (${Date.now() - t0} ms)`);
}
mkdirSync(new URL('./results/', import.meta.url), {recursive: true});
if (!filter) writeFileSync(new URL('./results/k-field5.json', import.meta.url), JSON.stringify(rows, null, 1) + '\n');
