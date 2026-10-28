// Run every kernel file (or the ones named on the command line) and write results/<file>.json plus a table.
// usage: node run.mjs [k-field k-hash ...]   (TRIALS=n overrides the per-kernel trial count)
import {writeFileSync, mkdirSync} from 'node:fs';
import {measure, runCase} from './lib/measure.mjs';

const files = process.argv.slice(2).length ? process.argv.slice(2) : ['k-hash', 'k-field', 'k-gf128', 'k-blake2s', 'k-rpo', 'k-tip5', 'k-stark'];
// calibration: an empty kernel measures 0
const cal = runCase({inputs: [Uint8Array.of(5)], body: new Uint8Array(0), outputs: [{num: 5n}]});
if (cal.opStd !== 0 || cal.instr !== 0) throw new Error('calibration failed ' + JSON.stringify(cal));
mkdirSync(new URL('./results/', import.meta.url), {recursive: true});
const fmt = (a) => (a.min === a.max ? `${Math.round(a.min)}` : `${Math.round(a.min)}–${Math.round(a.max)} (mean ${Math.round(a.mean)})`);
for (const f of files) {
  const ks = (await import(`./${f}.mjs`)).default;
  const rows = [];
  for (const k of ks) {
    const t0 = Date.now();
    const r = measure(k.name, k.build, {trials: Number(process.env.TRIALS ?? k.trials ?? 16)});
    rows.push({id: k.id, group: k.group, notes: k.notes, extra: k.extra, ...r});
    console.log(`${k.id.padEnd(5)} ${k.name.padEnd(90).slice(0, 90)} std ${fmt(r.opStd).padEnd(28)} cons ${fmt(r.opCons).padEnd(12)} it ${fmt(r.iters).padEnd(6)} B ${fmt(r.bodyBytes)}${r.defBytes ? '+def ' + r.defBytes : ''} real:${r.real.join('|')} (${Date.now() - t0} ms)`);
  }
  writeFileSync(new URL(`./results/${f}.json`, import.meta.url), JSON.stringify(rows, null, 1) + '\n');
}
