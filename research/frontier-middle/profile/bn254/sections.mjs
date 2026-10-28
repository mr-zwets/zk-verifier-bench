// Frame-ip section sums: node sections.mjs <out.json> <frameName> <a:b=label,...>  (ip ranges inclusive, +1 shift for call returns)
import {readFileSync} from 'node:fs';
const o = JSON.parse(readFileSync(process.argv[2], 'utf8')); const fr = process.argv[3];
const ranges = process.argv[4].split('|').map((x) => { const [r, l] = x.split('='); const [a, b] = r.split(':').map(Number); return {a, b, l, c: 0}; });
let tot = 0, other = 0;
for (const [f, ip, c] of o.frameIp) { if (f !== fr) continue; tot += c; const r = ranges.find((r) => ip >= r.a && ip <= r.b); if (r) r.c += c; else other += c; }
for (const r of ranges) console.log(r.l.padEnd(30), (r.c / 1e6).toFixed(3) + 'M');
console.log('other'.padEnd(30), (other / 1e6).toFixed(3) + 'M', 'frame total', (tot / 1e6).toFixed(3) + 'M');
