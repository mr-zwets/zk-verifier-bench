// main-frame section x callee: node xsec.mjs <vectors> <out.json> <artifact> <frame> "a:b=label|..."
import {readFileSync} from 'node:fs';
import {hexToBin, binToHex, decodeAuthenticationInstructions} from '@bitauth/libauth';
const v = JSON.parse(readFileSync(process.argv[2], 'utf8')); const o = JSON.parse(readFileSync(process.argv[3], 'utf8'));
const art = JSON.parse(readFileSync(process.argv[4], 'utf8')); const fr = process.argv[5];
const names = new Map(); for (const f of art.debug.functions) if (f.id !== undefined) names.set(f.id, f.name);
const num = (x) => x.opcode === 0 ? 0 : x.opcode >= 0x51 && x.opcode <= 0x60 ? x.opcode - 0x50 : x.data ? Number(BigInt('0x' + (binToHex(x.data.slice().reverse()) || '0'))) : null;
const ins = decodeAuthenticationInstructions(hexToBin(v.lockingOK));
const ranges = process.argv[6].split('|').map((x) => { const [r, l] = x.split('='); const [a, b] = r.split(':').map(Number); return {a, b, l, m: new Map(), n: new Map()}; });
for (const [f, ip, c] of o.frameIp) { if (f !== fr) continue; const r = ranges.find((r) => ip >= r.a && ip <= r.b); if (!r) continue;
  const k = ip > 0 && ins[ip - 1]?.opcode === 0x8a ? names.get(num(ins[ip - 2])) ?? 'f' + num(ins[ip - 2]) : 'glue'; r.m.set(k, (r.m.get(k) ?? 0) + c); if (k !== 'glue') r.n.set(k, (r.n.get(k) ?? 0) + 1); }
for (const r of ranges) console.log(r.l, [...r.m].sort((a, b) => b[1] - a[1]).map(([k, c]) => `${k}${r.n.get(k) ? '×' + r.n.get(k) : ''} ${(c / 1e6).toFixed(3)}`).join(', '));
