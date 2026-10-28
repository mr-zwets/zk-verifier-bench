// timeline of one frame: node ftimeline.mjs <vectors.json> <out.json> <artifact|-> <frameName> [fid number]
import {readFileSync} from 'node:fs';
import {hexToBin, binToHex, decodeAuthenticationInstructions, encodeAuthenticationInstruction} from '@bitauth/libauth';
const v = JSON.parse(readFileSync(process.argv[2], 'utf8')); const o = JSON.parse(readFileSync(process.argv[3], 'utf8'));
const art = process.argv[4] !== '-' ? JSON.parse(readFileSync(process.argv[4], 'utf8')) : null;
const fr = process.argv[5]; const fidNum = process.argv[6];
const names = new Map(); if (art) for (const f of art.debug.functions) if (f.id !== undefined) names.set(f.id, f.name);
const num = (x) => x.opcode === 0 ? 0 : x.opcode >= 0x51 && x.opcode <= 0x60 ? x.opcode - 0x50 : x.data ? Number(BigInt('0x' + (binToHex(x.data.slice().reverse()) || '0'))) : null;
const top = decodeAuthenticationInstructions(hexToBin(v.lockingOK));
let ins = top;
if (fidNum !== undefined) { for (let i = 0; i < top.length; i++) if (top[i].opcode === 0x89 && num(top[i - 1]) === Number(fidNum)) ins = decodeAuthenticationInstructions(top[i - 2].data); }
const cost = new Map(); for (const [f, ip, c] of o.frameIp) if (f === fr) cost.set(ip, (cost.get(ip) ?? 0) + c);
let segStart = 0, segCost = 0, segBytes = 0, acc = 0;
for (let ip = 0; ip <= ins.length; ip++) {
  const c = cost.get(ip) ?? 0; segCost += c; acc += c; if (ip < ins.length) segBytes += encodeAuthenticationInstruction(ins[ip]).length;
  if (ip < ins.length && (ins[ip].opcode === 0x8a || [0x63, 0x64, 0x67, 0x68, 0x65, 0x66].includes(ins[ip].opcode))) {
    const lab = ins[ip].opcode === 0x8a ? '-> ' + (names.get(num(ins[ip - 1])) ?? 'f' + num(ins[ip - 1])) : '[ctl ' + ins[ip].opcode.toString(16) + ']';
    console.log(`ip ${segStart}-${ip} bytes ${segBytes} cost ${(segCost / 1e6).toFixed(3)}M ${lab}`); segStart = ip + 1; segCost = 0; segBytes = 0; }
}
console.log(`tail ${segStart}- bytes ${segBytes} cost ${(segCost / 1e6).toFixed(3)}M total ${(acc / 1e6).toFixed(3)}M (instrs ${ins.length})`);
if (process.env.RANGES) {
  for (const x of process.env.RANGES.split('|')) { const [r, l] = x.split('='); const [a, b] = r.split(':').map(Number); let by = 0, pushData = 0;
    for (let ip = a; ip <= Math.min(b, ins.length - 1); ip++) { const n = encodeAuthenticationInstruction(ins[ip]).length; by += n; if (ins[ip].data && ins[ip].data.length >= 20) pushData += n; }
    console.log('BYTES', l.padEnd(28), by, 'of which >=20B pushes', pushData); }
}
