// main-body timeline: node timeline.mjs <locking hex file|vectors.json> <out.json> [artifact]
import {readFileSync} from 'node:fs';
import {hexToBin, binToHex, decodeAuthenticationInstructions, encodeAuthenticationInstruction} from '@bitauth/libauth';
const v = JSON.parse(readFileSync(process.argv[2], 'utf8')); const o = JSON.parse(readFileSync(process.argv[3], 'utf8'));
const art = process.argv[4] ? JSON.parse(readFileSync(process.argv[4], 'utf8')) : null;
const names = new Map(); if (art) for (const f of art.debug.functions) if (f.id !== undefined) names.set(f.id, f.name);
const ins = decodeAuthenticationInstructions(hexToBin(v.lockingOK));
const cost = new Map(o.topIp);
const num = (x) => x.opcode === 0 ? 0 : x.opcode >= 0x51 && x.opcode <= 0x60 ? x.opcode - 0x50 : x.data ? Number(BigInt('0x' + (binToHex(x.data.slice().reverse()) || '0'))) : null;
let acc = 0, segStart = o.mainStart, segCost = 0, bytes = 0, segBytes = 0;
for (let ip = o.mainStart; ip < ins.length; ip++) {
  const c = cost.get(ip) ?? 0; segCost += c; acc += c; const b = encodeAuthenticationInstruction(ins[ip]).length; segBytes += b;
  if (ins[ip].opcode === 0x8a) { const id = num(ins[ip - 1]); console.log(`ip ${segStart}-${ip} bytes ${segBytes} cost ${(segCost / 1e6).toFixed(3)}M -> ${names.get(id) ?? 'f' + id}`); segStart = ip + 1; segCost = 0; segBytes = 0; }
}
console.log(`tail ip ${segStart}- bytes ${segBytes} cost ${(segCost / 1e6).toFixed(3)}M; total ${(acc / 1e6).toFixed(3)}M`);
