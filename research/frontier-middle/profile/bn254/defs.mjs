// node defs.mjs <vectors.json> <artifact|-> : per OP_DEFINE entry bytes (body push + id + DEFINE)
import {readFileSync} from 'node:fs';
import {hexToBin, binToHex, decodeAuthenticationInstructions, encodeAuthenticationInstruction} from '@bitauth/libauth';
const v = JSON.parse(readFileSync(process.argv[2], 'utf8')); const art = process.argv[3] !== '-' ? JSON.parse(readFileSync(process.argv[3], 'utf8')) : null;
const names = new Map(); if (art) for (const f of art.debug.functions) if (f.id !== undefined) names.set(f.id, f.name);
const num = (x) => x.opcode === 0 ? 0 : x.opcode >= 0x51 && x.opcode <= 0x60 ? x.opcode - 0x50 : x.data ? Number(BigInt('0x' + (binToHex(x.data.slice().reverse()) || '0'))) : null;
const ins = decodeAuthenticationInstructions(hexToBin(v[process.env.KEY ?? 'lockingOK']));
const rows = []; let last = 0; let start = 0;
for (let i = 0; i < ins.length; i++) if (ins[i].opcode === 0x89) {
  const b = ins.slice(start, i + 1).reduce((s, x) => s + encodeAuthenticationInstruction(x).length, 0);
  const id = num(ins[i - 1]); const body = ins[i - 2].data; const bi = decodeAuthenticationInstructions(body);
  const constBytes = bi.filter((x) => x.data && x.data.length >= 20).reduce((s, x) => s + encodeAuthenticationInstruction(x).length, 0);
  rows.push({id, name: names.get(id) ?? 'f' + id, bytes: b, body: body.length, instrs: bi.length, constBytes}); start = i + 1; }
console.log(JSON.stringify(rows));
