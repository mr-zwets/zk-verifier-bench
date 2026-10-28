import {readFileSync} from 'node:fs';
import {hexToBin, decodeAuthenticationInstructions, encodeAuthenticationInstruction} from '@bitauth/libauth';
const v = JSON.parse(readFileSync(process.argv[2], 'utf8')); const ins = decodeAuthenticationInstructions(hexToBin(v.lockingOK));
const [a, b] = process.argv[3].split(':').map(Number); const h = new Map();
for (let i = a; i <= Math.min(b, ins.length - 1); i++) { const k = ins[i].data ? 'push' + (ins[i].data.length >= 20 ? '>=20' : '<20') : ins[i].opcode.toString(16); const n = encodeAuthenticationInstruction(ins[i]).length; const e = h.get(k) ?? [0, 0]; e[0]++; e[1] += n; h.set(k, e); }
console.log([...h].sort((x, y) => y[1][1] - x[1][1]).map(([k, [c, n]]) => `${k}:${c}x/${n}B`).join(' '));
