import {readFileSync} from 'node:fs';
import {hexToBin, decodeAuthenticationInstructions, encodeAuthenticationInstruction} from '@bitauth/libauth';
const v = JSON.parse(readFileSync(process.argv[2], 'utf8')); const ins = decodeAuthenticationInstructions(hexToBin(v[process.argv[3] ?? 'unlocking'])).reverse(); // args in order
const sizes = ins.map((x) => encodeAuthenticationInstruction(x).length);
const groups = JSON.parse(process.argv[4] ?? '[]'); let i = 0;
for (const [name, n] of groups) { const s = sizes.slice(i, i + n).reduce((a, b) => a + b, 0); console.log(name.padEnd(24), n, 'items', s, 'B'); i += n; }
console.log('rest', sizes.length - i, 'items', sizes.slice(i).reduce((a, b) => a + b, 0), 'B; total', sizes.reduce((a, b) => a + b, 0));
