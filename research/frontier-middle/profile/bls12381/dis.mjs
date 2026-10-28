import { readFileSync } from 'node:fs';
import { hexToBin, binToHex, decodeAuthenticationInstructions, encodeAuthenticationInstruction } from '@bitauth/libauth';
const NAMES={0x89:'DEFINE',0x8a:'INVOKE',0x65:'BEGIN',0x66:'UNTIL',0x63:'IF',0x64:'NOTIF',0x67:'ELSE',0x68:'ENDIF',0x69:'VERIFY',0x76:'DUP',0x79:'PICK',0x7a:'ROLL',0x7c:'SWAP',0x75:'DROP',0x6d:'2DROP',0x93:'ADD',0x94:'SUB',0x95:'MUL',0x97:'MOD',0x87:'EQUAL',0x9c:'NUMEQUAL',0x9d:'NUMEQUALVERIFY',0x6c:'FROMALT',0x6b:'TOALT',0x8d:'RSHIFTNUM',0x8c:'LSHIFTNUM'};
const [file, key, from, to] = process.argv.slice(2);
const v = JSON.parse(readFileSync(file,'utf8'));
const b = hexToBin(key.length>40?key:v[key]);
const ins = decodeAuthenticationInstructions(b);
let o=0;
for (const i of ins) { const l=encodeAuthenticationInstruction(i).length; if (o>=+from && o<=+to) console.log(o, i.opcode.toString(16), NAMES[i.opcode]??'', i.data? (i.data.length>16? `<${i.data.length}B>` : binToHex(i.data)):''); o+=l; }
