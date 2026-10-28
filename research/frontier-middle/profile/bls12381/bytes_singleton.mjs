// code-byte accounting for the plain singleton: OP_DEFINE prelude per function, main body, inline ranges
import { readFileSync } from 'node:fs';
import { compileFile } from 'cashc';
import { hexToBin, binToHex, decodeAuthenticationInstructions, encodeAuthenticationInstruction } from '@bitauth/libauth';
const G='/home/mrzwets/BCH-projects/verifier.cash/groth16_cashscript/singleton/bls12-381/';
const art = compileFile(G+'groth16.cash', { optimizeFor:'size', rescheduleStacks:true });
const b = hexToBin(art.debug.bytecode);
const ins = decodeAuthenticationInstructions(b);
let o=0, offs=[]; for (const i of ins){ offs.push(o); o+=encodeAuthenticationInstruction(i).length; }
// prelude: pattern <body> <id> OP_DEFINE
let k=0, prelude=0; const per={};
while (k+2<ins.length && ins[k+2].opcode===0x89) { const len = offs[k+3]-offs[k]; const body=ins[k].data; const idI=ins[k+1]; per[binToHex(idI.data??new Uint8Array([idI.opcode]))]=len; prelude+=len; k+=3; }
console.log('instructions', ins.length, 'prelude instr', k, 'prelude bytes', prelude, 'main bytes', b.length-prelude, 'main instr', ins.length-k);
console.log('inlineRanges', art.debug.inlineRanges);
// interpret ranges as main-instruction indices and as main byte offsets
for (const r of art.debug.inlineRanges.split(';')) { const [s,e,n]=r.split(':'); 
  const asIns = offs[k+ +e] - offs[k+ +s];
  console.log(n, 'if instr idx -> bytes', asIns, '| if byte offsets -> bytes', e-s); }
const fns = art.debug.functions.filter(f=>f.id!==undefined).map(f=>({name:f.name,id:f.id,body:f.bytecode.length/2}));
console.log(JSON.stringify(fns));
console.log(JSON.stringify(art.debug.functions.filter(f=>f.id===undefined).map(f=>({name:f.name,body:f.bytecode.length/2}))));
