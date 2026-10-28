import { compileFile } from 'cashc';
const G='/home/mrzwets/BCH-projects/verifier.cash/groth16_cashscript/singleton/bls12-381/';
for (const o of [{ optimizeFor: 'size', rescheduleStacks: true },{ optimizeFor: 'size', disableDefSinking: true }]) {
const a = compileFile(G+'groth16.cash', o);
const d=a.debug;
console.log(JSON.stringify(d.inlineRanges)?.slice(0,1500));
console.log(d.functions.map(f=>`${f.id}:${f.name}:${f.bytecode?.length/2}`).join(' '));
}
