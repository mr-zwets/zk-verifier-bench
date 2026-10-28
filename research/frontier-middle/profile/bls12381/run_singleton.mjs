import { readFileSync, writeFileSync } from 'node:fs';
import { compileFile } from 'cashc';
import { hexToBin, binToHex, bigIntToVmNumber } from '@bitauth/libauth';
import { profile, fmt } from './profiler.mjs';
const B='/home/mrzwets/BCH-projects/verifier.cash/zk-verifier-bench/src/bch/';
const G='/home/mrzwets/BCH-projects/verifier.cash/groth16_cashscript/singleton/bls12-381/';
const which = process.argv[2] ?? 'plain';
const file = which==='plain' ? 'groth16-bls12381-singleton-vectors.json' : 'groth16-bls12381-singleton-opcode-optimized-vectors.json';
const v = JSON.parse(readFileSync(B+file,'utf8'));
const opts = { optimizeFor:'size', rescheduleStacks:true }; // opt build kept candidate B (rescheduled compile): ids 0..36 identical, call counts match
const art = compileFile(G+'groth16.cash', opts);
const names = {};
for (const f of art.debug.functions.filter(f=>f.id!==undefined)) names[binToHex(bigIntToVmNumber(BigInt(f.id)))] = f.name;
if (which==='plain') console.log('compiled==vector locking:', art.debug.bytecode === v.lockingOK, v.lockingOK.length/2);
for (let i=37;i<200;i++) { const k=binToHex(bigIntToVmNumber(BigInt(i))); if(!names[k]) names[k]='outl'+i; }
let unl = hexToBin(v.unlocking);
const worst = process.argv[3] === 'worst';
if (worst) { // replace in1, in0 (first two pushes) with dense 254-bit inputs; proof then fails only at the final ==1 check
  const { decodeAuthenticationInstructions, encodeAuthenticationInstructions, encodeDataPush } = await import('@bitauth/libauth');
  const ins = decodeAuthenticationInstructions(unl);
  const W = 28948022309329048855892746252171976963317496166410141009864396001978282409983n;
  const rest = ins.slice(2);
  unl = Uint8Array.from([...encodeDataPush(bigIntToVmNumber(W)), ...encodeDataPush(bigIntToVmNumber(W)), ...encodeAuthenticationInstructions(rest)]);
}
const r = profile({ locking: hexToBin(v.lockingOK), unlocking: unl, names });
console.log(which, 'accepted', r.accepted, r.error, 'opCost', fmt(r.operationCost), 'attributed', fmt(r.attributed), 'instr', fmt(r.instructions));
const { opExcl, ...rest } = r;
writeFileSync(`out-${which}${worst?'-worst':''}.json`, JSON.stringify({ ...rest, bodyBytes: art.debug.functions.filter(f=>f.id!==undefined).map(f=>({id:f.id,name:f.name,bytes:f.bytecode.length/2})) }, null, 1));
console.log('top:'); for (const t of r.top) console.log('  ', t.name, fmt(t.cost));
console.log('incl:'); for (const [k,x] of Object.entries(r.incl)) console.log('  ', k.padEnd(20), fmt(x).padStart(14), 'calls', r.calls[k]??'', 'excl', fmt(r.excl[k]??0));
console.log('defines', r.defines.length, 'body bytes', r.defines.reduce((a,d)=>a+d.bodyLen,0));
