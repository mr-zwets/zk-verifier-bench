import { readFileSync, writeFileSync } from 'node:fs';
import { compileFile, utils } from 'cashc';
import { hexToBin, binToHex, bigIntToVmNumber } from '@bitauth/libauth';
import { profile, fmt } from './profiler.mjs';
import { lineMap } from './srcmap.mjs';
const B='/home/mrzwets/BCH-projects/verifier.cash/zk-verifier-bench/src/bch/';
const G='/home/mrzwets/BCH-projects/verifier.cash/groth16_cashscript/singleton/bls12-381/';
const which = process.argv[2] ?? 'valid';
const v = JSON.parse(readFileSync(B+'groth16-bls12381-singleton-minop-vectors.json','utf8'));
const mp = JSON.parse(readFileSync(B+'groth16-bls12381-singleton-minop-multiproof-vectors.json','utf8'));
const art = compileFile(G+'groth16_minop.cash', { rescheduleStacks: true });
const bc = binToHex(utils.asmToBytecode(art.bytecode));
console.log('compiled==vector locking:', bc === v.lockingOK, v.lockingOK.length/2);
const names = {};
for (const f of art.debug.functions.filter(f=>f.id!==undefined)) names[binToHex(bigIntToVmNumber(BigInt(f.id)))] = f.name;
const inl = art.debug.functions.filter(f=>f.id===undefined).map(f=>f.name);
console.log('defined fns', Object.keys(names).length, 'inlined fns', inl.join(','));
const unl = which==='worst' ? mp.worstCaseProof.unlocking : v.unlocking;
const SRC = readFileSync(G+'groth16_minop.cash','utf8').split('\n');
const lm = lineMap(G+'groth16_minop.cash', { rescheduleStacks: true });
const PRE = 27 * 3; // OP_DEFINE prelude instructions
const catOfLine = (ln) => {
  const t = SRC[ln - 1] ?? '';
  if (ln < 41) return 'input checks (range, curve, twist)';
  if (ln < 62) return 'vk_x GLV 4-scalar Straus (+zInv witness check)';
  if (ln < 413) {
    if (t.includes('fp12MulTorus(')) return 'Miller: c^-1 torus fold (residue)';
    if (t.includes('fp12Sqr(')) return 'Miller: f squaring (fp12Sqr)';
    if (t.includes('pointDouble(')) return 'Miller: B point doubling';
    if (t.includes('pointAdd(')) return 'Miller: B point addition';
    if (t.includes('line(') && t.includes(', Ax, nAy)')) return 'Miller: (-A,B) line evaluation';
    if (t.includes('line(')) return 'Miller: baked (vk_x,gamma)/(C,delta) line evaluation';
    return 'Miller: setup/glue';
  }
  if (ln < 420) return 'G2 subgroup check (psi endpoint)';
  return 'residue terminal check (torus Frobenius + cross product)';
};
const offIdx = new Map(lm.offs.map((o, i) => [o, i]));
const catOfOff = (off) => { const i = offIdx.get(off); if (i === undefined) return 'unknown'; if (i < PRE) return 'OP_DEFINE prelude'; return catOfLine(lm.lines[i]); };
// static bytes per category (main instructions) and big pushes
const statBytes = {}; let bigPush = { n: 0, bytes: 0 }; const bigByCat = {};
lm.ins.forEach((x, i) => { const len = (i + 1 < lm.offs.length ? lm.offs[i + 1] : lm.bc.length) - lm.offs[i]; const c = i < PRE ? 'OP_DEFINE prelude' : catOfLine(lm.lines[i]); statBytes[c] = (statBytes[c] ?? 0) + len; if (i >= PRE && x.data && x.data.length >= 40) { bigPush.n++; bigPush.bytes += len; bigByCat[c] = (bigByCat[c] ?? 0) + len; } });
console.log('static bytes by category', JSON.stringify(statBytes), 'big pushes (>=40B) in main', JSON.stringify(bigPush), JSON.stringify(bigByCat));
const r = profile({ locking: hexToBin(v.lockingOK), unlocking: hexToBin(unl), names, segOf: (nm, offs, phase) => phase === 0 ? 'unlocking (push witnesses)' : catOfOff(offs[0]) });
console.log(which, 'accepted', r.accepted, r.error, 'opCost', fmt(r.operationCost), 'instr', fmt(r.instructions));
const { opExcl, ...rest } = r;
writeFileSync(`out-minop-${which}.json`, JSON.stringify({ ...rest, statBytes, bigPush, bigByCat, fnBytes: art.debug.functions.map(f=>({id:f.id,name:f.name,bytes:f.bytecode?.length/2})) }, null, 1));
console.log('segments:'); { const t = Object.values(r.custom).reduce((a,b)=>a+b,0); for (const [k,x] of Object.entries(r.custom)) console.log('  ', k.padEnd(58), fmt(x).padStart(13), (100*x/t).toFixed(2)+'%'); }
console.log('incl:'); for (const [k,x] of Object.entries(r.incl)) console.log('  ', k.padEnd(20), fmt(x).padStart(14), 'calls', r.calls[k]??'', 'excl', fmt(r.excl[k]??0));
console.log('defines', r.defines.length, 'body bytes', r.defines.reduce((a,d)=>a+d.bodyLen,0));
