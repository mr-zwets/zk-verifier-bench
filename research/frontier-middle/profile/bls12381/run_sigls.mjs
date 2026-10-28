// Profile the bench SI-GLS single vector (bch-spec VM, density base lifted) by redeem section x depth-1 function.
import { readFileSync, writeFileSync } from 'node:fs';
import { hexToBin, bigIntToVmNumber, binToHex, createInstructionSetBchSpec, ripemd160, secp256k1, sha1, sha256, decodeAuthenticationInstructions, encodeAuthenticationInstruction } from '@bitauth/libauth';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
const specPath = createRequire(import.meta.url).resolve('@bitauth/libauth').replace(/index\.js$/, 'lib/vm/instruction-sets/bch/spec/bch-spec-consensus.js');
const { ConsensusBchSpec } = await import(pathToFileURL(specPath).href);
import { buildRedeem } from './src/sound-si-gls/script.mjs';
import { profile, fmt } from './profiler.mjs';
const v = JSON.parse(readFileSync('/home/mrzwets/BCH-projects/verifier.cash/zk-verifier-bench/src/bch/groth16-bls12381-sound-si-gls-single-vectors.json', 'utf8'));
const which = process.argv[2] ?? 'valid';
const raw = which === 'worst' ? v.worstCaseProof : v.steps;
const { redeem, info } = buildRedeem();
const names = {}; for (const [n, id] of Object.entries(info.funcIds)) names[binToHex(bigIntToVmNumber(BigInt(id)))] = n;
const NEXT = { 'end:init': 'transcript', 'end:transcript': 'parse+checks', 'end:parse+checks': 'powers', 'end:powers': 'gls-tables', 'end:gls-tables': 'loop-setup', 'end:loop-setup': 'loop:entry', 'end:loop': 'terminal', 'end:terminal': 'quotient', 'end:final': 'cleanup' };
const marks = info.marks.slice().sort((a, b) => a.off - b.off).map((m) => ({ ...m, name: NEXT[m.name] ?? 'loop:' + m.name }));
const secOf = (off) => { let n = 'prologue(OP_DEFINE)'; for (const m of marks) if (m.off <= off) n = m.name; return n; };
const base = createInstructionSetBchSpec(false, { consensus: { ...ConsensusBchSpec, densityControlBaseLength: 1_000_000_000 }, ripemd160, secp256k1, sha1, sha256 });
const inputs = raw.map((s) => ({ lockingBytecode: hexToBin(s.locking), unlockingBytecode: hexToBin(s.unlocking) }));
const r = profile({ base, names, intraTx: { index: 0, inputs },
  segOf: (nm, offs, phase) => phase < 2 ? `unlocking+p2sh|(self)` : `${secOf(offs[0])}|${nm[1] ?? '(self)'}` });
console.log(which, 'accepted', r.accepted, r.error, 'opCost', fmt(r.operationCost), 'attributed', fmt(r.attributed));
// static bytes: redeem sections (marks) and unlocking pushes
const unl = decodeAuthenticationInstructions(inputs[0].unlockingBytecode).map((i) => ({ len: i.data?.length, enc: encodeAuthenticationInstruction(i).length }));
console.log('unlocking pushes', JSON.stringify(unl), 'total', inputs[0].unlockingBytecode.length);
console.log('sections(bytes)', JSON.stringify(info.sections), 'funcs(bytes)', JSON.stringify(info.funcs));
const { opExcl, timeline, topOff, ...rest } = r;
writeFileSync(`out-sigls-${which}.json`, JSON.stringify({ ...rest, info: { sections: info.sections, funcs: info.funcs, prologue: info.prologue } }, null, 1));
const bySec = {}; for (const [k, x] of Object.entries(r.custom)) { const [s, f] = k.split('|'); (bySec[s] ??= {})[f] = x; }
for (const [s, m] of Object.entries(bySec)) { const t = Object.values(m).reduce((a, b) => a + b, 0); console.log(s.padEnd(22), fmt(t).padStart(12), JSON.stringify(Object.fromEntries(Object.entries(m).sort((a,b)=>b[1]-a[1]).map(([k,x])=>[k,fmt(x)])))); }
console.log('incl', JSON.stringify(Object.fromEntries(Object.entries(r.incl).map(([k,x])=>[k,`${fmt(x)} /${r.calls[k]??''}`]))));
console.log('defines', r.defines.length, r.defines.reduce((a, d) => a + d.bodyLen, 0));
