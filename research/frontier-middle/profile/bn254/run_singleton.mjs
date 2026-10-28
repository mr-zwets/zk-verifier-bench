// Profile a single-input p2s singleton from the bench vectors: node run_singleton.mjs <vectors.json> [artifact.json] [unlockingKey]
import {readFileSync, writeFileSync} from 'node:fs';
import {hexToBin, createTestAuthenticationProgramBch, decodeAuthenticationInstructions, encodeAuthenticationInstruction, binToHex} from '@bitauth/libauth';
import {makeTracedVm, top, M} from './trace.mjs';
const v = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const art = process.argv[3] && process.argv[3] !== '-' ? JSON.parse(readFileSync(process.argv[3], 'utf8')) : null;
const key = process.argv[4] ?? 'unlocking';
const locking = hexToBin(v.lockingOK), unlocking = hexToBin(v[key]);
const {vm, P} = makeTracedVm('loose');
const t = Date.now();
const st = vm.evaluate(createTestAuthenticationProgramBch({lockingBytecode: locking, unlockingBytecode: unlocking, valueSatoshis: 1000n}));
console.log('ms', Date.now() - t, 'err', st.error, 'stack', st.stack.length, 'libauth opCost', st.metrics.operationCost, 'traced', P.total, 'instr', P.instr, 'arith', P.arith, 'pushed', P.pushed);
// static: defined functions
const ins = decodeAuthenticationInstructions(locking);
const defs = []; let mainStart = 0, off = 0;
for (let i = 0; i < ins.length; i++) {
  const n = encodeAuthenticationInstruction(ins[i]).length;
  if (ins[i].opcode === 0x89) { const body = ins[i - 2].data; const id = ins[i - 1].data ? binToHex(ins[i - 1].data) : ins[i - 1].opcode; defs.push({id, bodyLen: body.length}); mainStart = i + 1; }
  off += n;
}
const defBytes = ins.slice(0, mainStart).reduce((s, x) => s + encodeAuthenticationInstruction(x).length, 0);
console.log('locking', locking.length, 'unlocking', unlocking.length, 'defs', defs.length, 'define section bytes', defBytes, 'main', locking.length - defBytes, 'main instrs', ins.length - mainStart);
const names = new Map();
if (art) for (const f of art.debug.functions) if (f.id !== undefined) names.set('f' + binToHex(Uint8Array.from(f.id === 0 ? [] : [f.id])), f.name);
// map numeric pushes: OP_0 -> '' ; OP_1..16 -> 0x51.. pushes are encoded as opcodes; handle via defs list
const idName = (fid) => names.get(fid) ?? fid;
const out = {total: P.total, excl: top(P.excl, 200).map(([k, x]) => [idName(k), x, P.calls.get(k) ?? 0, P.frameLen.get(k)]),
  incl: top(P.incl, 200).map(([k, x]) => [idName(k), x, P.calls.get(k) ?? 0]),
  path: top(P.path, 400).map(([k, x]) => [k.split('>').map(idName).join('>'), x]),
  byOpcode: [...P.byOpcode], instr: P.instr, arith: P.arith, pushed: P.pushed, frameIp: [...P.frameIp].map(([k, x]) => { const [f, ip] = k.split('@'); return [idName(f), Number(ip), x]; }), defs: defs.map((d) => ({...d})), topIp: [...P.topIp].filter(([k]) => k.startsWith('top')).map(([k, x]) => [Number(k.split('@')[1]), x]).sort((a, b) => a[0] - b[0]), mainStart};
writeFileSync(process.argv[5] ?? 'out.json', JSON.stringify(out));
console.log('EXCL'); for (const [k, x, c, l] of out.excl.slice(0, 40)) console.log(' ', String(k).padEnd(16), M(x).padStart(10), 'calls', c, 'len', l);
console.log('INCL'); for (const [k, x, c] of out.incl.slice(0, 40)) console.log(' ', String(k).padEnd(16), M(x).padStart(10), 'calls', c);
