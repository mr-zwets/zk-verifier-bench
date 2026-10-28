// Profile the bench sound-native BLS vectors (bch-2026, budget lifted) per input, by role section x callee.
import { readFileSync, writeFileSync } from 'node:fs';
import { hexToBin, bigIntToVmNumber, binToHex, decodeAuthenticationInstructions, encodeAuthenticationInstruction } from '@bitauth/libauth';
import { buildAll } from './src/bls-native-sound/script.mjs';
import { profile, fmt } from './profiler.mjs';
const v = JSON.parse(readFileSync('/home/mrzwets/BCH-projects/verifier.cash/zk-verifier-bench/src/bch/groth16-bls12381-sound-native-vectors.json', 'utf8'));
const which = process.argv[2] ?? 'valid';
const raw = which === 'worst' ? v.worstCaseProof : v.steps;
const b = buildAll();
const names = { '': 'BLOB' };
for (const [n, f] of b.info.ctx.funcs) if (f.id !== null && f.id !== undefined) names[binToHex(bigIntToVmNumber(BigInt(f.id)))] = n;
for (let i = 0; i < 4; i++) { const k = binToHex(bigIntToVmNumber(BigInt(i + 1))); if (names[k]) console.log('id clash', i + 1, names[k]); names[k] = 'ROLE' + i; }
console.log('blob', b.blob.length, 'R', b.R.length, 'roles', b.info.roles, 'funcs', JSON.stringify(b.info.funcs));
console.log('sections', JSON.stringify(b.info.sections));
const inputs = raw.map((s) => ({ lockingBytecode: hexToBin(s.locking), unlockingBytecode: hexToBin(s.unlocking) }));
console.log('R in vector unlocking:', raw.every((s) => s.unlocking.endsWith(binToHex(b.R))));
const out = [];
for (let i = 0; i < 4; i++) {
  const mk = b.info.marks.filter((m) => m.role === i).sort((x, y) => x.off - y.off);
  const secOf = (off) => { let n = 'start'; for (const m of mk) if (m.off <= off) n = 'after-' + m.name.replace(/^r\d:end:/, ''); return n; };
  const r = profile({ names, intraTx: { index: i, inputs }, segOf: (nm, offs, phase) => {
    const j = nm.indexOf('ROLE' + i);
    if (j < 0) return `${phase === 2 ? 'R+blob' : 'unlocking/p2sh'}|${nm.slice(1, 3).join('>') || '(self)'}`;
    return `${secOf(offs[j])}|${nm.slice(j + 1, j + 3).join('>') || '(self)'}`;
  } });
  const unl = decodeAuthenticationInstructions(inputs[i].unlockingBytecode).map((x) => x.data?.length ?? 0);
  console.log(`== input ${i}: accepted ${r.accepted} ${r.error ?? ''} opCost ${fmt(r.operationCost)} unlocking ${inputs[i].unlockingBytecode.length} pushes ${JSON.stringify(unl)} budget ${fmt((41 + inputs[i].unlockingBytecode.length) * 800)}`);
  const bySec = {}; for (const [k, x] of Object.entries(r.custom)) { const [s, f] = k.split('|'); (bySec[s] ??= {})[f] = x; }
  for (const [s, m] of Object.entries(bySec)) { const t = Object.values(m).reduce((a, c) => a + c, 0); console.log('  ', s.padEnd(24), fmt(t).padStart(11), JSON.stringify(Object.fromEntries(Object.entries(m).sort((a, c) => c[1] - a[1]).filter(([, x]) => x > 20000).map(([k, x]) => [k, fmt(x)])))); }
  console.log('   incl', JSON.stringify(Object.fromEntries(Object.entries(r.incl).filter(([, x]) => x > 20000).map(([k, x]) => [k, `${fmt(x)} /${r.calls[k] ?? ''}`]))));
  const defs = r.defines; console.log('   defines', defs.length, 'body bytes', defs.reduce((a, d) => a + d.bodyLen, 0));
  const { opExcl, timeline, topOff, ...rest } = r; out.push({ input: i, unlockingPushes: unl, ...rest });
}
writeFileSync(`out-native-${which}.json`, JSON.stringify({ info: { roles: b.info.roles, funcs: b.info.funcs, sections: b.info.sections, blob: b.blob.length, R: b.R.length }, inputs: out }, null, 1));
