// scratch: SI-GLS op-cost by section x function with the generic tracer (consensus + standard)
import {writeFileSync} from 'node:fs';
import {decodeAuthenticationInstructions, encodeAuthenticationInstruction, binToHex} from '@bitauth/libauth';
import {buildRedeem} from './script.mjs';
import {FIXTURES} from './math.mjs';
import {redeem, locking, unlocking} from './transaction.mjs';
import {programOf} from './vm.mjs';
import {makeTracedVm} from '../../../../trace.mjs';
const {info} = buildRedeem(); if (!Buffer.from(buildRedeem().redeem).equals(redeem)) throw new Error('stale');
const ins = decodeAuthenticationInstructions(redeem); const offs = []; { let o = 0; for (const i of ins) { offs.push(o); o += encodeAuthenticationInstruction(i).length; } }
const names = Object.fromEntries(Object.entries(info.fids).map(([n, id]) => ['f' + binToHex(Uint8Array.from(id === 0 ? [] : [id])), n]));
const marks = info.marks.slice().sort((a, b) => a.off - b.off);
const sectionAt = (ip) => { let n = 'prologue'; for (const m of marks) if (m.off <= offs[ip]) n = m.name; return n; };
const fx = Number(process.env.FIX ?? 0);
const {unlocking: u} = unlocking(FIXTURES.fixtures[fx]);
const res = {};
for (const std of [false, true]) {
  const {vm, P} = makeTracedVm('spec', std);
  const st = vm.evaluate(programOf(locking, u));
  const R = `top${ins.length}`;
  const sec = new Map();
  for (const [k, c] of P.frameIp) { const [f, ip] = k.split('@'); if (f !== R) continue; const s = sectionAt(Math.max(0, Number(ip) - 1)); sec.set(s, (sec.get(s) ?? 0) + c); }
  // path by (section of outer, first callee)
  res[std ? 'standard' : 'consensus'] = {err: st.error ?? null, libauth: st.metrics.operationCost, traced: P.total, instr: P.instr, arith: P.arith, pushed: P.pushed, hash: P.hash,
    sections: Object.fromEntries(sec), excl: Object.fromEntries([...P.excl].map(([k, v]) => [names[k] ?? k, v])), incl: Object.fromEntries([...P.incl].map(([k, v]) => [names[k] ?? k, v])), calls: Object.fromEntries([...P.calls].map(([k, v]) => [names[k] ?? k, v])), byOpcode: [...P.byOpcode]};
}
res.redeemBytes = redeem.length; res.unlockingBytes = u.length; res.funcBytes = info.funcs; res.sectionsBytes = info.sections; res.prologue = info.prologue;
writeFileSync(process.argv[2], JSON.stringify(res, null, 1));
console.log(JSON.stringify({c: res.consensus.libauth, ct: res.consensus.traced, s: res.standard.libauth, st: res.standard.traced, err: res.consensus.err}));
