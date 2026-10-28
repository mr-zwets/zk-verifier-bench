// Op-cost profile of the fixture transaction, per input, by section of the role program (and by function).
//   [FIX=0] [MODE=standard] node profile.mjs
import {decodeAuthenticationInstructions, encodeAuthenticationInstruction} from '@bitauth/libauth';
import {FIXTURES} from '../sound-si-gls/math.mjs';
import {buildProgram} from './script.mjs';
import {transactionFor} from './transaction.mjs';
import {programOf, VMS} from './vm.mjs';
const prog = buildProgram();
const tx = transactionFor(FIXTURES.fixtures[Number(process.env.FIX ?? 0)], prog);
const roleIns = [0, 1, 2].map((i) => { const c = prog.funcCodes['role' + i]; const d = decodeAuthenticationInstructions(c); const o = []; let x = 0; for (const t of d) { o.push(x); x += encodeAuthenticationInstruction(t).length; } return {n: d.length, offs: o}; });
const marks = prog.marks.slice().sort((a, b) => a.roff - b.roff);
const fnOf = new Map(); for (const [n, c] of Object.entries(prog.funcCodes)) { const L = decodeAuthenticationInstructions(c).length; fnOf.set(L, fnOf.has(L) ? fnOf.get(L) + '|' + n : n); }
const GX = new Map(); const mode = process.env.MODE ?? 'standard'; const lock = tx.locking;
for (let i = 0; i < 3; i++) {
  const tr = VMS[mode].debug(programOf(tx.unlockings.map(() => lock), tx.unlockings, i));
  const bySec = new Map(), byFn = new Map(), X = new Map(); let prev = 0, cur = 'unlocking/R';
  for (const s of tr) {
    const c = s.metrics?.operationCost ?? 0; const d = c - prev; prev = c;
    const ri = roleIns.findIndex((x) => x.n === s.instructions?.length);
    if (ri >= 0) { let n = 'r' + ri + ':start'; for (const m of marks) if (m.role === ri && m.roff <= roleIns[ri].offs[Math.max(0, s.ip - 1)]) n = m.name; cur = n; }
    bySec.set(cur, (bySec.get(cur) ?? 0) + d);
    const fk = fnOf.get(s.instructions?.length) ?? 'other'; byFn.set(fk, (byFn.get(fk) ?? 0) + d); const xk = cur.replace(/^r\d:/, '') + ' | ' + fk; X.set(xk, (X.get(xk) ?? 0) + d); GX.set(xk, (GX.get(xk) ?? 0) + d);
  }
  console.log(`input ${i}: total ${prev} (${mode}), unlocking ${tx.unlockings[i].length}`);
  for (const [k, v] of [...bySec].sort((a, b) => b[1] - a[1])) if (v > 5000) console.log('  ' + k.padEnd(26), (v / 1e6).toFixed(3) + 'M');
  console.log('  by function (innermost):', [...byFn].sort((a, b) => b[1] - a[1]).filter(([, v]) => v > 5000).map(([k, v]) => `${k} ${(v / 1e6).toFixed(3)}M`).join(', '));
}
console.log('CROSS'); for (const [k, v] of [...GX].sort((a, b) => b[1] - a[1])) if (v > 3000) console.log('  ' + k.padEnd(36), (v / 1e6).toFixed(3) + 'M');
