// Straight-line program compiler onto a symbolic stack (Stk).
// A program is a list of assignments [name, expr]; exprs reference stack items or earlier names with V(name).
// Every referenced item is copied (PICK) while it has later uses and moved (ROLL) at its last use, so inputs and
// temporaries are consumed exactly when they die. Items named in `keep` are never consumed.
// Expressions: V(n), K(c) constant, add/sub/mul/div/mod2(a, b) binary opcodes, modp(a, p) = a OP_MOD p (p pushed),
// op(code, ...args) any opcode with one output, raw(fn) escape hatch.
import {Stk, fresh} from './asm.mjs';

export const V = (n) => ({t: 'v', n});
export const K = (c) => ({t: 'c', c: BigInt(c)});
export const op = (o, ...args) => ({t: 'op', o, args});
export const add = (a, b) => op('ADD', a, b);
export const sub = (a, b) => op('SUB', a, b);
export const mul = (a, b) => op('MUL', a, b);
export const modp = (a, p) => op('MOD', a, K(p));
export const sum = (...xs) => xs.reduce((a, b) => add(a, b));

function countUses(e, uses) {
  if (e.t === 'v') uses.set(e.n, (uses.get(e.n) ?? 0) + 1);
  else if (e.t === 'op') e.args.forEach((x) => countUses(x, uses));
}

const COMM = new Set(['ADD', 'MUL', 'BOOLAND', 'BOOLOR', 'NUMEQUAL', 'MIN', 'MAX', 'AND', 'OR', 'XOR']);
export function compileSlp(stk, prog, {keep = []} = {}) {
  const uses = new Map();
  for (const [, e] of prog) countUses(e, uses);
  const keepSet = new Set(keep);
  const emitE = (e) => {
    if (e.t === 'v') {
      const left = uses.get(e.n); uses.set(e.n, left - 1);
      if (left > 1 || keepSet.has(e.n)) stk.pick(e.n); else stk.roll(e.n);
      return;
    }
    if (e.t === 'c') { stk.push(e.c); return; }
    // peephole: every argument is a dying item already on top in order (or, for a commutative binary op, swapped)
    const n = e.args.length;
    const dying = (x) => x.t === 'v' && uses.get(x.n) === 1 && !keepSet.has(x.n);
    if (e.args.every(dying) && new Set(e.args.map((x) => x.n)).size === n) {
      const topN = stk.st.slice(-n), names = e.args.map((x) => x.n);
      const inOrder = topN.every((x, i) => x === names[i]);
      const swapped = n === 2 && COMM.has(e.o) && topN[0] === names[1] && topN[1] === names[0];
      if (inOrder || swapped) { names.forEach((x) => uses.set(x, 0)); stk.op(e.o, n, fresh('x')); return; }
    }
    e.args.forEach(emitE);
    stk.op(e.o, e.args.length, fresh('x'));
  };
  for (const [name, e] of prog) { emitE(e); stk.st[stk.st.length - 1] = name; }
  return stk;
}

// evaluate a program in JS (BigInt), mirroring CashVM integer semantics (DIV/MOD truncate toward zero)
export function evalSlp(prog, env) {
  const v = new Map(Object.entries(env));
  const ev = (e) => {
    if (e.t === 'v') { if (!v.has(e.n)) throw new Error('unbound ' + e.n); return v.get(e.n); }
    if (e.t === 'c') return e.c;
    const a = e.args.map(ev);
    switch (e.o) {
      case 'ADD': return a[0] + a[1]; case 'SUB': return a[0] - a[1]; case 'MUL': return a[0] * a[1];
      case 'DIV': return a[0] / a[1]; case 'MOD': return a[0] % a[1];
      case 'LSHIFTNUM': return a[0] << a[1]; case 'RSHIFTNUM': return a[0] >> a[1];
      default: throw new Error('evalSlp: ' + e.o);
    }
  };
  for (const [n, e] of prog) v.set(n, ev(e));
  return v;
}

export {Stk};
