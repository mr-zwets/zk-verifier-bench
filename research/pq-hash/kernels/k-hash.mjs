// K17 native SHA-256 node, K6 Merkle level step (h = 32 and 25; branch and branchless), authentication path
// (loop and unrolled, with index-bit handling), K7 leaf hash + parse, K5 digest -> challenge / index / grinding.
import {createHash} from 'node:crypto';
import {asm, numBytes} from './lib/asm.mjs';
import {P} from './lib/ref-field.mjs';

const sha = (...bs) => Uint8Array.from(createHash('sha256').update(Buffer.concat(bs.map((b) => Buffer.from(b)))).digest());
const nb = (v) => numBytes(v);
const kernels = [];
const def = (id, group, name, build, notes = '', trials = 16, extra) => kernels.push({id, group, name, build, notes, trials, extra});

// ---- K17: native SHA-256 of one 64-byte node ----
def('K17', 'hash', 'SHA-256 node: OP_CAT + OP_SHA256 of two 32-byte children', (rng) => {
  const l = rng.bytes(32), r = rng.bytes(32);
  return {inputs: [l, r], body: asm('CAT', 'SHA256'), outputs: [{bin: sha(l, r)}]};
}, '2 digest iterations (64-byte message)');
def('K17', 'hash', 'SHA-256 of one 64-byte item (OP_SHA256 only)', (rng) => {
  const m = rng.bytes(64);
  return {inputs: [m], body: asm('SHA256'), outputs: [{bin: sha(m)}]};
});
def('K17', 'hash', 'SHA-256 of one 55-byte item (largest 1-iteration message)', (rng) => {
  const m = rng.bytes(55);
  return {inputs: [m], body: asm('SHA256'), outputs: [{bin: sha(m)}]};
});

// ---- K6: Merkle level step ----
const parent = (cur, sib, bit, h) => (bit ? sha(sib, cur) : sha(cur, sib)).slice(0, h);
for (const h of [32, 25]) {
  const trunc = h === 32 ? [] : [h, 'SPLIT', 'DROP'];
  def('K6', 'merkle', `Merkle level (cur, sib, bit) -> parent, h=${h}, branch (NOTIF SWAP ENDIF)`, (rng) => {
    const cur = rng.bytes(h), sib = rng.bytes(h), bit = rng.int(2);
    return {inputs: [sib, cur, nb(bit)], body: asm('NOTIF', 'SWAP', 'ENDIF', 'CAT', 'SHA256', trunc), outputs: [{bin: parent(cur, sib, bit, h)}]};
  });
  def('K6', 'merkle', `Merkle level (cur, sib, bit) -> parent, h=${h}, branchless (bit OP_ROLL)`, (rng) => {
    const cur = rng.bytes(h), sib = rng.bytes(h), bit = rng.int(2);
    return {inputs: [cur, sib, nb(bit)], body: asm('ROLL', 'CAT', 'SHA256', trunc), outputs: [{bin: parent(cur, sib, bit, h)}]};
  }, 'bit in {0,1}: 0 OP_ROLL is a no-op, 1 OP_ROLL is OP_SWAP');
}

// ---- authentication path with index bits: one step and a d-level loop ----
// state: idx cur blob  (blob = remaining siblings, lowest level first)
// idx -> bit, idx' :  DUP 2 MOD  (bit) ... ; then SWAP 1 RSHIFTNUM
const step = (h) => [
  h, 'SPLIT', 'TOALTSTACK',          // idx cur sib             | alt: blob'
  'ROT', 'DUP', 1, 'RSHIFTNUM', 'TOALTSTACK', // cur sib idx  | alt: blob' idx'
  2, 'MOD', 'ROLL', 'CAT', 'SHA256', ...(h === 32 ? [] : [h, 'SPLIT', 'DROP']), // parent
  'FROMALTSTACK', 'SWAP', 'FROMALTSTACK', // idx' parent blob'
];
const pathRef = (leaf, idx, sibs, h) => { let cur = leaf; for (const s of sibs) { cur = parent(cur, s, idx & 1, h); idx >>= 1; } return cur; };
for (const h of [32, 25]) {
  def('K6', 'merkle', `auth path step with index bit (idx, cur, sibling blob) -> (idx>>1, parent, blob'), h=${h}`, (rng) => {
    const cur = rng.bytes(h), sibs = [rng.bytes(h), rng.bytes(h)], idx = rng.int(1 << 20);
    const blob = Uint8Array.from([...sibs[0], ...sibs[1]]);
    return {inputs: [nb(idx), cur, blob], body: asm(step(h)),
      outputs: [{num: BigInt(idx >> 1)}, {bin: parent(cur, sibs[0], idx & 1, h)}, {bin: sibs[1]}]};
  }, 'unrolled; 1 split of the sibling blob, bit = idx mod 2, idx >>= 1');
  for (const d of [20]) {
    def('K6', 'merkle', `auth path, ${d} levels, loop (OP_BEGIN ... OP_UNTIL on empty blob), h=${h}; root compared`, (rng) => {
      const leaf = rng.bytes(h), sibs = Array.from({length: d}, () => rng.bytes(h)), idx = rng.int(1 << d);
      const blob = Uint8Array.from(sibs.flatMap((s) => [...s]));
      const root = pathRef(leaf, idx, sibs, h);
      const body = asm('BEGIN', step(h), 'SIZE', 'NOT', 'UNTIL', 'DROP', 'NIP', root, 'EQUAL');
      return {inputs: [nb(idx), leaf, blob], body, outputs: [{num: 1n}]};
    }, `per level: divide by ${d}`, 8, {perLevel: d});
    def('K6', 'merkle', `auth path, ${d} levels, unrolled, h=${h}; root compared`, (rng) => {
      const leaf = rng.bytes(h), sibs = Array.from({length: d}, () => rng.bytes(h)), idx = rng.int(1 << d);
      const blob = Uint8Array.from(sibs.flatMap((s) => [...s]));
      const root = pathRef(leaf, idx, sibs, h);
      const body = asm(Array.from({length: d}, () => step(h)), 'DROP', 'NIP', root, 'EQUAL');
      return {inputs: [nb(idx), leaf, blob], body, outputs: [{num: 1n}]};
    }, `per level: divide by ${d}`, 8, {perLevel: d});
    def('K6', 'merkle', `auth path, ${d} levels, unrolled, siblings as separate pushes, branchless, h=${h}`, (rng) => {
      const leaf = rng.bytes(h), sibs = Array.from({length: d}, () => rng.bytes(h)), idx = rng.int(1 << d);
      const root = pathRef(leaf, idx, sibs, h);
      // stack: sib_{d-1} ... sib_0 idx leaf ; per level: idx cur -> idx' parent
      const lv = ['SWAP', 'DUP', 1, 'RSHIFTNUM', 'TOALTSTACK', 2, 'MOD', // sib.. cur bit   | alt idx'
        'ROT', 'SWAP', 'ROLL', 'CAT', 'SHA256', ...(h === 32 ? [] : [h, 'SPLIT', 'DROP']), 'FROMALTSTACK', 'SWAP'];
      const body = asm(Array.from({length: d}, () => lv), 'NIP', root, 'EQUAL');
      return {inputs: [...[...sibs].reverse(), nb(idx), leaf], body, outputs: [{num: 1n}]};
    }, `per level: divide by ${d}`, 8, {perLevel: d});
  }
}

// ---- K8: multiproof merge (sorted distinct positions at the cap level -> root), canonical order ----
// Level by level: an entry (pos, node) merges with the next entry if pos is even and the next pos is pos + 1,
// otherwise it consumes the next proof sibling. Entries are 4-byte LE positions || h-byte nodes in one blob;
// the sibling stream stays on the altstack. Levels are unrolled; the inner loop runs once per produced node.
function multiproofRef(leaves, positions, h, D) {
  // full tree
  const lv = [leaves]; for (let d = 0; d < D; d++) { const prev = lv[d]; lv.push(Array.from({length: prev.length / 2}, (_, i) => parent(prev[2 * i], prev[2 * i + 1], 0, h))); }
  let L = positions.map((q) => [q, leaves[q]]); const proof = []; let nodes = 0;
  for (let d = 0; d < D; d++) {
    const next = [];
    for (let i = 0; i < L.length; i++) {
      const [q, nd] = L[i]; nodes++;
      if (q % 2 === 0 && i + 1 < L.length && L[i + 1][0] === q + 1) { next.push([q >> 1, parent(nd, L[i + 1][1], 0, h)]); i++; }
      else { const sib = lv[d][q ^ 1]; proof.push(sib); next.push([q >> 1, parent(nd, sib, q & 1, h)]); }
    }
    L = next;
  }
  if (L.length !== 1 || L[0][0] !== 0) throw new Error('multiproof ref');
  return {root: L[0][1], proof, nodes, treeRoot: lv[D][0]};
}
function multiproofBody(h, D) {
  const E = 4 + h, tr = h === 32 ? [] : [h, 'SPLIT', 'DROP'];
  const inner = ['BEGIN',
    E, 'SPLIT', 'SWAP', 4, 'SPLIT', 'SWAP', 'BIN2NUM',                       // next L' node pos
    2, 'PICK', 'SIZE', 'NIP', 'IF', 2, 'PICK', 4, 'SPLIT', 'DROP', 'BIN2NUM', 'OVER', '1ADD', 'NUMEQUAL', 'OVER', 2, 'MOD', 'NOT', 'BOOLAND', 'ELSE', 0, 'ENDIF',
    'IF', 'ROT', E, 'SPLIT', 'SWAP', 4, 'SPLIT', 'NIP', 3, 'ROLL', 'SWAP', 'CAT', 'SHA256', ...tr, 'ROT', 'SWAP',   // merge
    'ELSE', 'FROMALTSTACK', h, 'SPLIT', 'TOALTSTACK', 'OVER', 2, 'MOD', 'ROT', 'TOALTSTACK', 'ROLL', 'CAT', 'SHA256', ...tr, 'FROMALTSTACK', 'SWAP', // sibling
    'ENDIF',
    'SWAP', 1, 'RSHIFTNUM', 4, 'NUM2BIN', 'SWAP', 'CAT', 'ROT', 'SWAP', 'CAT', 'SWAP', // next' L
    'SIZE', 'NOT', 'UNTIL', 'DROP'];
  return asm('SWAP', 'TOALTSTACK', Array.from({length: D}, () => [0, 'SWAP', inner]), // each level: [next=empty, L] -> next
    4, 'SPLIT', 'NIP', 'FROMALTSTACK', 'SIZE', 'NIP', 'NOT', 'VERIFY');
}
for (const [h, D, k] of [[32, 10, 22], [25, 10, 22], [32, 10, 43]]) {
  const body = multiproofBody(h, D);
  def('K8', 'merkle', `multiproof merge, ${k} sorted positions (with duplicates removed) over ${D} levels, h=${h}; returns the root`, (rng) => {
    const leaves = Array.from({length: 1 << D}, () => rng.bytes(h));
    const pos = [...new Set(Array.from({length: k}, () => rng.int(1 << D)))].sort((a, b) => a - b);
    const ref = multiproofRef(leaves, pos, h, D);
    if (Buffer.compare(Buffer.from(ref.root), Buffer.from(ref.treeRoot)) !== 0) throw new Error('multiproof root');
    const L = Uint8Array.from(pos.flatMap((q) => [q & 255, (q >> 8) & 255, (q >> 16) & 255, 0, ...leaves[q]]));
    const proof = Uint8Array.from(ref.proof.flatMap((x) => [...x]));
    return {inputs: [proof, L], body, outputs: [{bin: ref.root}], meta: {nodes: ref.nodes, siblings: ref.proof.length}};
  }, 'per node: divide by the nodes processed (reported in meta)', 6);
}

// ---- K7: leaf hash + parse (tag byte, k values of 8 bytes LE, unsigned) ----
const le8 = (v) => { const b = new Uint8Array(8); for (let i = 0; i < 8; i++) b[i] = Number((v >> BigInt(8 * i)) & 255n); return b; };
for (const [nv, label] of [[8, '64 B (trace leaf: 4 points x 2 values)'], [24, '192 B (composition / FRI leaf: 24 values)']]) {
  for (const h of [32, 25]) {
    def('K7', 'merkle', `leaf hash + parse, ${label}, h=${h}`, (rng) => {
      const vals = Array.from({length: nv}, () => rng.big(64));
      const leaf = Uint8Array.from(vals.flatMap((v) => [...le8(v)]));
      const tag = Uint8Array.of(0x02);
      const digest = sha(tag, leaf).slice(0, h);
      // leaf -> v0 .. v_{n-1} digest ; values decoded unsigned: b || 0x00, BIN2NUM
      const parse = Array.from({length: nv - 1}, () => [8, 'SPLIT', 'SWAP', Uint8Array.of(0), 'CAT', 'BIN2NUM', 'SWAP']).flat();
      const body = asm('DUP', tag, 'SWAP', 'CAT', 'SHA256', ...(h === 32 ? [] : [h, 'SPLIT', 'DROP']), 'TOALTSTACK',
        parse, Uint8Array.of(0), 'CAT', 'BIN2NUM', 'FROMALTSTACK');
      return {inputs: [leaf], body, outputs: [...vals.map((v) => ({num: v})), {bin: digest}]};
    }, `${nv} values; per value: divide the parse part`);
  }
}

// ---- K5: digest -> F_p^3 challenge, digest -> index, grinding check ----
const leNum = (b) => b.reduceRight((a, x) => (a << 8n) | BigInt(x), 0n);
const p = P.gl;
def('K5', 'transcript', 'E(d): 32-byte digest -> F_p^3 (v mod p, v div p mod p, v div p^2 mod p)', (rng) => {
  const d = rng.bytes(32); const v = leNum(d);
  const body = asm(Uint8Array.of(0), 'CAT', 'BIN2NUM', 'DUP', p, 'MOD', 'SWAP', p, 'DIV', 'DUP', p, 'MOD', 'SWAP', p, 'DIV', p, 'MOD');
  return {inputs: [d], body, outputs: [{num: v % p}, {num: (v / p) % p}, {num: (v / p / p) % p}]};
});
def('K5', 'transcript', 'challenge from transcript: SHA256(t || "a" || u8 j) then E(d)', (rng) => {
  const t = rng.bytes(32); const d = sha(t, Uint8Array.of(0x61, 3)); const v = leNum(d);
  const body = asm(Uint8Array.of(0x61, 3), 'CAT', 'SHA256', Uint8Array.of(0), 'CAT', 'BIN2NUM', 'DUP', p, 'MOD', 'SWAP', p, 'DIV', 'DUP', p, 'MOD', 'SWAP', p, 'DIV', p, 'MOD');
  return {inputs: [t], body, outputs: [{num: v % p}, {num: (v / p) % p}, {num: (v / p / p) % p}]};
});
for (const bits of [21, 19]) {
  def('K5', 'transcript', `query index: SHA256(G || u16 i), first 4 bytes LE mod 2^${bits}`, (rng) => {
    const G = rng.bytes(32), i = rng.int(43); const u16 = Uint8Array.of(i & 255, i >> 8);
    const d = sha(G, u16); const idx = leNum(d.slice(0, 4)) % (1n << BigInt(bits));
    const body = asm(u16, 'CAT', 'SHA256', 4, 'SPLIT', 'DROP', Uint8Array.of(0), 'CAT', 'BIN2NUM', 1n << BigInt(bits), 'MOD');
    return {inputs: [G], body, outputs: [{num: idx}]};
  }, 'u16 i pushed as a constant (unrolled per query)');
}
def('K5', 'transcript', 'grinding: G = SHA256(t6 || nonce8), require top 28 bits zero (mask AND)', (rng) => {
  // find a nonce with 12 leading zero bits only would be cheap; the cost does not depend on the value, so we
  // construct an accepting case by searching a nonce for a weaker 8-bit target and checking with that mask.
  const t6 = rng.bytes(32); let nonce, G;
  for (let n = 0; ; n++) { nonce = le8(BigInt(n) + rng.big(40)); G = sha(t6, nonce); if (G[0] === 0) break; }
  const body = asm('CAT', 'SHA256', 'DUP', 4, 'SPLIT', 'DROP', Uint8Array.of(0xff, 0, 0, 0), 'AND', Uint8Array.of(0, 0, 0, 0), 'EQUALVERIFY');
  return {inputs: [t6, nonce], body, outputs: [{bin: G}]};
}, 'mask 0xff000000 here (8-bit target, so the case can be ground in JS); the 28-bit mask ffffff f0 costs the same');

export default kernels;
