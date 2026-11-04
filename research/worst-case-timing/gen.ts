// Worst-case density kernels for the BCH 2026 VM, at today's per-input limits and at raised ones.
//
// Every kernel is one P2S input (locking bytecode <= 201 B, standard in 2026; unlocking push-only). The locking script
// runs one or more loops (OP_BEGIN ... OP_UNTIL, BCH 2026) and the loop counts are chosen so the input uses as much of
// its budget as the limits allow:
//   op-cost <= (41 + unlocking) * 800                 (standard op-cost: hash digest iterations at 192; consensus: 64)
//   hash digest iterations <= 0.5 (standard) or 3.5 (consensus) * (41 + unlocking)
//   sigchecks <= (unlocking + 60) / 43 per input, and <= 3000 per tx (standard)
// The unlocking bytecode is padded with a data push to the target length L, so every input is exactly L bytes of
// unlocking (the budget is linear in L).
//
// Parts (run in this order inside one input when several are present):
//   sig   OP_3DUP OP_CHECKDATASIGVERIFY on a fixed (ECDSA DER sig, 32-byte msg, pubkey), N times
//   hash  OP_DUP OP_RIPEMD160 OP_DROP on one item of S bytes, N times
//   roll  stack filled to 997 items by a loop, then <995> OP_ROLL, N times (unrolled x U)
//   mul   OP_2DUP OP_MUL OP_DROP on two numbers of a and b bytes, N times
//   mod   OP_2DUP OP_MOD OP_DROP, a-byte by b-byte, N times
//   copy  OP_DUP OP_DROP on one item of S bytes, N times
//   cat   OP_DUP OP_DUP OP_CAT OP_DROP on one item of S/2 bytes (copies S/2 and S bytes), N times
//
// Profiles (libauth VMs):
//   today      BCH 2026 as libauth 3.1.0-next.8 defines it (10,000 B unlocking/stack items/numbers)
//   txv5-100k  raised-limit profile (same raised limits as src/harness/vm.ts consensusTxv5; "txv5" is an identifier only):
//              bytecode, stack item and standard unlocking
//              caps 100,000 B; density base 41; VM numbers stay 10,000 B
//   txv5-150k  the same with 150,000 B caps
//   (numbers raised to the item cap: suffix "+num", e.g. txv5-100k+num; only the mul/mod kernels care)
//
// Usage: npx tsx gen.ts <outdir>   (writes rig-*.json for rig-run.ts and units-*.json for bchd/libauth timers)
import { writeFileSync, mkdirSync } from 'node:fs';
import {
  binToHex, createInstructionSetBch2026, generateSigningSerializationBch, hash256, createVirtualMachine, createVirtualMachineBch2026, encodeTransactionBch, encodeTransactionOutputs,
  ripemd160, secp256k1, sha1, sha256, hexToBin,
} from '@bitauth/libauth';
import { consensusBch2026 } from '../../src/harness/vm.js';

// ------------------------------------------------------------------ script helpers
const OP = { _0: 0x00, _1: 0x51, PD1: 0x4c, PD2: 0x4d, PD4: 0x4e, BEGIN: 0x65, UNTIL: 0x66, TOALT: 0x6b, FROMALT: 0x6c, DROP2: 0x6d,
  DUP2: 0x6e, DUP3: 0x6f, DEPTH: 0x74, DROP: 0x75, DUP: 0x76, ROLL: 0x7a, CAT: 0x7e, SUB1: 0x8c, NOT: 0x91, MUL: 0x95, MOD: 0x97,
  GTE: 0xa2, RIPEMD160: 0xa6, CDSV: 0xbb, CMSV: 0xaf, OVER: 0x78, PICK: 0x79, DEFINE: 0x89, INVOKE: 0x8a } as const;
const cat = (...xs: (number | Uint8Array | number[])[]) => Uint8Array.from(xs.flatMap((x) => (typeof x === 'number' ? [x] : [...x])));
const pushData = (d: Uint8Array): Uint8Array => {
  const n = d.length;
  if (n === 0) return Uint8Array.of(OP._0);
  if (n === 1 && d[0]! >= 1 && d[0]! <= 16) return Uint8Array.of(0x50 + d[0]!);
  if (n <= 75) return cat(n, d);
  if (n <= 255) return cat(OP.PD1, n, d);
  if (n <= 65535) return cat(OP.PD2, n & 0xff, n >> 8, d);
  return cat(OP.PD4, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff, d);
};
const vmNum = (v: number): Uint8Array => { // minimal VM number encoding (v >= 0)
  if (v === 0) return new Uint8Array(0);
  const out: number[] = []; let x = v;
  while (x > 0) { out.push(x & 0xff); x = Math.floor(x / 256); }
  if (out[out.length - 1]! & 0x80) out.push(0);
  return Uint8Array.from(out);
};
const pushNum = (v: number) => (v >= 1 && v <= 16 ? Uint8Array.of(0x50 + v) : pushData(vmNum(v)));
/** a positive, minimally encoded VM number of exactly `len` bytes */
const bigNumBytes = (len: number, seed: number) => { const b = new Uint8Array(len); for (let i = 0; i < len; i++) b[i] = (seed * 131 + i * 197 + 89) & 0xff; b[len - 1] = 0x40 | (b[len - 1]! & 0x3f); return b; };
const loop = (body: Uint8Array) => cat(OP.BEGIN, OP.TOALT, body, OP.FROMALT, OP.SUB1, OP.DUP, OP.NOT, OP.UNTIL, OP.DROP);
const rep = (b: Uint8Array, u: number) => cat(...Array.from({ length: u }, () => b));

// ------------------------------------------------------------------ fixed data signature
const PRIV = sha256.hash(new TextEncoder().encode('worst-case-timing key'));
const PUB = secp256k1.derivePublicKeyCompressed(PRIV) as Uint8Array;
const MSG = sha256.hash(new TextEncoder().encode('worst-case-timing msg'));
const SIG = secp256k1.signMessageHashDER(PRIV, sha256.hash(MSG)) as Uint8Array; // OP_CHECKDATASIG checks sha256(msg)
if (!(SIG instanceof Uint8Array)) throw new Error('sign failed');
// 1-of-20 legacy multisig: 20 keys; the signature is made with key 0, which CHECKMULTISIG tries last (19 failed verifies)
const MS_N = 20;
const MS_PRIV = Array.from({ length: MS_N }, (_, i) => sha256.hash(new TextEncoder().encode('worst-case-timing msig ' + i)));
const MS_PUB = MS_PRIV.map((k) => secp256k1.derivePublicKeyCompressed(k) as Uint8Array);
const SIGHASH_ALL_FORKID = 0x41;
/** tx signature (ECDSA, SIGHASH_ALL|FORKID) for input `index` of `tx`, covering `locking` (P2S, no OP_CODESEPARATOR) */
const txSig = (tx: any, sourceOutputs: any[], index: number, locking: Uint8Array) => {
  const h = hash256(generateSigningSerializationBch({ inputIndex: index, sourceOutputs, transaction: tx } as any, { coveredBytecode: locking, signingSerializationType: Uint8Array.of(SIGHASH_ALL_FORKID) }));
  return cat(secp256k1.signMessageHashDER(MS_PRIV[0]!, h) as Uint8Array, SIGHASH_ALL_FORKID);
};

// ------------------------------------------------------------------ profiles
type Profile = { name: string; itemCap: number; numCap: number; unlockCap: number };
const parseProfile = (p: string): Profile => {
  const num = p.endsWith('+num'); const base = num ? p.slice(0, -4) : p;
  const cap = base === 'today' ? 10_000 : base === 'txv5-100k' ? 100_000 : base === 'txv5-150k' ? 150_000 : NaN;
  if (Number.isNaN(cap)) throw new Error('profile ' + p);
  return { name: p, itemCap: cap, numCap: num ? cap : 10_000, unlockCap: cap };
};
const vmCache = new Map<string, any>();
export const vmFor = (p: Profile, standard: boolean, unbudgeted = false) => {
  const k = `${p.name}/${standard}/${unbudgeted}`;
  if (unbudgeted && !vmCache.has(k)) { // same limits, but op-cost and hash budgets lifted (only used to measure per-iteration slopes)
    const consensus = { ...consensusBch2026, maximumBytecodeLength: p.unlockCap, maximumStackItemLength: p.itemCap, maximumVmNumberByteLength: p.numCap,
      maximumStandardUnlockingBytecodeLength: p.unlockCap, densityControlBaseLength: 1e9 };
    vmCache.set(k, createVirtualMachine(createInstructionSetBch2026(standard, { consensus: consensus as any, ripemd160, secp256k1, sha1, sha256 })));
  }
  if (!vmCache.has(k) && p.name === 'today') vmCache.set(k, createVirtualMachineBch2026(standard)); // libauth's own BCH 2026 VM
  if (!vmCache.has(k)) {
    const consensus = { ...consensusBch2026, maximumBytecodeLength: p.unlockCap, maximumStackItemLength: p.itemCap, maximumVmNumberByteLength: p.numCap,
      maximumStandardUnlockingBytecodeLength: p.unlockCap };
    vmCache.set(k, createVirtualMachine(createInstructionSetBch2026(standard, { consensus: consensus as any, ripemd160, secp256k1, sha1, sha256 })));
  }
  return vmCache.get(k);
};

// ------------------------------------------------------------------ kernel parts
type PartKind = 'sig' | 'msig' | 'invoke' | 'hash' | 'roll' | 'mul' | 'mod' | 'copy' | 'cat';
interface Part { kind: PartKind; size?: number; a?: number; b?: number; unroll?: number }
// a part contributes: unlocking pushes (bottom..top, excluding its counter), locking code (counter on top at entry).
// 'SIG' in data marks the tx signature (filled in by assemble/the rig once the locking and outpoint are known).
const SIG_SLOT = new Uint8Array(0);
const partCode = (p: Part): { data: Uint8Array[]; code: Uint8Array } => {
  const u = p.unroll ?? 1;
  switch (p.kind) {
    case 'msig': // stack [.. pk0..pk19 sig]; body: OP_0 OP_OVER OP_1 (<23> OP_PICK)x20 <20> OP_CHECKMULTISIGVERIFY
      return { data: [...MS_PUB, SIG_SLOT], code: cat(loop(rep(cat(OP._0, OP.OVER, OP._1, ...Array.from({ length: MS_N }, () => cat(pushNum(23), OP.PICK)), pushNum(MS_N), OP.CMSV), u)),
        OP.DROP, ...Array.from({ length: MS_N / 2 }, () => OP.DROP2)) };
    case 'invoke': // define an empty function 1, then <1> OP_INVOKE in the loop
      return { data: [], code: cat(OP._0, OP._1, OP.DEFINE, loop(rep(Uint8Array.of(OP._1, OP.INVOKE), u))) };
    case 'sig': return { data: [SIG, MSG, PUB], code: cat(loop(rep(Uint8Array.of(OP.DUP3, OP.CDSV), u)), OP.DROP2, OP.DROP) };
    case 'hash': return { data: [new Uint8Array(p.size!).fill(0xa5)], code: cat(loop(rep(Uint8Array.of(OP.DUP, OP.RIPEMD160, OP.DROP), u)), OP.DROP) };
    case 'copy': return { data: [new Uint8Array(p.size!).fill(0x5a)], code: cat(loop(rep(Uint8Array.of(OP.DUP, OP.DROP), u)), OP.DROP) };
    case 'cat': return { data: [new Uint8Array(p.size! >> 1).fill(0x3c)], code: cat(loop(rep(Uint8Array.of(OP.DUP, OP.DUP, OP.CAT, OP.DROP), u)), OP.DROP) };
    case 'mul': return { data: [bigNumBytes(p.a!, 1), bigNumBytes(p.b!, 2)], code: cat(loop(rep(Uint8Array.of(OP.DUP2, OP.MUL, OP.DROP), u)), OP.DROP2) };
    case 'mod': return { data: [bigNumBytes(p.a!, 3), bigNumBytes(p.b!, 4)], code: cat(loop(rep(Uint8Array.of(OP.DUP2, OP.MOD, OP.DROP), u)), OP.DROP2) };
    case 'roll': // counter to alt, fill the main stack to 998 items with empties, counter back, roll loop; the empties stay
      return { data: [], code: cat(OP.TOALT, OP.BEGIN, OP._0, OP.DEPTH, pushNum(997), OP.GTE, OP.UNTIL, OP.FROMALT,
        loop(rep(cat(pushNum(995), OP.ROLL), u))) };
  }
};
const sigchecksPerIter = (p: Part) => (p.kind === 'sig' ? (p.unroll ?? 1) : p.kind === 'msig' ? MS_N * (p.unroll ?? 1) : 0);
const MAX_P2S_LOCKING = 201;
const lockingOf = (k: Kernel) => cat(...k.parts.map((p) => partCode(p).code), OP.BEGIN, OP.DROP, OP.DEPTH, OP.NOT, OP.UNTIL, OP._1);
/** shrink the unroll of the last unrolled part until the P2S locking fits the 201 B standard limit */
const fitLocking = (k: Kernel) => {
  for (;;) {
    if (lockingOf(k).length <= MAX_P2S_LOCKING) return;
    const p = [...k.parts].reverse().find((x) => (x.unroll ?? 1) > 1);
    if (!p) throw new Error(`${k.id}: locking ${lockingOf(k).length} B > 201 B`);
    p.unroll = p.unroll! - 1;
  }
};

export interface Kernel { id: string; group: string; profile: string; standard: boolean; L: number; parts: Part[]; description: string }
interface Built { k: Kernel; locking: Uint8Array; unlocking: Uint8Array; counts: number[]; pushes: ({ raw: Uint8Array } | { sig: true })[] }

/** Build unlocking/locking for given loop counts; pad so that unlocking is exactly L bytes. */
const assemble = (k: Kernel, counts: number[]) => {
  const code = lockingOf(k);
  const sigBytes = k.parts.some((p) => p.kind === 'msig') ? txSig(mkTx([{ unlocking: new Uint8Array(0) }]), [{ lockingBytecode: code, valueSatoshis: 100_000n }], 0, code) : undefined;
  const pushes: ({ raw: Uint8Array } | { sig: true })[] = [];
  // stack bottom..top: pad, then for parts in reverse order (last part deepest): counter_i, data_i ... ; first part on top
  // Part i (in run order) expects [.. data_i counter_i] on top when it starts; after it, its data and counter are gone.
  const segs: Uint8Array[] = [];
  for (let i = k.parts.length - 1; i >= 0; i--) {
    const pc = partCode(k.parts[i]!);
    for (const d of pc.data) { if (d === SIG_SLOT) { segs.push(pushData(sigBytes!)); pushes.push({ sig: true }); } else { segs.push(pushData(d)); pushes.push({ raw: d }); } }
    segs.push(pushNum(counts[i]!)); pushes.push({ raw: vmNum(counts[i]!) });
  }
  const body = cat(...segs);
  // pad: one or more pushes (each <= itemCap) at the bottom, total unlocking exactly L
  const prof = parseProfile(k.profile);
  // a re-signed low-S DER signature (+ sighash byte) is at most 72 B; leave room for 73 so the rig's signature never
  // makes the unlocking longer than L (it may make it up to 3 B shorter; build() sizes the limits for L - 3)
  const SIG_MAX = 73;
  let need = k.L - body.length - (sigBytes ? SIG_MAX - sigBytes.length : 0); const pads: Uint8Array[] = []; const padData: Uint8Array[] = [];
  if (need < 2) throw new Error(`${k.id}: kernel data (${body.length} B) does not fit L=${k.L}`);
  while (need > 0) {
    // choose a data length d with pushData(d) size <= need, d <= itemCap; leave either 0 or >= 2 bytes for the rest
    let d = Math.min(prof.itemCap, need - 1);
    const sz = (n: number) => pushData(new Uint8Array(n)).length;
    while (d > 0 && sz(d) > need) d--;
    while (d > 0 && need - sz(d) === 1) d--;
    const pd = new Uint8Array(d).fill(0x11); if (d === 1) pd[0] = 0x11; // 1-byte 0x11 stays a data push (not OP_N)
    const p = pushData(pd); pads.push(p); need -= p.length; padData.push(pd);
  }
  const unlocking = cat(...pads, body);
  if (unlocking.length !== k.L - (sigBytes ? SIG_MAX - sigBytes.length : 0)) throw new Error(`${k.id}: unlocking ${unlocking.length} != ${k.L}`);
  return { locking: code, unlocking, pushes: [...padData.map((d) => ({ raw: d })), ...pushes] };
};

const FAKE_TXID = sha256.hash(Uint8Array.of(1, 2, 3));
const mkTx = (ins: { unlocking: Uint8Array }[]) => ({ version: 2, locktime: 0,
  inputs: ins.map((x, i) => ({ outpointTransactionHash: FAKE_TXID, outpointIndex: i, sequenceNumber: 0, unlockingBytecode: x.unlocking })),
  outputs: [{ lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 0n }] });
const evalInput = (k: Kernel, locking: Uint8Array, unlocking: Uint8Array, standard: boolean, unbudgeted = false) => {
  const vm = vmFor(parseProfile(k.profile), standard, unbudgeted);
  const tx = mkTx([{ unlocking }]); const so = [{ lockingBytecode: locking, valueSatoshis: 100_000n }];
  const st = vm.evaluate({ inputIndex: 0, sourceOutputs: so, transaction: tx });
  return { ok: vm.stateSuccess(st) === true, err: vm.stateSuccess(st), m: st.metrics };
};

/** Fill: parts in order, each loop count as high as the limits allow given the parts before it. */
export const build = (k: Kernel): Built => {
  fitLocking(k);
  // a re-signed DER signature may be up to 4 B shorter than the 73 B reserved: size every limit for L - 4
  const signed = k.parts.some((p) => p.kind === 'msig'); const Lm = signed ? k.L - 4 : k.L;
  const dl = 41 + Lm;
  const budget = dl * 800, hashMax = Math.floor((k.standard ? 0.5 : 3.5) * dl), sigMax = Math.min(Math.floor((Lm + 60) / 43), 3000);
  const counts = k.parts.map(() => 1);
  const metrics = (c: number[], unbudgeted = false) => { const a = assemble(k, c); const r = evalInput(k, a.locking, a.unlocking, k.standard, unbudgeted); return { ...a, ...r }; };
  for (let i = 0; i < k.parts.length; i++) {
    // linear in the count: measure at count 1 and 2 (the loop is a do-while, so count 1 runs one iteration)
    const c1 = [...counts]; c1[i] = 1; const c2 = [...counts]; c2[i] = 2;
    const r1 = metrics(c1, true), r2 = metrics(c2, true); const m1 = r1.m, m2 = r2.m;
    if (!r1.ok || !r2.ok) throw new Error(`${k.id}: slope probe failed: ${r1.err} / ${r2.err}`);
    const dOp = m2.operationCost - m1.operationCost, dHash = m2.hashDigestIterations - m1.hashDigestIterations;
    const dSig = sigchecksPerIter(k.parts[i]!);
    let n = Math.floor((budget - m1.operationCost) / dOp) + 1;
    if (dHash > 0) n = Math.min(n, Math.floor((hashMax - m1.hashDigestIterations) / dHash) + 1);
    if (dSig > 0) n = Math.min(n, Math.floor((sigMax - m1.signatureCheckCount) / dSig) + 1);
    if (i < k.parts.length - 1 && !['sig', 'msig', 'hash'].includes(k.parts[i]!.kind)) throw new Error('only sig/msig/hash may precede other parts');
    n = Math.max(1, n);
    counts[i] = n;
    // the count pushes may grow by a byte or two as n grows: back off until valid
    for (let t = 0; t < 50; t++) { const r = metrics(counts); if (r.ok) break; counts[i] = Math.max(1, counts[i]! - Math.max(1, Math.ceil(counts[i]! * 0.001))); if (t === 49) throw new Error(`${k.id}: cannot fit (${r.err})`); }
  }
  const a = assemble(k, counts);
  return { k, locking: a.locking, unlocking: a.unlocking, counts, pushes: a.pushes };
};

export const report = (b: Built) => {
  const cons = evalInput(b.k, b.locking, b.unlocking, false), std = evalInput(b.k, b.locking, b.unlocking, true);
  const dl = 41 + b.k.L;
  return { consOk: cons.ok, consErr: cons.ok ? undefined : String(cons.err), stdOk: std.ok, stdErr: std.ok ? undefined : String(std.err),
    opCons: cons.m.operationCost, opStd: std.m.operationCost, budget: dl * 800, hashIter: cons.m.hashDigestIterations, sigchecks: cons.m.signatureCheckCount,
    instr: cons.m.evaluatedInstructionCount, pushedBytes: cons.m.stackPushedBytes, arith: cons.m.arithmeticCost,
    fillStd: std.m.operationCost / (dl * 800), fillCons: cons.m.operationCost / (dl * 800), counts: b.counts, lockingBytes: b.locking.length };
};

// ------------------------------------------------------------------ exports
const toNc = (id: string, group: string, description: string, ins: { locking: Uint8Array; unlocking: Uint8Array }[]) => ({
  id, group, kind: 'valid', expect: 'accept', defBytes: 0, description,
  txs: [{ version: 2, locktime: 0, inputs: ins.map((x) => ({ source: { lockingHex: binToHex(x.locking), valueSatoshis: 100_000 }, unlockingHex: binToHex(x.unlocking), sequenceNumber: 0 })),
    outputs: [{ lockingHex: '6a', valueSatoshis: 0 }] }] });
/** Track 1 rig format (research/opcost-timing/bchn/rig.ts Workload, json), plus `resign` for signed inputs */
const toRig = (id: string, group: string, description: string, ins: Built[]) => ({
  id, group, description, expect: 'accept', version: 2, locktime: 0,
  inputs: ins.map((b) => ({ sourceLockingHex: binToHex(b.locking), valueSatoshis: 100_000, unlockingHex: binToHex(b.unlocking), sequenceNumber: 0,
    ...(b.pushes.some((x) => 'sig' in x) ? { resign: b.pushes.map((x) => ('sig' in x ? { alg: 'ecdsa', keyHex: binToHex(MS_PRIV[0]!), hashType: SIGHASH_ALL_FORKID } : { rawHex: binToHex(x.raw) })) } : {}) })),
  outputs: [{ lockingHex: '6a', valueSatoshis: 0 }] });
const toUnit = (id: string, group: string, mode: string, ins: { locking: Uint8Array; unlocking: Uint8Array }[], opCosts: number[]) => {
  const tx: any = mkTx(ins); const so = ins.map((x) => ({ lockingBytecode: x.locking, valueSatoshis: 100_000n }));
  ins.forEach((x: any, i) => { if (x.pushes?.some((p: any) => 'sig' in p)) tx.inputs[i].unlockingBytecode = cat(...x.pushes.map((p: any) => pushData('sig' in p ? txSig(tx, so, i, x.locking) : p.raw))); });
  return { name: id, group, mode, txHex: binToHex(encodeTransactionBch(tx as any)), sourceOutputsHex: binToHex(encodeTransactionOutputs(so as any)), inputs: null,
    expectAccept: true, expectOpCost: opCosts, txBytes: encodeTransactionBch(tx as any).length };
};

// kernel catalogue at a given profile and length
export const catalogue = (profile: string, L: number, standard: boolean): Kernel[] => {
  const p = parseProfile(profile);
  const S = Math.min(p.itemCap, L - 200); // big item size: as large as the item cap and the unlocking allow
  const tag = `${profile}-L${L}-${standard ? 'std' : 'cons'}`;
  const ks: Kernel[] = [];
  const add = (name: string, parts: Part[], description: string) => ks.push({ id: `${name}@${tag}`, group: name, profile, standard, L, parts, description });
  add('msig', [{ kind: 'msig' }], '1-of-20 legacy OP_CHECKMULTISIGVERIFY (ECDSA, signature for the key tried last: 19 failed + 1 good verify), to the sigcheck density limit');
  add('invoke', [{ kind: 'invoke', unroll: 64 }], 'OP_INVOKE of an empty function, to the op-cost budget');
  add('hash', [{ kind: 'hash', size: S, unroll: 4 }], `OP_DUP OP_RIPEMD160 OP_DROP of a ${S} B item, to the hash limit`);
  add('roll', [{ kind: 'roll', unroll: 48 }], '997-item stack, <995> OP_ROLL, to the op-cost budget');
  add('mul1', [{ kind: 'mul', a: 1, b: 1, unroll: 32 }], 'OP_2DUP OP_MUL OP_DROP, 1 B x 1 B');
  add('mul32', [{ kind: 'mul', a: 32, b: 32, unroll: 16 }], 'OP_MUL 32 B x 32 B');
  add('mod1', [{ kind: 'mod', a: 8, b: 1, unroll: 32 }], 'OP_2DUP OP_MOD OP_DROP, 8 B mod 1 B');
  // largest balanced OP_MUL that fits: a*b + pushes <= budget, a <= numCap
  const budget = (41 + L) * 800;
  let a = Math.min((p.numCap >> 1) - 1, Math.floor(Math.sqrt(budget * 0.97)), (L >> 1) - 40); // the product must fit the number cap too
  // two copies of each operand pushed by OP_2DUP + product; keep the data in the unlocking
  while (a * a + 4 * a > budget * 0.97) a--;
  add('mulbig', [{ kind: 'mul', a, b: a }], `OP_MUL ${a} B x ${a} B (largest balanced product within the budget and number cap)`);
  add('copy', [{ kind: 'copy', size: S, unroll: 8 }], `OP_DUP OP_DROP of a ${S} B item`);
  add('cat', [{ kind: 'cat', size: S, unroll: 4 }], `OP_DUP OP_DUP OP_CAT OP_DROP on a ${S >> 1} B item (builds ${S} B)`);
  // composites: fill in order of measured BCHN ns per op-cost unit (see README); sig and hash are capped by their own limits
  add('mix-msig-roll', [{ kind: 'msig' }, { kind: 'roll', unroll: 48 }], 'msig to the sigcheck limit, then OP_ROLL to the op-cost budget');
  add('mix-msig-hash-roll', [{ kind: 'msig' }, { kind: 'hash', size: Math.min(S, L - 1200), unroll: 2 }, { kind: 'roll', unroll: 48 }], 'msig to the sigcheck limit, then hashing to the hash limit, then OP_ROLL to the budget');
  return ks;
};

// ------------------------------------------------------------------ main
if (process.argv[1]?.endsWith('gen.ts')) {
  const out = process.argv[2] ?? 'data'; mkdirSync(out, { recursive: true });
  const meta: any[] = [];
  const nc: Record<string, any[]> = {}; const units: Record<string, any[]> = {};
  const push = (file: string, x: any, into: Record<string, any[]>) => { (into[file] ??= []).push(x); };
  const TX_IN_OVERHEAD = 41 + 3; // outpoint 36 + sequence 4 + compact size of unlocking (3 B for 253..65535) ... +1 for >65535
  const doKernel = (k: Kernel, opts: { nc?: string; units?: string; mode: string; txOf?: number }) => {
    const b = build(k); const r = report(b);
    const ok = k.standard ? r.stdOk && r.consOk : r.consOk;
    meta.push({ id: k.id, group: k.group, profile: k.profile, standard: k.standard, L: k.L, description: k.description, ...r, ok });
    console.error(`${ok ? 'ok ' : 'BAD'} ${k.id.padEnd(44)} cons=${r.opCons} std=${r.opStd} fill(std)=${(r.fillStd * 100).toFixed(2)}% hash=${r.hashIter} sig=${r.sigchecks} n=${r.counts.join('/')} ${r.consErr ?? ''} ${k.standard ? r.stdErr ?? '' : ''}`);
    if (!ok) throw new Error('invalid kernel ' + k.id);
    const n = opts.txOf ?? 1; const ins = Array.from({ length: n }, () => b);
    const id = n > 1 ? `${k.id}-x${n}` : k.id;
    if (opts.nc) push(opts.nc, toRig(id, k.group, k.description, ins), nc);
    if (opts.units) push(opts.units, toUnit(id, k.group, opts.mode, ins, ins.map(() => r.opCons)), units);
    return { b, r };
  };
  // (1) today, BCHN: one 10,000 B input per tx; and a 100 KB standard tx of 10 inputs of 9,950 B
  for (const std of [true, false]) {
    for (const k of catalogue('today', 10_000, std)) doKernel(k, { nc: `rig-today-${std ? 'std' : 'cons'}.json`, units: 'units-today.json', mode: 'today' });
    for (const k of catalogue('today', 9_950, std)) doKernel(k, { nc: `rig-today-tx-${std ? 'std' : 'cons'}.json`, mode: 'today', txOf: 10 });
  }
  // (2) BCHN linearity sweep within today's limits: L = 2,500 / 5,000 (item size follows L)
  for (const L of [2_500, 5_000]) for (const k of catalogue('today', L, true)) doKernel(k, { nc: 'rig-today-sweep.json', units: 'units-today.json', mode: 'today' });
  // (3) raised limits (bchd + libauth only): L = 100,000 (and 99,900: fits a 100,000 B tx), 150,000
  for (const [prof, L] of [['txv5-100k', 100_000], ['txv5-150k', 150_000]] as const) {
    for (const std of [true, false]) for (const k of catalogue(prof, L, std)) doKernel(k, { units: `units-${prof}.json`, mode: prof });
  }
  // mul/mod with VM numbers raised to the item cap (the "+num" reading); the today-number kernels are identical here
  for (const [prof, L] of [['txv5-100k+num', 100_000], ['txv5-150k+num', 150_000]] as const) {
    for (const k of catalogue(prof, L, true).filter((x) => x.group === 'mulbig')) doKernel(k, { units: `units-${prof.replace('+num', '-num')}.json`, mode: prof });
    // unbalanced: the largest number times an 800 B (100k) / 800 B (150k) number: a*b = L*800 roughly fills the budget
    const p = parseProfile(prof); const a = p.numCap - 200 > L - 2000 ? L - 2000 : p.numCap - 200; const bb = Math.floor(((41 + L) * 800 * 0.9) / a);
    doKernel({ id: `mulwide@${prof}-L${L}-std`, group: 'mulwide', profile: prof, standard: true, L, parts: [{ kind: 'mul', a, b: bb }], description: `OP_MUL ${a} B x ${bb} B` },
      { units: `units-${prof.replace('+num', '-num')}.json`, mode: prof });
  }
  for (const [f, w] of Object.entries(nc)) writeFileSync(`${out}/${f}`, JSON.stringify({ workloads: w }));
  for (const [f, u] of Object.entries(units)) writeFileSync(`${out}/${f}`, JSON.stringify(u));
  writeFileSync(`${out}/kernels.json`, JSON.stringify(meta, null, 1));
  console.error(`wrote ${Object.keys(nc).length} nc files, ${Object.keys(units).length} unit files, ${meta.length} kernels`);
}
