// TXv5-as-written grade for bch-spec entries (bench issue #35, option 2).
//
// bch-spec entries are graded on libauth's BCH_SPEC VM, whose op-cost budget is
// (10,000 + unlockingLen) * 800 per input. TXv5 (CHIP-2025-01 v1.0.0) raises the bytecode and
// stack element caps to 100,000 B but keeps the density-control base at 41, so under TXv5 an
// input's budget is (41 + unlockingLen) * 800, as on BCH 2026. This module answers, for each
// bch-spec entry:
//   1. does the shipped transaction validate on the TXv5 VM (consensus / standard)?
//   2. if not, which minimal zero padding of the unlockings makes every input fit its budget,
//      and what is the padded score?
//
// Padding follows the harness's existing convention (benchmark.ts zeroPadBytes): one all-zero
// data push that the script ignores, at the convention's pad position (just before the redeem
// script under P2SH, last for a bare/P2S locking). If an input already carries a pad there
// (non-empty, all zero) it is lengthened; otherwise a new zero push is inserted there. An
// all-zero push anywhere else is never touched (it could be a real zero-valued witness element).
// The scripts do not inspect the pad's bytes (any content of the same length is accepted); the
// grade uses zero bytes, as padBytes does.
// An entry may ship a TXv5-grading variant (Scenario.txv5Variant): the same program with a
// documented pad slot, used for this grade only. The grade is then measured on the variant's
// runs and says so (Txv5Grade.variant, Txv5Summary.variant).
// Otherwise nothing is rebuilt: an entry that pins its push layout (e.g. DEPTH == 2 at entry) rejects
// the pad, and is reported "not paddable as shipped". For those, an ESTIMATE of the padding a
// pad slot would need is given (measured op-cost + the pad's own push and drop), clearly
// labelled as such.
//
// The padding is computed by a least fixpoint: measure each input's op-cost and hash-digest
// iterations on the TXv5 VM with the density budget lifted (every other TXv5 limit applies), grow
// the short inputs' pads to the smallest length whose op-cost AND hash-iteration limits cover
// them, re-measure (a pad's bytes are themselves pushed and sibling
// inputs may read a padded input via introspection), and repeat until every input fits. The
// result is then replayed on the real TXv5 VM, which must accept every input.
//
// Every honest run the entry ships is graded (the valid run = fixture 0, every extraValidProof,
// and the bch-spec worstCaseProof). On TXv5 a padded run's size is set by its op-cost (each
// padded input ends near ceil(op / 800) - 41 bytes whatever its shipped length), and a run that
// validates as shipped costs its shipped size; so the TXv5 worst case is the honest run with the
// largest TXv5 figure over ALL honest runs (as-shipped ones included), which need not be the
// bch-spec worst-case witness. The summary reports fixture 0 next to that maximum, and calls the
// TXv5 figure standard only if EVERY honest run's figure is standard.
//
// Transaction size (the standard 100,000 B check, txBytes and the score's tx overhead) is
// modelled with the harness's v1/v2 serialization. TXv5's v5 encoding is a few bytes smaller per
// input and output (1-byte input bitfield instead of a 4-byte sequence, compact values), so the
// figures slightly overstate a v5 transaction; no current standardness verdict is within that
// margin (the closest, 100,109 B and 101,201 B, are hundreds of bytes over the cap).
import {
  decodeAuthenticationInstructions,
  encodeAuthenticationInstruction,
  encodeDataPush,
} from '@bitauth/libauth';

import { assertRunShape, assertSameProgramRun } from './scenario-contract.js';
import { withUnlockings } from './gates.js';
import type { Scenario, Step } from './types.js';
import {
  createRealVmTxv5,
  createStandardVmTxv5,
  createUnbudgetedVmTxv5,
  evaluatePair,
  isP2sh20Locking,
  isP2sh32Locking,
  MAX_STANDARD_LOCKING_BYTECODE,
  MAX_STANDARD_TRANSACTION_SIZE,
  TXV5_STANDARD_UNLOCKING_CAP,
  type Bch2026Vm,
} from './vm.js';

const DENSITY_BASE = 41;
const PER_BYTE = 800;
const budgetOf = (unlockingLen: number) => (DENSITY_BASE + unlockingLen) * PER_BYTE;
// hash-digest iteration limit per input: floor(perByte * (41 + unlockingLen)), perByte 0.5 in
// standard mode and 3.5 in consensus (libauth bch-2023-instruction-set initialize)
const HASH_PER_BYTE = { standard: 0.5, consensus: 3.5 } as const;
/** Smallest unlocking length whose op-cost budget AND hash-iteration limit cover the measured
 * use (iters <= floor(f * (41 + L))  <=>  41 + L >= ceil(iters / f), iters being an integer). */
const neededUnlockingLen = (m: { opCost: number; iters: number }, standard: boolean) => Math.max(
  Math.ceil(m.opCost / PER_BYTE) - DENSITY_BASE,
  Math.ceil(m.iters / HASH_PER_BYTE[standard ? 'standard' : 'consensus']) - DENSITY_BASE,
);

type Instr = ReturnType<typeof decodeAuthenticationInstructions>[number];
const dataOf = (i: Instr): Uint8Array | undefined => ('data' in i ? (i as { data: Uint8Array }).data : undefined);
const isZeroPad = (i: Instr) => {
  const d = dataOf(i);
  return d !== undefined && d.length > 0 && d.every((b) => b === 0);
};
const concat = (parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((a, p) => a + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};

/** Where a pad goes in one input, and the unlocking it yields for a given pad data length. */
interface PadSlot {
  kind: 'grow' | 'insert';
  /** pad data length already present (grow) or 0 (insert: no pad yet) */
  base: number;
  build: (dataLen: number) => Uint8Array;
}
const padSlots = (step: Step): PadSlot[] => {
  const ins = decodeAuthenticationInstructions(step.unlockingBytecode);
  const enc = ins.map((i) => encodeAuthenticationInstruction(i));
  const zeroPush = (n: number) => encodeDataPush(new Uint8Array(n));
  const slots: PadSlot[] = [];
  // the convention's pad position: second-to-last under a P2SH envelope (the redeem is pushed
  // last), else last. grow: an existing zero pad AT that position (never another all-zero push,
  // which could be a real zero-valued witness element); insert: a new zero push there.
  const p2sh = isP2sh32Locking(step.lockingBytecode) || isP2sh20Locking(step.lockingBytecode);
  const at = p2sh ? ins.length - 2 : ins.length - 1;
  if (at >= 0 && isZeroPad(ins[at]!)) {
    const base = dataOf(ins[at]!)!.length;
    slots.push({ kind: 'grow', base, build: (n) => concat(enc.map((e, k) => (k === at ? zeroPush(n) : e))) });
  }
  const pos = p2sh ? Math.max(0, enc.length - 1) : enc.length;
  slots.push({ kind: 'insert', base: 0, build: (n) => concat([...enc.slice(0, pos), zeroPush(n), ...enc.slice(pos)]) });
  return slots;
};

/** Smallest pad data length (>= min) whose unlocking is at least `target` bytes long. */
const padLenFor = (slot: PadSlot, target: number, min: number): number => {
  const len = (n: number) => slot.build(n).length;
  let n = Math.max(min, slot.base + Math.max(0, target - len(slot.base)));
  while (len(n) < target) n++;
  while (n > min && len(n - 1) >= target) n--;
  return n;
};

const accepts = (vm: Bch2026Vm, s: Step, bsv: boolean) => {
  const o = evaluatePair(vm, s.lockingBytecode, s.unlockingBytecode, s.covenant, s.intraTx, s.grouped);
  return { ok: bsv ? o.bsvAccepted : o.accepted, opCost: o.operationCost, iters: o.hashDigestIterations, error: o.error };
};

export interface Txv5PadResult {
  /** total bytes added to the unlockings (pad growth incl. push headers) */
  padBytes: number;
  /** bytes added per input, in input order */
  perInput: number[];
  /** headline score of the padded transaction (scripts + tx overhead) */
  score: number;
  /** serialized size of the padded transaction(s) as the harness models it */
  txBytes: number;
}

export interface Txv5ModeGrade {
  /** the shipped transaction validates on this TXv5 mode */
  asShipped: boolean;
  /** first failing input and error when it does not */
  reason?: string;
  /** minimal padding when it does not and the entry is paddable */
  padded?: Txv5PadResult;
}

export interface Txv5Grade {
  vm: 'txv5';
  consensus: Txv5ModeGrade;
  /** standard (relay) mode: per-input standard VM + 201 B locking, 100,000 B unlocking
   * (assumed), 100,000 B transaction */
  standard: Txv5ModeGrade & { fits: boolean; policyReason?: string };
  /** 'not-needed': validates as shipped in both modes; 'paddable': minimal padding found and
   * verified; 'not-paddable': some input that needs budget rejects every pad (pinned layout). */
  padding: 'not-needed' | 'paddable' | 'not-paddable';
  notPaddableReason?: string;
  /** not-paddable only: the padding a pad slot WOULD need (estimate, not measured: assumes
   * the pad costs one push of its bytes plus one OP_DROP, on top of the measured op-cost). */
  estimate?: { padBytes: number; score: number; mode: 'standard' };
  /** the bch-spec worst-case witness (worstCaseProof, picked for the bch-spec budget), graded the
   * same way. It need not be the TXv5 worst case: on TXv5 the largest figure over all honest runs
   * binds (see `honest` and Txv5Summary.worst) */
  worstCase?: { consensus: Txv5ModeGrade; standard: Txv5ModeGrade & { fits: boolean; policyReason?: string }; padding: Txv5Grade['padding']; estimate?: Txv5Grade['estimate'] };
  /** the TXv5 figure of every honest run: fixture 0 first, then each extraValidProof, then the
   * worst-case proof */
  honest?: Txv5RunFigure[];
  /** set when the grade is measured on the entry's TXv5-grading variant (Scenario.txv5Variant)
   * instead of its shipped runs; invalidRejected counts the variant's invalid runs rejected on
   * the TXv5 VM with the density budget lifted, in both modes */
  variant?: { description: string; invalidRejected: number; invalid: number };
}

type ScoreOf = (run: Step[]) => { score: number; txBytes: number };

interface ModeContext {
  standard: boolean;
  real: Bch2026Vm;
  unbudgeted: Bch2026Vm;
}

/** Pad strategy chosen per input (the first slot that keeps the whole run accepting). */
const chooseSlots = (run: Step[], ctx: ModeContext[], bsv: boolean, need: boolean[]):
  { slots: (PadSlot | undefined)[]; failed?: string } => {
  const slots: (PadSlot | undefined)[] = run.map(() => undefined);
  for (let i = 0; i < run.length; i++) {
    if (!need[i]) continue;
    const candidates = padSlots(run[i]!);
    const ok = candidates.find((slot) => {
      const probe = withUnlockings(run, new Map([[i, slot.build(Math.max(slot.base, 0) + 8)]]));
      return ctx.every((c) => probe.every((s) => accepts(c.unbudgeted, s, bsv).ok));
    });
    if (ok === undefined) {
      return { slots, failed: `input ${i} (${run[i]!.label}) rejects a zero pad push (${candidates.map((c) => c.kind).join(' or ')}): the push layout is pinned` };
    }
    slots[i] = ok;
  }
  return { slots };
};

/** Least-fixpoint minimal padding of `run` for one mode; undefined when not paddable. */
const minimalPadding = (run: Step[], c: ModeContext, slots: (PadSlot | undefined)[], bsv: boolean):
  { run: Step[]; perInput: number[] } | { error: string } => {
  const lens: (number | undefined)[] = slots.map((s) => (s === undefined ? undefined : s.base));
  const build = () => withUnlockings(run, new Map(
    slots.flatMap((s, i) => (s === undefined || lens[i] === undefined || (s.kind === 'grow' && lens[i] === s.base) || (s.kind === 'insert' && lens[i] === 0) ? [] : [[i, s.build(lens[i]!)] as [number, Uint8Array]])),
  ));
  for (let iter = 0; iter < 64; iter++) {
    const cur = build();
    const out = cur.map((s) => accepts(c.unbudgeted, s, bsv));
    const bad = out.findIndex((o) => !o.ok);
    if (bad >= 0) return { error: `input ${bad} rejects on the unbudgeted TXv5 VM after padding: ${out[bad]!.error ?? 'not accepted'}` };
    let changed = false;
    cur.forEach((s, i) => {
      const target = neededUnlockingLen(out[i]!, c.standard);
      if (s.unlockingBytecode.length >= target) return;
      const slot = slots[i];
      if (slot === undefined) return; // an unpadded input that falls short: caught below
      lens[i] = padLenFor(slot, target, Math.max(lens[i] ?? 0, slot.kind === 'insert' ? 1 : slot.base));
      changed = true;
    });
    if (!changed) {
      const short = cur.findIndex((s, i) => s.unlockingBytecode.length < neededUnlockingLen(out[i]!, c.standard));
      if (short >= 0) return { error: `input ${short} exceeds its budget and has no pad slot` };
      // replay on the real TXv5 VM: every input must accept within its own budget
      const realBad = cur.map((s) => accepts(c.real, s, bsv)).findIndex((o) => !o.ok);
      if (realBad >= 0) return { error: `padded input ${realBad} still rejects on the real TXv5 VM` };
      return { run: cur, perInput: cur.map((s, i) => s.unlockingBytecode.length - run[i]!.unlockingBytecode.length) };
    }
  }
  return { error: 'padding did not converge' };
};

const firstFailure = (run: Step[], vm: Bch2026Vm, bsv: boolean): string | undefined => {
  for (let i = 0; i < run.length; i++) {
    const o = accepts(vm, run[i]!, bsv);
    if (!o.ok) {
      const e = (o.error ?? 'not accepted').toLowerCase();
      const tag = e.includes('operation cost') ? 'op-cost over (41 + unlocking) * 800'
        : e.includes('hash') ? 'hash iterations over density budget'
        : e.includes('bytecode length') ? 'script size'
        : o.error ?? 'not accepted';
      return `input ${i} (${run[i]!.label}): ${tag}`;
    }
  }
  return undefined;
};

const standardPolicy = (run: Step[], scoreOf: ScoreOf): string | undefined => {
  const reasons = [
    run.some((s) => s.lockingBytecode.length > MAX_STANDARD_LOCKING_BYTECODE) ? `locking > ${MAX_STANDARD_LOCKING_BYTECODE} B` : null,
    run.some((s) => s.unlockingBytecode.length > TXV5_STANDARD_UNLOCKING_CAP) ? `unlocking > ${TXV5_STANDARD_UNLOCKING_CAP.toLocaleString('en-US')} B` : null,
    scoreOf(run).txBytes > MAX_STANDARD_TRANSACTION_SIZE ? `tx ${scoreOf(run).txBytes.toLocaleString('en-US')} B > ${MAX_STANDARD_TRANSACTION_SIZE.toLocaleString('en-US')} B` : null,
  ].filter(Boolean);
  return reasons.length ? reasons.join('; ') : undefined;
};

/** Estimated padding for an input layout that cannot take a pad as shipped: a new push of
 * `added` encoded bytes (header + L data bytes) costs one push (100 + L) and one OP_DROP (100).
 * Not counted (hence an estimate): the script change a pad slot needs (an OP_DROP or a changed
 * DEPTH constant, a few bytes of redeem script) and, for multi-input entries, the extra
 * introspection cost when a sibling input grows. */
const pushHeader = (encoded: number) => (encoded <= 76 ? 1 : encoded <= 257 ? 2 : encoded <= 65_538 ? 3 : 5);
const estimatePadding = (run: Step[], c: ModeContext, bsv: boolean): number[] =>
  run.map((s) => {
    const m = accepts(c.unbudgeted, s, bsv);
    const u = s.unlockingBytecode.length;
    if (u >= neededUnlockingLen(m, c.standard)) return 0;
    let added = Math.max(1, neededUnlockingLen(m, c.standard) - u);
    while (budgetOf(u + added) < m.opCost + 200 + (added - pushHeader(added))
      || u + added < neededUnlockingLen(m, c.standard)) added++;
    return added;
  });

const gradeRun = (run: Step[], bsv: boolean, scoreOf: ScoreOf, ctx: ModeContext[]) => {
  const [cons, std] = ctx as [ModeContext, ModeContext];
  const consFail = firstFailure(run, cons.real, bsv);
  const stdFail = firstFailure(run, std.real, bsv);
  const policy = standardPolicy(run, scoreOf);
  const consensus: Txv5ModeGrade = { asShipped: consFail === undefined, ...(consFail ? { reason: consFail } : {}) };
  const standard: Txv5ModeGrade & { fits: boolean; policyReason?: string } = {
    asShipped: stdFail === undefined && policy === undefined,
    ...(stdFail || policy ? { reason: [stdFail, policy].filter(Boolean).join('; ') } : {}),
    fits: stdFail === undefined && policy === undefined,
    ...(policy ? { policyReason: policy } : {}),
  };
  if (consFail === undefined && stdFail === undefined) return { consensus, standard, padding: 'not-needed' as const };

  // which inputs need budget (in either mode), and does each tolerate a pad?
  const need = run.map((s) => ctx.some((c) => s.unlockingBytecode.length < neededUnlockingLen(accepts(c.unbudgeted, s, bsv), c.standard)));
  const unbudgetedOk = ctx.every((c) => run.every((s) => accepts(c.unbudgeted, s, bsv).ok));
  if (!unbudgetedOk || !need.some(Boolean)) {
    return { consensus, standard, padding: 'not-paddable' as const, notPaddableReason: 'rejects on TXv5 for a reason other than the density budget' };
  }
  const { slots, failed } = chooseSlots(run, ctx, bsv, need);
  if (failed !== undefined) {
    const est = estimatePadding(run, std, bsv);
    const estRun = withUnlockings(run, new Map(run.map((s, i) => [i, concat([s.unlockingBytecode, new Uint8Array(est[i]!)])] as [number, Uint8Array])));
    return {
      consensus, standard, padding: 'not-paddable' as const, notPaddableReason: failed,
      estimate: { padBytes: est.reduce((a, b) => a + b, 0), score: scoreOf(estRun).score, mode: 'standard' as const },
    };
  }
  const padFor = (c: ModeContext, asShipped: boolean): Txv5PadResult | { error: string } | undefined => {
    if (asShipped) return undefined;
    const r = minimalPadding(run, c, slots, bsv);
    if ('error' in r) return r;
    const { score, txBytes } = scoreOf(r.run);
    return { padBytes: r.perInput.reduce((a, b) => a + b, 0), perInput: r.perInput, score, txBytes, ...(c.standard ? { policy: standardPolicy(r.run, scoreOf) } : {}) } as Txv5PadResult;
  };
  const pc = padFor(cons, consensus.asShipped);
  const ps = padFor(std, stdFail === undefined);
  const err = [pc, ps].find((p) => p !== undefined && 'error' in p) as { error: string } | undefined;
  if (err) return { consensus, standard, padding: 'not-paddable' as const, notPaddableReason: err.error };
  if (pc) consensus.padded = pc as Txv5PadResult;
  if (ps) {
    const { policy, ...padded } = ps as Txv5PadResult & { policy?: string };
    standard.padded = padded;
    standard.fits = policy === undefined;
    if (policy) standard.policyReason = `padded: ${policy}`; else delete standard.policyReason;
  }
  return { consensus, standard, padding: 'paddable' as const };
};

/** The one figure a graded run yields: what that honest run costs on TXv5. */
export interface Txv5RunFigure {
  /** which honest run: 'fixture 0' (the valid run), 'extra proof #k', 'worst-case proof' */
  run: string;
  status: 'as-shipped' | 'padded' | 'not-paddable' | 'invalid';
  /** shipped score, padded score (standard-mode padding when that tx is standard, else
   * consensus), or the estimate (not-paddable); null when invalid */
  score: number | null;
  /** bytes of pad behind `score` (same mode as score); estimate when `estimated` */
  padBytes: number;
  /** which TXv5 mode `score` is measured in: standard when that figure is standard (or an
   * estimate, which targets standard mode), else consensus */
  mode: 'standard' | 'consensus';
  /** the figure is relayable (standard) under the assumed 100,000 B unlocking cap */
  standard: boolean;
  /** why not standard (policy, or the standard VM), when it is not. Names the mode it comes
   * from when that differs from `mode` (e.g. 'standard mode, padded: tx ...' next to a
   * consensus score) */
  nonStandardReason?: string;
  /** serialized size of the transaction(s) behind `score` (same mode as score; harness v2
   * model); absent for estimates and invalid runs */
  txBytes?: number;
  estimated: boolean;
}

const figureOf = (run: string, g: ReturnType<typeof gradeRun>, shipped: { score: number; txBytes: number }): Txv5RunFigure => {
  const shippedScore = shipped.score;
  // the standard-mode reason, labelled with its mode when the figure is a consensus figure
  const stdReason = (r: string | undefined) => (r === undefined ? undefined : g.standard.fits ? r : `standard mode, ${r}`);
  if (g.padding === 'not-needed') {
    return { run, status: 'as-shipped', score: shippedScore, padBytes: 0, mode: g.standard.fits ? 'standard' : 'consensus', standard: g.standard.fits, ...(g.standard.fits ? {} : { nonStandardReason: stdReason(g.standard.policyReason ?? g.standard.reason) }), txBytes: shipped.txBytes, estimated: false };
  }
  if (g.padding === 'paddable') {
    const stdPadded = g.standard.fits && g.standard.padded !== undefined;
    // standard needs no pad while consensus does: not expected (standard is stricter), kept total
    const stdShipped = g.standard.fits && g.standard.padded === undefined;
    const score = stdPadded ? g.standard.padded!.score
      : stdShipped ? shippedScore
      : g.consensus.padded?.score ?? (g.consensus.asShipped ? shippedScore : null);
    const padBytes = stdPadded ? g.standard.padded!.padBytes : stdShipped ? 0 : g.consensus.padded?.padBytes ?? 0;
    const txBytes = stdPadded ? g.standard.padded!.txBytes : stdShipped ? shipped.txBytes : g.consensus.padded?.txBytes ?? (g.consensus.asShipped ? shipped.txBytes : undefined);
    return { run, status: 'padded', score, padBytes, mode: g.standard.fits ? 'standard' : 'consensus', standard: g.standard.fits, ...(g.standard.fits ? {} : { nonStandardReason: stdReason(g.standard.policyReason ?? g.standard.reason) }), ...(txBytes !== undefined ? { txBytes } : {}), estimated: false };
  }
  if (g.estimate) {
    return { run, status: 'not-paddable', score: g.estimate.score, padBytes: g.estimate.padBytes, mode: 'standard', standard: false, nonStandardReason: 'not paddable as shipped', estimated: true };
  }
  return { run, status: 'invalid', score: null, padBytes: 0, mode: 'consensus', standard: false, nonStandardReason: g.notPaddableReason ?? 'rejects on TXv5', estimated: false };
};

/** Grade one bch-spec entry on TXv5 as written. `scoreOf` is the harness's own score model.
 * The top-level fields grade the valid run (fixture 0); `worstCase` grades the bch-spec
 * worst-case witness (picked for the bch-spec budget; not necessarily the TXv5 worst case); `honest`
 * gives the figure of every honest run (fixture 0, each extraValidProof, the worst-case proof). */
export const txv5Grade = (scenario: Scenario, bsv: boolean, scoreOf: ScoreOf): Txv5Grade => {
  // Validate shipped and variant programs independently before any VM execution.
  // A pad-slot variant deliberately changes programs and may shift proof push indices.
  const v = scenario.txv5Variant;
  [scenario, ...(v ? [v] : [])].forEach((source, sourceIndex) => {
    const label = sourceIndex === 0 ? 'TXv5 shipped' : 'TXv5 variant';
    assertRunShape(source.valid, `${label} valid`);
    (source.extraValidProofs ?? []).forEach((run, index) =>
      assertSameProgramRun(source.valid, run, `${label} extra proof #${index + 1}`));
    if (source.worstCaseProof !== undefined) assertSameProgramRun(source.valid, source.worstCaseProof, `${label} worst-case proof`);
  });
  const ctx: ModeContext[] = [
    { standard: false, real: createRealVmTxv5(), unbudgeted: createUnbudgetedVmTxv5(false) },
    { standard: true, real: createStandardVmTxv5(), unbudgeted: createUnbudgetedVmTxv5(true) },
  ];
  const src = v ?? scenario;
  const runs: [string, Step[]][] = [
    ['fixture 0', src.valid],
    ...(src.extraValidProofs ?? []).map((r, k): [string, Step[]] => [`extra proof #${k + 1}`, r]),
    ...(src.worstCaseProof?.length ? [['worst-case proof', src.worstCaseProof] as [string, Step[]]] : []),
  ];
  if (v && (v.extraValidProofs?.length ?? 0) !== (scenario.extraValidProofs?.length ?? 0)) throw new Error('txv5Variant: extraValidProofs count differs from the shipped entry');
  if (v && !!v.worstCaseProof?.length !== !!scenario.worstCaseProof?.length) throw new Error('txv5Variant: worstCaseProof presence differs from the shipped entry');
  const variant = v ? {
    description: v.description,
    invalid: v.invalid?.length ?? 0,
    invalidRejected: (v.invalid ?? []).filter((run) => ctx.every((c) => run.some((s) => !accepts(c.unbudgeted, s, bsv).ok))).length,
  } : undefined;
  if (variant && variant.invalidRejected !== variant.invalid) throw new Error(`txv5Variant: ${variant.invalid - variant.invalidRejected} of ${variant.invalid} invalid runs are not rejected on TXv5 (budget lifted)`);
  const graded = runs.map(([label, run]) => ({ label, run, g: gradeRun(run, bsv, scoreOf, ctx) }));
  const main = graded[0]!.g;
  const wc = graded.find((x) => x.label === 'worst-case proof')?.g;
  return {
    vm: 'txv5',
    ...main,
    ...(wc ? { worstCase: { consensus: wc.consensus, standard: wc.standard, padding: wc.padding, ...(wc.estimate ? { estimate: wc.estimate } : {}) } } : {}),
    honest: graded.map((x) => figureOf(x.label, x.g, scoreOf(x.run))),
    ...(variant ? { variant } : {}),
  };
};

/** Summary of a TXv5 grade for the site: the figure to show next to the bch-spec score.
 * status / score / padBytes / estimated describe fixture 0 (the valid run):
 *   'as-shipped'   - validates on TXv5 as shipped; score = the shipped score.
 *   'padded'       - measured: the minimal zero padding validates; score = the padded score
 *                    (standard-mode padding when the padded tx is standard, else consensus).
 *   'not-paddable' - the entry pins its push layout; score = the ESTIMATE for a pad slot.
 *   'invalid'      - rejects on TXv5 for a reason padding cannot fix; score = null.
 * standard is true only if EVERY honest run's figure is standard (liveness: the worst-case
 * honest witness must be relayable too). worst is the TXv5 worst case when it is not fixture 0:
 * an invalid honest run, else the honest run with the largest TXv5 figure over ALL honest runs
 * (a run valid as shipped counts with its shipped score: it is the size that proof costs on TXv5).
 * worstPadded is the largest figure among the runs that need padding (or an estimate), when that
 * run differs from worst; mixed is true when honest runs land on different sides of the TXv5
 * budget (some valid as shipped, others not). */
export interface Txv5Summary {
  status: Txv5RunFigure['status'];
  score: number | null;
  /** bytes of pad behind `score` (same mode as score) */
  padBytes: number;
  /** TXv5 mode `score` and `padBytes` are measured in (fixture 0) */
  mode: 'standard' | 'consensus';
  standard: boolean;
  /** an honest run whose figure is not standard (the worst case when it is one), when standard
   * is false */
  nonStandard?: { run: string; reason?: string };
  estimated: boolean;
  worst?: Txv5RunFigure;
  /** the heaviest honest run that does NOT validate as shipped, when it is not `worst` */
  worstPadded?: Txv5RunFigure;
  mixed: boolean;
  /** number of honest runs graded */
  runs: number;
  /** the figures are measured on the entry's TXv5-grading variant (Txv5Grade.variant) */
  variant?: string;
}
export const txv5Summary = (g: Txv5Grade, shippedScore: number): Txv5Summary => {
  const honest = g.honest ?? [];
  const f0 = honest[0] ?? figureOf('fixture 0', g as ReturnType<typeof gradeRun>, { score: shippedScore, txBytes: 0 });
  const all = honest.length ? honest : [f0];

  // TXv5 worst case: an invalid run if any, else the largest TXv5 figure over ALL honest runs
  // (a run valid as shipped costs its shipped size on TXv5; ties keep the earlier run)
  const largest = (fs: Txv5RunFigure[]) => fs.reduce<Txv5RunFigure | undefined>((w, f) => (w === undefined || (f.score ?? 0) > (w.score ?? 0) ? f : w), undefined);
  const worst = all.find((f) => f.status === 'invalid') ?? largest(all);
  // the heaviest run that needs padding (or an estimate), reported when it is not `worst`
  const worstPadded = largest(all.filter((f) => f.status !== 'as-shipped' && f.status !== 'invalid'));
  // the run to name when the figure is not standard: the worst case if it is non-standard
  const nonStd = worst !== undefined && !worst.standard ? worst : all.find((f) => !f.standard);
  const shipped = all.filter((f) => f.status === 'as-shipped').length;
  return {
    status: f0.status,
    score: f0.score,
    padBytes: f0.padBytes,
    mode: f0.mode,
    standard: nonStd === undefined,
    ...(nonStd ? { nonStandard: { run: nonStd.run, ...(nonStd.nonStandardReason ? { reason: nonStd.nonStandardReason } : {}) } } : {}),
    estimated: f0.estimated,
    ...(worst !== undefined && worst !== f0 ? { worst } : {}),
    ...(worstPadded !== undefined && worstPadded !== worst && worstPadded !== f0 ? { worstPadded } : {}),
    mixed: shipped > 0 && shipped < all.length,
    runs: all.length,
    ...(g.variant ? { variant: g.variant.description } : {}),
  };
};
