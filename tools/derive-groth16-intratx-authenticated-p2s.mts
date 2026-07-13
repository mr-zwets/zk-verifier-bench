// Derive src/bch/groth16-intratx-authenticated-p2s-vectors.json from
// src/bch/groth16-intratx-vectors.json.
//
// Transformation, per step of every run: the unlocking bytecode is copied
// BYTE-IDENTICAL (stage bodies forward-check successor unlockings at fixed
// byte offsets, so any shift breaks the chain); the 35-byte P2SH32 locking
// (aa20<hash256(body)>87) is replaced by a 44-byte bare (P2S) dispatcher:
//
//   76 aa 20<hash256(body)> 88 02e703 89 02e703 8a
//   OP_DUP OP_HASH256 <digest> OP_EQUALVERIFY <999> OP_DEFINE <999> OP_INVOKE
//
// The stage body stays as the final push of the unlocking — now ordinary
// authenticated data instead of a P2SH redeem script.
//
// Identifier 999 (the top of OP_DEFINE's valid 0..999 range) is reserved for
// the dispatcher: the stage bodies define identifiers densely from 0 upward
// (currently 0..24), and libauth errors on redefinition, so the identifier
// must be one no body ever defines. Asserted per body below.
//
// Two invalid runs are ADDED beyond those inherited from the source vectors:
//   - modified-body: one byte flipped inside one stage's body push
//   - wrong-stage-body: bodies of two stages with differing digests swapped
// Both must be rejected by the dispatcher's hash check.
//
// Run: pnpm exec tsx tools/derive-groth16-intratx-authenticated-p2s.mts
import { readFileSync, writeFileSync } from 'node:fs';

import {
  binToHex,
  decodeAuthenticationInstructions,
  hash256,
  hexToBin,
} from '@bitauth/libauth';

interface RawStep { label: string; locking: string; unlocking: string; checkpoint?: string }
interface Vectors {
  steps: RawStep[];
  extraValidProofs?: RawStep[][];
  worstCaseProof?: RawStep[];
  invalid?: RawStep[][];
  [k: string]: unknown;
}

const SOURCE = 'src/bch/groth16-intratx-vectors.json';
const TARGET = 'src/bch/groth16-intratx-authenticated-p2s-vectors.json';

const src = JSON.parse(readFileSync(SOURCE, 'utf8')) as Vectors;

const fail = (msg: string): never => { throw new Error(msg); };

/** Final data push of a script: its data and the byte offset where the push starts. */
const finalPush = (unlocking: Uint8Array, where: string): { data: Uint8Array; start: number } => {
  const ins = decodeAuthenticationInstructions(unlocking);
  const last = ins.at(-1);
  if (last === undefined || !('data' in last)) throw new Error(`${where}: final instruction is not a data push`);
  const data = last.data as Uint8Array;
  // Recover the push's start offset: canonical encodings only (verified below).
  const header = data.length < 0x4c ? 1 : data.length <= 0xff ? 2 : data.length <= 0xffff ? 3 : fail(`${where}: body too large`);
  const start = unlocking.length - (header as number) - data.length;
  const reencoded = encodePush(data);
  if (binToHex(unlocking.subarray(start)) !== binToHex(reencoded)) fail(`${where}: final push is not canonically encoded`);
  return { data, start };
};

/** Canonical (minimal) data push encoding. */
const encodePush = (data: Uint8Array): Uint8Array => {
  if (data.length < 0x4c) return Uint8Array.from([data.length, ...data]);
  if (data.length <= 0xff) return Uint8Array.from([0x4c, data.length, ...data]);
  if (data.length <= 0xffff) return Uint8Array.from([0x4d, data.length & 0xff, data.length >> 8, ...data]);
  return fail('push too large');
};

/** Static scan: does the body define the dispatcher's reserved function
 * identifier 999 (push e703 followed by OP_DEFINE)? A body defining it would
 * collide at runtime (libauth errors on redefinition). */
const definesReservedIdentifier = (body: Uint8Array): boolean => {
  const ins = decodeAuthenticationInstructions(body);
  for (let i = 1; i < ins.length; i++) {
    const prev = ins[i - 1]!;
    if (ins[i]!.opcode === 0x89 /* OP_DEFINE */ && 'data' in prev && binToHex(prev.data) === 'e703') return true;
  }
  return false;
};

const dispatcher = (bodyDigestHex: string): string => `76aa20${bodyDigestHex}8802e7038902e7038a`;

// --- derive the primary run, sanity-checking the P2SH32 envelope hashes -----
const primaryDigests: string[] = [];
const deriveStep = (s: RawStep, where: string, index: number): RawStep => {
  if (!(s.locking.length === 70 && s.locking.startsWith('aa20') && s.locking.endsWith('87')))
    fail(`${where}: source locking is not 35-byte P2SH32: ${s.locking}`);
  const unlocking = hexToBin(s.unlocking);
  const { data: body } = finalPush(unlocking, where);
  const digest = binToHex(hash256(body));
  if (where.startsWith('steps') && digest !== s.locking.slice(4, 68))
    fail(`${where}: hash256(body) != P2SH32 envelope hash`);
  if (where.startsWith('steps')) {
    primaryDigests.push(digest);
    if (definesReservedIdentifier(body)) fail(`${where}: body defines reserved identifier 999`);
  } else if (digest !== primaryDigests[index])
    fail(`${where}: body digest differs from primary step ${index}`);
  return { label: s.label, locking: dispatcher(digest), unlocking: s.unlocking, ...(s.checkpoint !== undefined ? { checkpoint: s.checkpoint } : {}) };
};

const steps = src.steps.map((s, i) => deriveStep(s, `steps[${i}]`, i));
const extraValidProofs = (src.extraValidProofs ?? []).map((run, r) => run.map((s, i) => deriveStep(s, `extraValidProofs[${r}][${i}]`, i)));
const worstCaseProof = (src.worstCaseProof ?? []).map((s, i) => deriveStep(s, `worstCaseProof[${i}]`, i));
const invalid = (src.invalid ?? []).map((run, r) => run.map((s, i) => deriveStep(s, `invalid[${r}][${i}]`, i)));

// --- new invalid run (a): modified-body — flip one byte inside one body push
const replaceBody = (step: RawStep, newBody: Uint8Array): RawStep => {
  const unlocking = hexToBin(step.unlocking);
  const { start } = finalPush(unlocking, step.label);
  const out = new Uint8Array(start + encodePush(newBody).length);
  out.set(unlocking.subarray(0, start), 0);
  out.set(encodePush(newBody), start);
  return { ...step, unlocking: binToHex(out) };
};
{
  const target = 0;
  const { data: body } = finalPush(hexToBin(steps[target]!.unlocking), 'modified-body');
  const flipped = Uint8Array.from(body);
  flipped[Math.floor(flipped.length / 2)]! ^= 0x01;
  invalid.push(steps.map((s, i) => (i === target
    ? { ...replaceBody(s, flipped), label: `${s.label} (invalid: body byte flipped)` }
    : s)));
}

// --- new invalid run (b): wrong-stage-body — swap two bodies whose digests differ
{
  const a = 0;
  const b = primaryDigests.findIndex((d, i) => i !== a && d !== primaryDigests[a]);
  if (b === -1) fail('wrong-stage-body: no stage with a differing digest found');
  const bodyA = finalPush(hexToBin(steps[a]!.unlocking), 'swap-a').data;
  const bodyB = finalPush(hexToBin(steps[b]!.unlocking), 'swap-b').data;
  invalid.push(steps.map((s, i) => (i === a
    ? { ...replaceBody(s, bodyB), label: `${s.label} (invalid: body of stage ${b})` }
    : i === b
      ? { ...replaceBody(s, bodyA), label: `${s.label} (invalid: body of stage ${a})` }
      : s)));
}

const totalBytes = steps.reduce((t, s) => t + s.locking.length / 2 + s.unlocking.length / 2, 0);
const distinctDigests = new Set(primaryDigests).size;

const out = {
  description:
    'Authenticated bare (P2S) dispatcher variant of bch-groth16-intratx: each stage\'s ' +
    '35-byte P2SH32 locking is replaced by a 44-byte bare dispatcher (OP_DUP OP_HASH256 ' +
    '<hash256(body)> OP_EQUALVERIFY <999> OP_DEFINE <999> OP_INVOKE) that authenticates the ' +
    'stage body — still the final push of the byte-identical unlocking — before invoking it. ' +
    'Derived by tools/derive-groth16-intratx-authenticated-p2s.mts.',
  method: 'intra-tx-linked',
  deployment: 'bare (authenticated P2S dispatcher)',
  numInputs: steps.length,
  budgetPerInput: src.budgetPerInput,
  totalBytes,
  steps,
  extraValidProofs,
  worstCaseProof,
  invalid,
};

writeFileSync(TARGET, JSON.stringify(out));
console.log(JSON.stringify({
  source: SOURCE,
  target: TARGET,
  steps: steps.length,
  distinctBodyDigests: distinctDigests,
  extraValidProofs: extraValidProofs.length,
  worstCaseProof: worstCaseProof.length,
  invalidRuns: invalid.length,
  totalBytes,
  noBodyDefinesReservedIdentifier999: true,
}, null, 2));
