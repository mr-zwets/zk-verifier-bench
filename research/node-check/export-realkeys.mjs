// Export Track 11 (real SP1 v5 / RISC Zero Groth16 keys on the bn-native-sound verifier) as node-check workloads.
//   G16=<groth16_cashscript checkout> node export-realkeys.mjs <out-dir>
// Reads groth16_cashscript chunked/bn254/real-keys (build-key.mjs, redteam-key.mjs, covenant-test.mjs outputs; it
// re-derives the valid transactions itself and checks them against the build files). Per key, writes
// realkeys-<key>.json with:
//   valid      : every published fixture (plain verifier), expect accept;
//   rejections : every red-team run of the public-input / proof-point kinds (patches of the fixture-0 transaction);
//   covenant   : the covenant build's control (accept) and every covenant rejection run (outputs differ).
// Each tx: 3 inputs under the shared P2SH32(R), 100,000 sat each, sequence 0; plain: one OP_RETURN output of 1,000
// sat; covenant: output 0 = OP_RETURN <PV>, 0 sat.
import {readFileSync, writeFileSync, mkdirSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
const G16 = process.env.G16 ?? '/home/mrzwets/BCH-projects/verifier.cash/work/real-keys/groth16_cashscript';
const RK = `${G16}/chunked/bn254/real-keys`;
const outDir = process.argv[2] ?? '.'; mkdirSync(outDir, {recursive: true});
const KINDS = new Set(['public-input-binding', 'public-input-encoding', 'invalid-proof-point', 'non-canonical-coordinate', 'g2-subgroup', 'real-public-input', 'real-other-proof', 'staple']);
const key = process.argv[3];
const {load, scoreOf} = await import(pathToFileURL(`${RK}/build-key.mjs`).href);
const {math, tx, vm, script} = await load(key);
const read = (f) => JSON.parse(readFileSync(`${RK}/${f}`, 'utf8'));
const built = read(`${key}.build.json`), rt = read(`${key}.redteam.json`), cv = read(`${key}.cov.report.json`);
const prog = script.buildProgram(); const lock = tx.lockingOf(prog); const hex = (b) => Buffer.from(b).toString('hex');
if (hex(prog.R) !== built.redeemHex) throw new Error('stale build');
const toTx = (unl, outputs = [{lockingHex: '6a', valueSatoshis: '1000'}], locking = hex(lock)) => ({label: 'tx0', version: 2, locktime: 0,
  inputs: unl.map((u) => ({source: {lockingHex: locking, valueSatoshis: '100000'}, unlockingHex: u, sequenceNumber: 0})), outputs});
const lib = (unl, outputs, lockingHex) => { vm.setOutputs(outputs.map((o) => ({lockingBytecode: Buffer.from(o.lockingHex, 'hex'), valueSatoshis: BigInt(o.valueSatoshis)})));
  const L = unl.map(() => (lockingHex ? Buffer.from(lockingHex, 'hex') : lock)); const U = unl.map((u) => Buffer.from(u, 'hex'));
  const s = vm.spendAll(L, U, 'standard'), c = vm.spendAll(L, U, 'consensus');
  return {std: s.every((x) => x.accepted), cons: c.every((x) => x.accepted), perInput: s.map((x, i) => ({role: 'role' + i, unlocking: x.length, opStd: x.opCost, opCons: c[i].opCost, budget: x.budget}))}; };
const wls = []; const g = `realkeys-${key}`;
const add = (id, kind, expect, unl, outputs, extra = {}) => { const l = lib(unl, outputs ?? [{lockingHex: '6a', valueSatoshis: '1000'}], extra.lockingHex);
  if ((expect === 'accept') !== l.cons || (expect === 'accept') !== l.std) throw new Error(`${id}: libauth disagrees with expect ${expect}`);
  const {lockingHex, ...rest} = extra; wls.push({id: `${g}:${id}`, group: g, kind, description: id, expect, defBytes: 0, libauth: l, ...rest, txs: [toTx(unl, outputs ?? undefined, lockingHex)]}); };
let T0 = null;
for (const fx of math.FIXTURES.fixtures) { const T = tx.transactionFor(fx, prog); if (!T0) T0 = T; add(`valid:${fx.id}`, 'valid', 'accept', T.unlockings.map(hex), null, {fills: T.fills, nq: T.core.nq}); }
let n = 0;
for (const r of rt.runs) { if (!KINDS.has(r.kind)) continue; const unl = T0.unlockings.map(hex); for (const p of r.patches) unl[p.input] = p.unlocking; add(`reject:${r.label}`, r.kind, 'reject', unl); n++; }
for (const r of cv.runs) add(`covenant:${r.label}`, r.kind === 'control' ? 'valid' : 'covenant-' + r.kind, r.kind === 'control' ? 'accept' : 'reject', r.tx.unlockingsHex, r.tx.outputs, {lockingHex: r.tx.lockingHex});
vm.setOutputs([{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 1000n}]);
writeFileSync(`${outDir}/${g}.json`, JSON.stringify({source: `groth16_cashscript chunked/bn254/real-keys (${key})`, workloads: wls}, null, 1) + '\n');
console.error(`${g}: ${wls.length} workloads (${wls.filter((w) => w.expect === 'accept').length} accept, ${n} red-team rejections, ${cv.runs.length - 1} covenant rejections)`);
