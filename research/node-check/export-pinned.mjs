// Export Track 12 (program-pinned covenant template on the bn-native-sound verifier) as node-check workloads.
//   G16=<groth16_cashscript checkout> node export-pinned.mjs <out-dir> test|sp1-v5|risc0
// Reads groth16_cashscript chunked/bn254/pinned/<key>.pinned.report.json (written by pinned-test.mjs), which holds every
// run's exact transaction (locking, unlockings, outputs). Re-checks each with libauth (patched, BCHN DEFINE accounting,
// consensus and standard) against its expectation, or aborts. Runs marked bench:false (a token output, whose category
// would fail BCHN's token rules before the script verdict matters) are libauth-only and skipped here.
// Each tx: the run's inputs under the run's P2SH32(R), 200,000 sat each (so that every rejection run, e.g. a duplicated 200,000-sat payout, balances and reaches the script), sequence 0; outputs as in the run
// (the controls pay 200,000 sat to a P2PKH plus a 0-sat OP_RETURN memo, so the fee is 400,000 sat).
import {readFileSync, writeFileSync, mkdirSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
const G16 = process.env.G16 ?? '/home/mrzwets/BCH-projects/verifier.cash/work/pinned/groth16_cashscript';
const PD = `${G16}/chunked/bn254/pinned`;
const outDir = process.argv[2] ?? '.'; mkdirSync(outDir, {recursive: true});
const key = process.argv[3];
const vm = await import(pathToFileURL(`${G16}/chunked/bn254/bn-native-sound/vm.mjs`).href);
const rep = JSON.parse(readFileSync(`${PD}/${key}.pinned.report.json`, 'utf8'));
const g = `pinned-${key}`; const wls = []; let skipped = 0;
for (const r of rep.runs) {
  if (r.bench === false) { skipped++; continue; }
  const outs = r.tx.outputs.map((o) => ({lockingBytecode: Buffer.from(o.lockingHex, 'hex'), valueSatoshis: BigInt(o.valueSatoshis)}));
  vm.setOutputs(outs);
  const L = r.tx.unlockingsHex.map(() => Buffer.from(r.tx.lockingHex, 'hex')), U = r.tx.unlockingsHex.map((u) => Buffer.from(u, 'hex'));
  const s = vm.spendAll(L, U, 'standard'), c = vm.spendAll(L, U, 'consensus');
  const lib = {std: s.every((x) => x.accepted), cons: c.every((x) => x.accepted), perInput: s.map((x, i) => ({role: 'role' + i, unlocking: x.length, opStd: x.opCost, opCons: c[i].opCost, budget: x.budget}))};
  if ((r.expect === 'accept') !== lib.cons || (r.expect === 'accept') !== lib.std) throw new Error(`${r.label}: libauth disagrees with expect ${r.expect}`);
  wls.push({id: `${g}:${r.system}:${r.expect === 'accept' ? 'valid' : 'reject'}:${r.label}`, group: g, kind: r.expect === 'accept' ? 'valid' : 'pinned-' + r.kind, description: `[${r.system}] ${r.label}`,
    expect: r.expect, defBytes: 0, libauth: lib,
    txs: [{label: 'tx0', version: 2, locktime: 0, inputs: r.tx.unlockingsHex.map((u) => ({source: {lockingHex: r.tx.lockingHex, valueSatoshis: '200000'}, unlockingHex: u, sequenceNumber: 0})),
      outputs: r.tx.outputs.map((o) => ({lockingHex: o.lockingHex, valueSatoshis: o.valueSatoshis}))}]});
}
vm.setOutputs([{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 1000n}]);
writeFileSync(`${outDir}/${g}.json`, JSON.stringify({source: `groth16_cashscript chunked/bn254/pinned (${key})`, workloads: wls}, null, 1) + '\n');
console.error(`${g}: ${wls.length} workloads (${wls.filter((w) => w.expect === 'accept').length} accept, ${wls.filter((w) => w.expect === 'reject').length} reject; ${skipped} libauth-only runs skipped)`);
