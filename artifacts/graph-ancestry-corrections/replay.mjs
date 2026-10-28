// Positive-only whole-transaction replay for the four published graph families.
// This consumes only saved artifacts and the immutable graph binder. It does not
// import producers, compilers, planners, provers, or negative-case paths.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { bindDefaultGraph, bindGroupedGraph } from './bind_reference_graphs.mjs';
import {
  ConsensusBch2025, createInstructionSetBch2026, createVirtualMachine,
  createVirtualMachineBch2026, encodeTransactionBch, encodeTransactionInput,
  hash256, ripemd160, secp256k1, sha1, sha256,
} from '@bitauth/libauth';

const here = new URL('.', import.meta.url);
const [sourceCheckout, outputArgument] = process.argv.slice(2);
if (sourceCheckout === undefined || outputArgument === undefined || process.argv.length !== 4) throw new Error('usage: node artifacts/graph-ancestry-corrections/replay.mjs source-checkout new-report.json');
const artifact = (path) => new URL(`../../${path}`, here).pathname;
const reportPath = resolve(outputArgument);
const bytes = (value) => Uint8Array.from(Buffer.from(value, 'hex'));
const hex = (value) => Buffer.from(value).toString('hex');
const read = (path) => readFileSync(path);
const sha256Hex = (value) => createHash('sha256').update(value).digest('hex');
const equalBytes = (a, b) => Buffer.from(a).equals(Buffer.from(b));
const category = bytes('cd'.repeat(32));
const token = (capability, commitment) => ({ amount: 0n, category, nft: { capability, commitment } });
const tokenWithCategory = (tokenCategory, capability, commitment) => ({ amount: 0n, category: tokenCategory, nft: { capability, commitment } });
const canonicalToken = (value) => value === undefined ? null : { amount: value.amount.toString(), category: hex(value.category), nft: value.nft === undefined ? null : { capability: value.nft.capability, commitment: hex(value.nft.commitment) } };
const canonicalOutput = (value) => ({ lockingBytecode: hex(value.lockingBytecode), valueSatoshis: value.valueSatoshis.toString(), ...(value.token === undefined ? {} : { token: canonicalToken(value.token) }) });
const canonicalSource = (values) => values.map(canonicalOutput);
const tokenEqual = (a, b) => JSON.stringify(canonicalToken(a)) === JSON.stringify(canonicalToken(b));
const outputEqual = (a, b) => equalBytes(a.lockingBytecode, b.lockingBytecode) && a.valueSatoshis === b.valueSatoshis && tokenEqual(a.token, b.token);
const hashLineage = (serialized) => {
  const raw = hash256(serialized);
  const independent = createHash('sha256').update(createHash('sha256').update(serialized).digest()).digest();
  if (!Buffer.from(raw).equals(independent)) throw new Error('libauth hash256 disagrees with independent double-SHA256');
  return { serializedSha256: sha256Hex(serialized), hash256RawHex: hex(raw), independentDoubleSha256RawHex: independent.toString('hex'), transactionIdUiOrderHex: hex(Uint8Array.from(raw).reverse()) };
};
const context = (sourceOutputs, transaction, serialized, identity) => {
  const sourceBytes = Buffer.from(JSON.stringify(canonicalSource(sourceOutputs)));
  return { transactionSha256: sha256Hex(serialized), transactionIdUiOrderHex: identity.transactionIdUiOrderHex, sourceOutputsSha256: sha256Hex(sourceBytes), sourceOutputCount: sourceOutputs.length, sourceOutputHashes: sourceOutputs.map((output) => sha256Hex(output.lockingBytecode)), transactionBytes: serialized.length, inputCount: transaction.inputs.length, outputCount: transaction.outputs.length, inputValueSatoshis: sourceOutputs.reduce((sum, output) => sum + output.valueSatoshis, 0n).toString(), outputValueSatoshis: transaction.outputs.reduce((sum, output) => sum + output.valueSatoshis, 0n).toString(), outpointHash: hex(transaction.inputs[0].outpointTransactionHash), outpointIndexes: transaction.inputs.map((input) => input.outpointIndex) };
};

const HUGE = Number.MAX_SAFE_INTEGER;
const oracle = createVirtualMachine(createInstructionSetBch2026(false, { consensus: {
  ...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7,
  maximumMemorySlots: HUGE, maximumStandardLockingBytecodeLength: -1,
  maximumStandardUnlockingBytecodeLength: HUGE, maximumTokenCommitmentLength: 128,
  operationCostBudgetPerByte: HUGE, maximumStackItemLength: HUGE,
  maximumVmNumberByteLength: HUGE, maximumBytecodeLength: HUGE,
  maximumOperationCount: HUGE, maximumStackDepth: HUGE, maximumControlStackDepth: HUGE,
}, ripemd160, secp256k1, sha1, sha256 }));
const modes = { oracle, consensus: createVirtualMachineBch2026(false), standard: createVirtualMachineBch2026(true) };
const helperSha256 = sha256Hex(read(new URL('./bind_reference_graphs.mjs', here).pathname));
if (helperSha256 !== '21da67414e46c66fcefd9935ccc423483283873e012be881705f91eb27b65d75') throw new Error('immutable graph binder hash mismatch');
const transactions = [];
const chains = [];
const addRecord = (family, caseName, unit, sourceOutputs, transaction, serialized, allowedAnchors = new Set()) => {
  const identity = hashLineage(serialized);
  const record = { family, case: caseName, unit, sourceOutputs, transaction, serialized, identity, allowedAnchors };
  const receipt = { family, case: caseName, unit, context: context(sourceOutputs, transaction, serialized, identity), modes: {} };
  for (const [mode, vm] of Object.entries(modes)) {
    const result = vm.verify({ sourceOutputs, transaction });
    receipt.modes[mode] = { accepted: result === true, error: result === true ? null : String(result) };
  }
  transactions.push(receipt);
  return record;
};

const defaultBytes = read(artifact('artifacts/bls-default-fp6-reencoded-v2/encoded-vectors-v1.json'));
if (sha256Hex(defaultBytes) !== '672f206dac00d9626275b17dc63eaf75df252c37b9ec6978558a98ec1c277e17') throw new Error('default source artifact hash mismatch');
const defaultSource = JSON.parse(defaultBytes);
const defaultBound = bindDefaultGraph(defaultBytes);
const defaultRecords = [];
for (const [caseIndex, rootedCase] of defaultBound.cases.entries()) {
  const original = defaultSource.cases[caseIndex];
  const originalInputs = original.steps.map((step, index) => ({ outpointTransactionHash: new Uint8Array(32), outpointIndex: index, sequenceNumber: 0, unlockingBytecode: bytes(step.unlocking) }));
  const originalTransaction = { version: 2, inputs: originalInputs, outputs: [{ lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 1000n }], locktime: 0 };
  const originalSerialized = encodeTransactionBch(originalTransaction);
  const total = 1000n + BigInt(originalSerialized.length);
  const each = total / 35n;
  const remainder = total % 35n;
  const sourceValues = Array.from({ length: 35 }, (_, index) => each + (BigInt(index) < remainder ? 1n : 0n));
  const inputs = rootedCase.steps.map((step, index) => ({ outpointTransactionHash: new Uint8Array(32), outpointIndex: index, sequenceNumber: 0, unlockingBytecode: bytes(step.unlocking) }));
  const transaction = { version: 2, inputs, outputs: [{ lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 1000n }], locktime: 0 };
  const sourceOutputs = rootedCase.steps.map((step, index) => ({ lockingBytecode: bytes(step.locking), valueSatoshis: sourceValues[index] }));
  defaultRecords.push(addRecord('bls-default-fp6', `case-${caseIndex}`, 0, sourceOutputs, transaction, encodeTransactionBch(transaction), new Set(sourceOutputs.map((_, index) => index))));
}
chains.push({ family: 'bls-default-fp6', cases: defaultRecords.map((record) => ({ name: record.case, units: [record] })) });

const groupedBytes = read(artifact('artifacts/historical-frame-repairs/corrected-positives.json'));
const framePath = resolve(sourceCheckout, 'chunked/intratx/historical-frame-repairs.json');
const frameBytes = read(framePath);
const groupedBound = bindGroupedGraph(groupedBytes, frameBytes);
if (sha256Hex(Buffer.from(`${JSON.stringify(groupedBound, null, 2)}\n`)) !== '98d41614aaadc92dd9ee4b1b784b8cc9cf891e74ad4e67532f8c4b72cedcfe60') throw new Error('grouped root-bound packet hash mismatch');
const groupedCases = [];
for (const run of groupedBound.cases) {
  const records = [];
  for (let groupIndex = 0; groupIndex < run.groups.length; groupIndex += 1) {
    const group = run.groups[groupIndex];
    const steps = run.steps.slice(group.lo, group.hi + 1);
    const overrides = steps.map((step, index) => index === 0 && groupIndex > 0 ? { hash: bytes(records[groupIndex - 1].identity.transactionIdUiOrderHex), index: 0 } : { hash: new Uint8Array(32), index: group.lo + index });
    const sourceOutputs = steps.map((step, index) => ({ lockingBytecode: bytes(step.locking), valueSatoshis: 1000n, ...(index === 0 ? { token: token(group.inToken.capability, bytes(group.inToken.commitment)) } : {}) }));
    const transaction = { version: 2, inputs: steps.map((step, index) => ({ outpointTransactionHash: overrides[index].hash, outpointIndex: overrides[index].index, sequenceNumber: 0, unlockingBytecode: bytes(step.unlocking) })), outputs: [{ lockingBytecode: group.outLocking === null ? Uint8Array.of(0x6a) : bytes(group.outLocking), valueSatoshis: 1000n, ...(group.outToken === null ? {} : { token: token(group.outToken.capability, bytes(group.outToken.commitment)) }) }], locktime: 0 };
    const allowed = new Set();
    for (let candidate = 0; candidate < run.groups.length; candidate += 1) for (let stage = run.groups[candidate].lo; stage <= run.groups[candidate].hi; stage += 1) if (candidate === 0 || stage !== run.groups[candidate].lo) allowed.add(stage);
    const record = addRecord('bn254-grouped', run.name, groupIndex, sourceOutputs, transaction, encodeTransactionBch(transaction), allowed);
    if (groupIndex > 0 && !outputEqual(records[groupIndex - 1].transaction.outputs[0], sourceOutputs[0])) throw new Error(`${run.name}/group${groupIndex}: parent/source output seam mismatch`);
    records.push(record);
  }
  groupedCases.push({ name: run.name, units: records });
}
chains.push({ family: 'bn254-grouped', cases: groupedCases });

const makeCovenant = (step, family, outpointHash, outpointIndex) => {
  const locking = bytes(family === 'bn254' ? step.locking : step.lockingHex);
  const unlocking = bytes(family === 'bn254' ? step.unlocking : step.unlockingHex);
  const covenant = family === 'bn254' ? { category, inputCapability: step.kind === 'genesis' ? 'minting' : 'mutable', outputCapability: step.kind === 'terminal' ? 'none' : 'mutable', inCommitment: step.commit, outCommitment: step.outCommit, outLocking: bytes(step.outLocking) } : { category: bytes(step.covenant.category), inputCapability: step.covenant.inputCapability, outputCapability: step.covenant.outputCapability, inCommitment: step.covenant.inCommitment, outCommitment: step.covenant.outCommitment, outLocking: bytes(step.covenant.outLockingHex) };
  const sourceOutputs = [{ lockingBytecode: locking, valueSatoshis: step.kind === 'genesis' ? 3000n : 1000n, token: tokenWithCategory(covenant.category, covenant.inputCapability, bytes(covenant.inCommitment)) }];
  const output = { lockingBytecode: covenant.outLocking, valueSatoshis: 1000n, token: tokenWithCategory(covenant.category, covenant.outputCapability, bytes(covenant.outCommitment)) };
  const outputs = step.kind === 'genesis' ? [output, { lockingBytecode: locking, valueSatoshis: 1000n, token: tokenWithCategory(covenant.category, 'minting', new Uint8Array()) }] : [output];
  const transaction = { version: 2, inputs: [{ outpointTransactionHash: outpointHash, outpointIndex, sequenceNumber: 0, unlockingBytecode: unlocking }], outputs, locktime: 0 };
  return { sourceOutputs, transaction, serialized: encodeTransactionBch(transaction) };
};
const loadCovenant = (family, path, expectedHash) => {
  const raw = read(artifact(path));
  if (sha256Hex(raw) !== expectedHash) throw new Error(`${family} artifact hash mismatch`);
  const packet = JSON.parse(raw);
  return family === 'bn254' ? packet.runs.map((run) => ({ name: run.tag, steps: run.result.steps })) : packet.cases.map((run, index) => ({ name: `case-${index}`, steps: run.steps }));
};
for (const [family, path, expectedHash] of [['bn254', 'artifacts/bn254-covenant-reencoded/encoded-vectors.json', '49f80dfd42790caf26ff56020b0bcd5ec916f9801d972475f147571863c51ed2'], ['bls', 'artifacts/bls-covenant-reencoded/encoded-vectors.json', '2773a19aec6b8cee7f2d2349e7173dc8d575f96d72221731ba8611a3a1aa6871']]) {
  const familyCases = [];
  for (const run of loadCovenant(family, path, expectedHash)) {
    const records = [];
    for (let index = 0; index < run.steps.length; index += 1) {
      const parentHash = index === 0 ? new Uint8Array(32) : bytes(records[index - 1].identity.transactionIdUiOrderHex);
      const built = makeCovenant(run.steps[index], family, parentHash, 0);
      const record = addRecord(family === 'bn254' ? 'bn254-covenant' : 'bls-covenant', run.name, index, built.sourceOutputs, built.transaction, built.serialized, new Set(index === 0 ? [0] : []));
      if (index > 0 && !outputEqual(records[index - 1].transaction.outputs[0], built.sourceOutputs[0])) throw new Error(`${family}/${run.name}/step${index}: parent/source output seam mismatch`);
      records.push(record);
    }
    familyCases.push({ name: run.name, units: records });
  }
  chains.push({ family: family === 'bn254' ? 'bn254-covenant' : 'bls-covenant', cases: familyCases });
}

const availableChains = [];
const chainFromRecords = (family, caseName, records) => {
  const available = new Map();
  const spent = new Set();
  const anchorKeys = new Set();
  const links = [];
  const anchors = [];
  for (let unitIndex = 0; unitIndex < records.length; unitIndex += 1) {
    const record = records[unitIndex];
    for (let inputIndex = 0; inputIndex < record.transaction.inputs.length; inputIndex += 1) {
      const input = record.transaction.inputs[inputIndex];
      const uiHash = hex(input.outpointTransactionHash);
      const key = `${uiHash}:${input.outpointIndex}`;
      const wireHash = encodeTransactionInput(input).slice(0, 32);
      if (uiHash === '00'.repeat(32)) {
        if (!record.allowedAnchors.has(input.outpointIndex)) throw new Error(`${family}/${caseName}/unit${unitIndex}/input${inputIndex}: unexpected synthetic anchor index`);
        if (anchorKeys.has(key)) throw new Error(`${family}/${caseName}/unit${unitIndex}/input${inputIndex}: synthetic anchor reused`);
        anchorKeys.add(key);
        if (!equalBytes(wireHash, new Uint8Array(32))) throw new Error(`${family}/${caseName}/unit${unitIndex}/input${inputIndex}: zero anchor wire mismatch`);
        anchors.push({ unit: unitIndex, input: inputIndex, index: input.outpointIndex });
      } else {
        const parent = available.get(key);
        if (parent === undefined) throw new Error(`${family}/${caseName}/unit${unitIndex}/input${inputIndex}: parent outpoint not generated`);
        if (spent.has(key)) throw new Error(`${family}/${caseName}/unit${unitIndex}/input${inputIndex}: double spend`);
        if (!outputEqual(record.sourceOutputs[inputIndex], parent.output)) throw new Error(`${family}/${caseName}/unit${unitIndex}/input${inputIndex}: source output differs from parent`);
        if (!equalBytes(wireHash, bytes(parent.identity.hash256RawHex))) throw new Error(`${family}/${caseName}/unit${unitIndex}/input${inputIndex}: serialized wire hash differs from parent raw double-SHA256`);
        spent.add(key);
        links.push({ childUnit: unitIndex, childInput: inputIndex, parentUnit: parent.unit, parentOutputIndex: input.outpointIndex, parentRawHashHex: parent.identity.hash256RawHex, childUiOutpointHash: uiHash, childWireOutpointHash: hex(wireHash), sourceOutputEqual: true });
      }
    }
    for (let outputIndex = 0; outputIndex < record.transaction.outputs.length; outputIndex += 1) {
      const identity = record.identity;
      const key = `${identity.transactionIdUiOrderHex}:${outputIndex}`;
      if (available.has(key)) throw new Error(`${family}/${caseName}: duplicate generated outpoint`);
      available.set(key, { unit: unitIndex, output: record.transaction.outputs[outputIndex], identity });
    }
  }
  availableChains.push({ family, case: caseName, transactionCount: records.length, links, anchors, generatedOutputCount: available.size, spentOutputCount: spent.size, unspentGeneratedOutputs: [...available.keys()].filter((key) => !spent.has(key)) });
};
for (const chain of chains) for (const item of chain.cases) chainFromRecords(chain.family, item.name, item.units ?? item);

const modeCounts = Object.fromEntries(Object.keys(modes).map((mode) => {
  const rows = transactions.map((entry) => entry.modes[mode]);
  return [mode, { accepted: rows.filter((row) => row.accepted).length, total: rows.length, failures: transactions.flatMap((entry) => entry.modes[mode].accepted ? [] : [{ family: entry.family, case: entry.case, unit: entry.unit, error: entry.modes[mode].error }]) }];
}));
const familyModeCounts = Object.fromEntries([...new Set(transactions.map((entry) => entry.family))].map((family) => [family, Object.fromEntries(Object.keys(modes).map((mode) => { const rows = transactions.filter((entry) => entry.family === family).map((entry) => entry.modes[mode]); return [mode, { accepted: rows.filter((row) => row.accepted).length, total: rows.length, failures: rows.length - rows.filter((row) => row.accepted).length }]; }))]));
const summary = { caseCount: 12, transactionCount: transactions.length, modeCounts, familyModeCounts, oracleAllAccepted: modeCounts.oracle.accepted === modeCounts.oracle.total, nativeExpectedHoldCount: { consensus: modeCounts.consensus.total - modeCounts.consensus.accepted, standard: modeCounts.standard.total - modeCounts.standard.accepted }, chainCount: availableChains.length, linkedParentCount: availableChains.reduce((sum, chain) => sum + chain.links.length, 0), syntheticAnchorCount: availableChains.reduce((sum, chain) => sum + chain.anchors.length, 0) };
const expectedFailure = (entry, mode) => {
  if (mode === 'oracle') return false;
  if (entry.family === 'bls-default-fp6') return entry.unit === 0;
  if (entry.family === 'bn254-grouped') return entry.unit >= 0 && entry.unit <= 2;
  if (entry.family === 'bn254-covenant') return entry.unit === 24 || entry.unit === 26;
  if (entry.family === 'bls-covenant') return entry.case === 'case-2' && entry.unit >= 1 && entry.unit <= 4;
  throw new Error(`unexpected family ${entry.family}`);
};
const expectedFailurePattern = (entry, mode) => {
  const error = entry.modes[mode].error ?? '';
  if (entry.family === 'bls-covenant') return error.includes('operation cost density limit');
  if (entry.family === 'bls-default-fp6' && mode === 'standard') return error.includes('maximum standard byte length') && error.includes('100000');
  return mode === 'consensus' ? error.includes('maximum bytecode length') && error.includes('10000') : error.includes('excessive unlocking bytecode length') && error.includes('10000');
};
for (const entry of transactions) for (const mode of Object.keys(modes)) {
  const expected = expectedFailure(entry, mode);
  if (entry.modes[mode].accepted === expected) throw new Error(`unexpected ${mode} disposition at ${entry.family}/${entry.case}/unit${entry.unit}`);
  if (expected && !expectedFailurePattern(entry, mode)) throw new Error(`unexpected ${mode} error at ${entry.family}/${entry.case}/unit${entry.unit}: ${entry.modes[mode].error}`);
}
if (summary.transactionCount !== 198 || summary.oracleAllAccepted !== true || modeCounts.consensus.accepted !== 176 || modeCounts.standard.accepted !== 176) throw new Error(`unexpected validation counts: ${JSON.stringify(summary)}`);
const report = { schema: 'graph-ancestry-corrections-positive-whole-transaction-replay/v1', status: 'PASS_ORACLE_198_OF_198_NATIVE_176_OF_198_PER_MODE', positiveOnly: true, sourceHelperSha256: helperSha256, sourceCheckoutInputs: { frameManifestPath: 'chunked/intratx/historical-frame-repairs.json', frameManifestSha256: sha256Hex(frameBytes) }, sourceArtifacts: { default: { path: 'artifacts/bls-default-fp6-reencoded-v2/encoded-vectors-v1.json', sha256: sha256Hex(defaultBytes) }, grouped: { path: 'artifacts/historical-frame-repairs/corrected-positives.json', sha256: sha256Hex(groupedBytes), frameManifestPath: 'chunked/intratx/historical-frame-repairs.json', frameManifestSha256: sha256Hex(frameBytes) }, bn254: { path: 'artifacts/bn254-covenant-reencoded/encoded-vectors.json', sha256: '49f80dfd42790caf26ff56020b0bcd5ec916f9801d972475f147571863c51ed2' }, bls: { path: 'artifacts/bls-covenant-reencoded/encoded-vectors.json', sha256: '2773a19aec6b8cee7f2d2349e7173dc8d575f96d72221731ba8611a3a1aa6871' } }, summary, checks: transactions, ancestry: availableChains, scope: 'Existing positive proof/public/state/token/value/output contexts only. Official double-SHA256 parent IDs, serialized child outpoint hash checks, parent-output/source-output equality, duplicate-output and double-spend checks, and explicit synthetic funding anchors are recorded. No live UTXO, relay, mainnet, compiler, producer, prover, planner, negative-case, or optimization claim.' };
writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx' });
console.log(JSON.stringify({ status: report.status, summary, report: 'validation-report.json' }, null, 2));
