// Portable source14 build/capture driver. --check-plan uses Node built-ins and
// hashes only; --execute is the explicit source-assembly path. No VM, prover,
// fixture producer, benchmark, legacy receipt writer, or protocol producer is
// imported.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, writeFileSync} from 'node:fs';
import {dirname, join, relative, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const MANIFEST_PATH = join(HERE, 'portable-manifest.json');
const manifest = JSON.parse(readFileSync(MANIFEST_PATH, 'utf8'));
const CLOSURE_PATH = join(HERE, manifest.dependencyClosurePath);
const closure = JSON.parse(readFileSync(CLOSURE_PATH, 'utf8'));
const SOURCE = resolve(HERE, manifest.candidateSourceRoot);
const DEPS_RECEIPT = CLOSURE_PATH;
const NATIVE = join(SOURCE, 'chunked/bn254/bn-native-sound');
const args = process.argv.slice(2);
const mode = args[0];
const outIndex = args.indexOf('--out-dir');
const outArg = outIndex < 0 ? undefined : args[outIndex + 1];
const dependencyIndex = args.indexOf('--dependency-root');
const dependencyArg = dependencyIndex < 0 ? undefined : args[dependencyIndex + 1];
if (!['--check-plan', '--execute'].includes(mode)) throw new Error('usage: --check-plan --dependency-root DIR | --execute --dependency-root DIR --out-dir DIR');
if (mode === '--execute' && outArg === undefined) throw new Error('--execute requires an exclusive --out-dir');
if (dependencyArg === undefined) throw new Error('--dependency-root is required');
const DEPENDENCY_ROOT = resolve(dependencyArg);

const sha256 = (data) => createHash('sha256').update(data).digest('hex');
const fileSha = (path) => sha256(readFileSync(path));
const jsonSafe = (value) => value instanceof Uint8Array || Buffer.isBuffer(value)
  ? {type: 'Buffer', data: Array.from(value)}
  : Array.isArray(value) ? value.map(jsonSafe)
  : value && typeof value === 'object' ? Object.fromEntries(Object.entries(value).map(([key, item]) => [key, jsonSafe(item)]))
  : value;
const fail = (message) => { throw new Error(message); };
const equal = (actual, expected, label) => { if (actual !== expected) fail(`${label}: ${actual} != ${expected}`); };
const sourceSeal = () => ({
  files: Object.fromEntries(Object.keys(manifest.sourceFiles).map((path) => [path, {bytes: readFileSync(join(SOURCE, path)).length, sha256: fileSha(join(SOURCE, path))}])),
  fixture: {path: manifest.fixture.path, bytes: readFileSync(join(SOURCE, manifest.fixture.path)).length, sha256: fileSha(join(SOURCE, manifest.fixture.path))},
});
const assertSourceSeal = (seal, label) => {
  for (const [path, expected] of Object.entries(manifest.sourceFiles)) {
    equal(seal.files[path].sha256, expected, `${label} source ${path}`);
  }
  equal(seal.fixture.sha256, manifest.fixture.sha256, `${label} fixture`);
};
const treeSeal = (root) => {
  const files = [];
  const walk = (dir, prefix = '') => {
    for (const entry of readdirSync(join(dir, prefix), {withFileTypes: true}).sort((a, b) => a.name.localeCompare(b.name))) {
      if (entry.isSymbolicLink()) fail(`dependency tree contains symlink: ${join(prefix, entry.name)}`);
      const child = join(prefix, entry.name);
      if (entry.isDirectory()) walk(dir, child); else files.push(child);
    }
  };
  walk(root);
  const records = files.map((path) => `${path.replaceAll('\\', '/')}\0${readFileSync(join(root, path)).length}\0${fileSha(join(root, path))}`);
  return {fileCount: files.length, totalBytes: records.reduce((sum, item) => sum + Number(item.split('\0')[1]), 0), treeSha256: sha256(`${records.join('\n')}\n`)};
};
const dependencySeal = async (resolveEdges = false) => {
  const expected = closure;
  equal(expected.edgeCount, 12, 'dependency edge count');
  const packages = {};
  for (const packageRecord of expected.packages) {
    const name = packageRecord.name;
    const root = resolve(DEPENDENCY_ROOT, packageRecord.rootRelative);
    const metadata = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    equal(metadata.name, name, `${name} package name`);
    equal(metadata.version, packageRecord.version, `${name} package version`);
    equal(fileSha(join(root, 'package.json')), packageRecord.packageJsonSha256, `${name} package.json hash`);
    const tree = treeSeal(root);
    equal(tree.fileCount, packageRecord.fileCount, `${name} package file count`);
    equal(tree.totalBytes, packageRecord.totalBytes, `${name} package byte count`);
    equal(tree.treeSha256, packageRecord.treeSha256, `${name} package tree`);
    packages[name] = {version: metadata.version, root, packageJsonSha256: fileSha(join(root, 'package.json')), ...tree};
  }
  const edges = expected.edges.map((edge) => {
    const actualPath = realpathSync(join(DEPENDENCY_ROOT, edge.package, edge.packageRelativePath));
    equal(fileSha(actualPath), edge.sha256, `dependency edge ${edge.specifier}`);
    return {parent: edge.parent, specifier: edge.specifier, resolved: actualPath, package: edge.package, sha256: edge.sha256};
  });
  if (resolveEdges) {
    for (const edge of expected.edges) {
      const parent = edge.parent.startsWith('chunked/') ? join(SOURCE, edge.parent) : join(DEPENDENCY_ROOT, edge.parent);
      const resolved = realpathSync(fileURLToPath(await import.meta.resolve(edge.specifier, pathToFileURL(parent).href)));
      equal(resolved, realpathSync(join(DEPENDENCY_ROOT, edge.package, edge.packageRelativePath)), `resolved edge ${edge.specifier}`);
    }
  }
  return {edgeCount: edges.length, edges, packages};
};
const baselineSeal = () => {
  return {sourceOnlyExpectedArtifact: true, codeBytes: manifest.expectedArtifact.codeBytes, codeSha256: manifest.expectedArtifact.codeSha256, redeemBytes: manifest.expectedArtifact.redeemBytes, redeemSha256: manifest.expectedArtifact.redeemSha256};
};
const runtimeSeal = (phase) => ({phase, node: process.version, execPath: process.execPath, execArgv: [...process.execArgv], nodeSha256: fileSha(process.execPath), driverSha256: fileSha(fileURLToPath(import.meta.url)), manifestSha256: fileSha(MANIFEST_PATH), dependencyReceiptSha256: fileSha(DEPS_RECEIPT)});
const assertCoveragePlan = () => {
  const expected = {kernelEvents: manifest.coverage.kernelEvents, functionBodies: manifest.coverage.functionBodies, sourceContextsReference: manifest.coverage.sourceContextsReference};
  for (const [name, value] of Object.entries(expected)) {
    if (!Number.isSafeInteger(value) || value <= 0) fail(`coverage.${name} must be a positive safe integer`);
  }
};
const preflight = async (resolveEdges, phase) => {
  assertCoveragePlan();
  if (manifest.driverSha256 !== undefined) equal(fileSha(fileURLToPath(import.meta.url)), manifest.driverSha256, 'driver pin');
  equal(fileSha(process.execPath), manifest.runtime.nodeBinarySha256, 'Node binary pin');
  equal(process.version, manifest.runtime.nodeVersion, 'Node version');
  if (!process.execArgv.includes(manifest.runtime.resolverFlag)) fail('resolver flag is required');
  const source = sourceSeal();
  assertSourceSeal(source, phase);
  const dependencyLink = join(SOURCE, 'node_modules');
  if (!lstatSync(dependencyLink).isSymbolicLink()) fail('isolated source staging requires a node_modules symlink');
  equal(realpathSync(dependencyLink), realpathSync(DEPENDENCY_ROOT), 'source dependency link target');
  const dependency = await dependencySeal(resolveEdges);
  const baseline = baselineSeal();
  return {source, dependency, baseline, runtime: runtimeSeal(phase)};
};

if (mode === '--check-plan') {
  console.log(JSON.stringify({schema: 'bn-c-first-prefix-extraction-build-plan/v2', status: 'CHECK_PLAN_PASS_NO_DYNAMIC_IMPORT', selectedCandidate: manifest.selectedCandidate, ...await preflight(false, 'plan'), outputPolicy: 'execute requires a new absent --out-dir'}, null, 2));
} else {
  const out = resolve(outArg);
  if (existsSync(out)) fail(`exclusive output already exists: ${out}`);
  const controls = manifest.runtime.controls;
  for (const name of controls) delete process.env[name];
  const envBefore = Object.fromEntries(controls.map((name) => [name, process.env[name] ?? null]));
  if (controls.some((name) => process.env[name] !== undefined)) fail('controlled environment was not cleared');
  const preflightBefore = await preflight(true, 'before');
  const sourceBefore = preflightBefore.source;
  const dependencyBefore = preflightBefore.dependency;
  const baseline = preflightBefore.baseline;
  const runtimeBefore = preflightBefore.runtime;
  mkdirSync(out, {recursive: false});
  writeFileSync(join(out, 'status.json'), JSON.stringify({schema: 'bn-c-first-prefix-extraction-build-status/v2', status: 'RUNNING_SOURCE_ASSEMBLY_ONLY', vm: false, prover: false, benchmark: false, fixtureGeneration: false}, null, 2) + '\n');

  const {Asm} = await import(pathToFileURL(join(NATIVE, 'asm.mjs')).href);
  const captures = [];
  const contexts = new Set();
  const observations = [];
  const roleObjects = [];
  const physicalSize = (asm) => {
    let size = asm.st.length + asm.alt.length;
    for (const [name, count] of asm.piles) {
      const present = asm.st.includes(name) || asm.alt.includes(name);
      if (!present) continue;
      if (count === null) {
        const bound = name === 'WSp' ? 12 : name === 'Dp' ? 4 : 0;
        if (bound === 0) fail(`unknown varying pile ${name}`);
        size += bound - 1;
      } else size += count - 1;
    }
    return size;
  };
  const observe = (asm, label) => observations.push({label, mainWords: asm.st.length, altWords: asm.alt.length, physicalWords: physicalSize(asm), main: [...asm.st], alt: [...asm.alt], piles: [...asm.piles.entries()]});
  const recordContext = (asm, label) => { contexts.add(asm); observe(asm, label); if (label) asm.__captureEventCount = (asm.__captureEventCount ?? 0) + 1; };
  const originalKernel = Asm.prototype.kernel;
  Asm.prototype.kernel = function (K, outs, options = {}) {
    const before = [...this.st], altBefore = [...this.alt], pilesBefore = [...this.piles.entries()], start = this.code.length;
    observations.push({label: 'kernel:before', mainWords: before.length, altWords: altBefore.length, physicalWords: physicalSize({st: before, alt: altBefore, piles: pilesBefore}), main: before, alt: altBefore, piles: pilesBefore});
    const result = originalKernel.call(this, K, outs, options);
    observe(this, 'kernel:after');
    const row = {asm: this, start, end: this.code.length, outs: [...outs], before, altBefore, after: [...this.st], altAfter: [...this.alt], pilesBefore, pilesAfter: [...this.piles.entries()], beforePhysical: physicalSize({st: before, alt: altBefore, piles: pilesBefore}), afterPhysical: physicalSize(this), nodes: K.nodes.map((node) => ({id: node.id, op: node.op, args: [...node.args], name: node.name, value: node.value === undefined ? undefined : String(node.value)})), kernelOuts: [...K.outs], rawBytes: result.code.length, rawHex: Buffer.from(result.code).toString('hex'), rawSha256: sha256(Buffer.from(result.code))};
    captures.push(row); recordContext(this, 'kernel'); return result;
  };
  const originalMark = Asm.prototype.mark;
  Asm.prototype.mark = function (name) { const initial = JSON.stringify(this.st) === JSON.stringify(['C', 'S', 'DS', 'FILL']) || JSON.stringify(this.st) === JSON.stringify(['C', 'S', 'HAND', 'DS', 'FILL']) || JSON.stringify(this.st) === JSON.stringify(['DG', 'STMT', 'S', 'HAND', 'DS', 'FILL', 'WQ']); if (name === 'layout' && initial && !roleObjects.includes(this)) roleObjects.push(this); const result = originalMark.call(this, name); recordContext(this, 'mark'); return result; };
  for (const name of ['emit', 'push', 'pushBytes', 'pushPile', 'pileTake', 'pileDone', 'toAlt', 'fromAlt', 'peekAlt', 'pushAltPile', 'altPileTake', 'pick', 'roll', 'drop', 'rename', 'op', 'invoke', 'ifElse', 'loop', 'arrange', 'arrangeAll', 'arrangeAbove']) {
    const original = Asm.prototype[name]; Asm.prototype[name] = function (...values) { recordContext(this, `${name}:before`); const result = original.apply(this, values); recordContext(this, `${name}:after`); return result; };
  }
  const {buildProgram} = await import(pathToFileURL(join(NATIVE, 'script.mjs')).href);
  const built = buildProgram();
  const preflightAfter = await preflight(true, 'after');
  const sourceAfter = preflightAfter.source; assert.deepEqual(sourceAfter, sourceBefore, 'source changed during prototype assembly');
  const dependencyAfter = preflightAfter.dependency; assert.deepEqual(dependencyAfter, dependencyBefore, 'dependencies changed during prototype assembly');
  const runtimeAfter = preflightAfter.runtime; assert.deepEqual(runtimeAfter.execArgv, runtimeBefore.execArgv, 'runtime flags changed');
  assertSourceSeal(sourceAfter, 'after');

  // Persist the raw build before any coverage or span-selection assertion.  A
  // later guard failure must not discard candidate bytes or duplicate events.
  const body = Object.fromEntries(Object.entries(built.funcCodes).map(([name, bytes]) => [name, {bytes: bytes.length, sha256: sha256(Buffer.from(bytes)), codeHex: Buffer.from(bytes).toString('hex')}]))
  const marks = jsonSafe(built.marks);
  const artifact = {codeHex: Buffer.from(built.code).toString('hex'), codeBytes: built.code.length, codeSha256: sha256(Buffer.from(built.code)), redeemHex: Buffer.from(built.R).toString('hex'), redeemBytes: built.R.length, redeemSha256: sha256(Buffer.from(built.R)), codePiecesHex: built.pieces.map((piece) => Buffer.from(piece).toString('hex')), codePieces: built.pieces.map((piece) => piece.length), layout: jsonSafe(built.lay), functionBodies: body, roleFunctionIds: [0, 1, 2].map((i) => built.info.roleId + i), roleByteLengths: built.info.roles, prologueBytes: built.info.prologue, window: built.info.WIN, marks};
  equal(artifact.codeBytes, manifest.expectedArtifact.codeBytes, 'generated code byte length');
  equal(artifact.codeSha256, manifest.expectedArtifact.codeSha256, 'generated code hash');
  equal(artifact.redeemBytes, manifest.expectedArtifact.redeemBytes, 'generated redeem byte length');
  equal(artifact.redeemSha256, manifest.expectedArtifact.redeemSha256, 'generated redeem hash');
  const rawCaptures = captures.map(({asm, ...row}) => row);
  writeFileSync(join(out, 'raw-build-snapshot.json'), JSON.stringify({schema: 'bn-c-first-prefix-extraction-raw-build-snapshot/v2', status: 'RAW_BUILD_CAPTURED_BEFORE_COVERAGE_GUARDS', selectedCandidate: manifest.selectedCandidate, source: {before: sourceBefore, after: sourceAfter}, dependency: {before: dependencyBefore, after: dependencyAfter}, runtime: {before: runtimeBefore, after: runtimeAfter}, baseline, artifact, captures: jsonSafe(rawCaptures)}, null, 2) + '\n');

  equal(captures.length, manifest.coverage.kernelEvents, 'kernel event coverage');
  equal(Object.keys(built.funcCodes).length, manifest.coverage.functionBodies, 'function body coverage');
  equal(contexts.size, manifest.coverage.sourceContextsReference, 'source context coverage');
  const mark = (name) => { const result = built.marks.filter((item) => item.name === name); if (result.length !== 1) fail(`expected one ${name} mark`); return result[0]; };
  const twMark = mark('r2:t:W'), bindingMark = mark('r2:binding');
  const ownerOf = (asm) => Object.entries(built.funcCodes).find(([, bytes]) => Buffer.from(bytes).equals(Buffer.from(asm.code)))?.[0] ?? null;
  const locate = (rawHex) => {
    const raw = Buffer.from(rawHex, 'hex'); const places = [];
    for (const [owner, bytes] of Object.entries(built.funcCodes)) {
      const bodyBytes = Buffer.from(bytes);
      for (let start = 0; start + raw.length <= bodyBytes.length; start++) if (bodyBytes.subarray(start, start + raw.length).equals(raw)) places.push({owner, start, end: start + raw.length});
    }
    return places;
  };
  const classifyTransient = (row) => {
    const refs = row.nodes.filter((node) => node.op === 'ref').map((node) => node.name);
    const outs = row.outs.join(',');
    if (outs === 'X0,X1,Y0,Y1,Fp,Fm,chk' && refs.includes('t')) return 'BDBL';
    if (outs === 'dx0,dx1,dc0,dc1,dl0,dl1,Fp,Fm') return 'DSTEP';
    return `transient:${outs}`;
  };
  const kernels = captures.map((row) => {
    const exactOwner = ownerOf(row.asm); const places = exactOwner === null ? locate(row.rawHex) : [];
    const match = exactOwner === null && places.length === 1 ? places[0] : null;
    const out = {...row, owner: exactOwner ?? match?.owner ?? classifyTransient(row), catalogBound: exactOwner !== null || match !== null, catalogStart: exactOwner !== null ? row.start : match?.start ?? null, catalogEnd: exactOwner !== null ? row.end : match?.end ?? null};
    delete out.asm; return out;
  });
  const tw = kernels.filter((row) => row.owner === 'role2' && row.start === twMark.roff && row.end === bindingMark.roff);
  if (tw.length < 1) fail(`expected at least one candidate role2 t:W kernel, got ${tw.length}`);
  const twProjection = (row) => ({start: row.start, end: row.end, outs: row.outs, before: row.before, altBefore: row.altBefore, after: row.after, altAfter: row.altAfter, pilesBefore: row.pilesBefore, pilesAfter: row.pilesAfter, nodes: row.nodes, kernelOuts: row.kernelOuts, rawBytes: row.rawBytes, rawHex: row.rawHex, rawSha256: row.rawSha256});
  const twReferenceProjection = JSON.stringify(twProjection(tw[0]));
  for (const [index, row] of tw.entries()) equal(JSON.stringify(twProjection(row)), twReferenceProjection, `duplicate t:W projection ${index}`);
  const twProjectionSha256 = sha256(twReferenceProjection);
  const frameSummary = {contexts: contexts.size, observedStates: observations.length, roleObjects: roleObjects.length, maxObservedPhysicalWords: Math.max(...observations.map((item) => item.physicalWords)), maxObservedMainWords: Math.max(...observations.map((item) => item.mainWords)), maxObservedAltWords: Math.max(...observations.map((item) => item.altWords)), tW: {start: twMark.off, endExclusive: bindingMark.off, eventCount: tw.length, eventIndexes: kernels.map((row, index) => row.owner === 'role2' && row.start === twMark.roff && row.end === bindingMark.roff ? index : null).filter((index) => index !== null), duplicateProjectionsAgree: true, projectionSha256: twProjectionSha256, deduplicatedForSpanAudit: true, bytes: tw[0].end - tw[0].start, entryWords: tw[0].before.length, postWords: tw[0].after.length, entryPhysical: tw[0].beforePhysical, postPhysical: tw[0].afterPhysical, rawSha256: tw[0].rawSha256, nodes: tw[0].nodes}};
  writeFileSync(join(out, 'candidate-catalog.json'), JSON.stringify({schema: 'bn-degree6-sign-fold-catalog/v1', artifact}, null, 2) + '\n');
  writeFileSync(join(out, 'kernel-capture.json'), JSON.stringify({schema: 'bn-degree6-sign-fold-kernel-capture/v1', kernels, frames: frameSummary, observations}, null, 2) + '\n');
  writeFileSync(join(out, 'receipt.json'), JSON.stringify({schema: 'bn-c-first-prefix-extraction-build-receipt/v2', status: 'PASS_SOURCE_ASSEMBLY_CAPTURE_ONLY', selectedCandidate: manifest.selectedCandidate, vm: false, prover: false, benchmark: false, fixtureGeneration: false, envBefore, source: {before: sourceBefore, after: sourceAfter}, dependency: {before: dependencyBefore, after: dependencyAfter}, runtime: {before: runtimeBefore, after: runtimeAfter}, baseline, candidate: {codeSha256: artifact.codeSha256, redeemSha256: artifact.redeemSha256, codeBytes: artifact.codeBytes, redeemBytes: artifact.redeemBytes, functionBodies: Object.keys(body).length, kernelEvents: kernels.length, transientEvents: kernels.filter((row) => !row.catalogBound).length, frames: frameSummary}}, null, 2) + '\n');
  console.log(JSON.stringify({status: 'PASS_SOURCE_ASSEMBLY_CAPTURE_ONLY', output: out, kernelEvents: kernels.length, functionBodies: Object.keys(body).length, contexts: contexts.size, tW: frameSummary.tW}, null, 2));
}
