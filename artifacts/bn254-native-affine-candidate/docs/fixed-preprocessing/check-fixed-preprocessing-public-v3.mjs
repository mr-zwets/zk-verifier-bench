import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, realpathSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

// This checker is deliberately self-contained apart from the ordinary,
// pinned BN254 field/Miller library supplied by the caller in --execute mode.
// It never imports the verifier, producer, assembler, catalog, or private
// source tree.  --check-plan is the safe default; --execute is an explicit
// later action because it performs Miller arithmetic.
const HERE = new URL('.', import.meta.url);
const fixturePath = new URL('../../source/chunked/bn254/densless-recovered/public-fixtures.json', HERE);
const inputsPath = new URL('./certificate-inputs.json', HERE);
const manifestPath = new URL('./proof-manifest-v3.json', HERE);
const sha256 = (data) => createHash('sha256').update(data).digest('hex');
const textSha = (url) => sha256(readFileSync(url));
const json = (url) => JSON.parse(readFileSync(url, 'utf8'));
const modFor = (p) => (x) => ((x % p) + p) % p;

const args = process.argv.slice(2);
const execute = args.includes('--execute');
const valueAfter = (name) => { const i = args.indexOf(name); return i < 0 ? undefined : args[i + 1]; };
const nobleEntry = valueAfter('--noble-entry');
if (args.includes('--check-plan') && execute) throw new Error('choose one action');
if (!args.includes('--check-plan') && !execute) throw new Error('explicit --check-plan or --execute required');

const manifest = json(manifestPath);
assert.equal(manifest.schema, 'pub-fixed-preprocessing-public-proof/v3');
assert.equal(manifest.math.source, 'independent raw Miller + local quotient arithmetic');
const fixtureBytes = readFileSync(fixturePath);
const inputBytes = readFileSync(inputsPath);
assert.equal(sha256(fixtureBytes), manifest.inputs.fixture.sha256);
assert.equal(sha256(inputBytes), manifest.inputs.certificateInputs.sha256);
const fixture = JSON.parse(fixtureBytes);
const inputs = JSON.parse(inputBytes);
assert.equal(fixture.artifactSha256, manifest.inputs.fixture.artifactSha256);
assert.equal(inputs.schema, 'bn-c-first-prefix-extraction/vk-table-certificate/v6');
const p = BigInt(inputs.field.p);
const r = BigInt(inputs.field.r);
const bnX = BigInt(inputs.field.bnX);
assert.equal(p, 21888242871839275222246405745257275088696311157297823662689037894645226208583n);
assert.equal(r, 21888242871839275222246405745257275088548364400416034343698204186575808495617n);
assert.equal(bnX, 4965661367192848881n);
const mod = modFor(p);
assert.deepEqual(inputs.field.flattenBasisDegrees, [0, 2, 4, 1, 3, 5]);

const closurePath = new URL('../../source/reproduce-v2/dependency-closure.json', HERE);
assert.equal(sha256(readFileSync(closurePath)), manifest.dependencies.closureSha256);
const closure = json(closurePath);
assert.equal(closure.edgeCount, 12);
assert.equal(closure.packages.length, 3);
assert.equal(manifest.dependencies.edgeCount, closure.edgeCount);
for (const expected of manifest.dependencies.packages) {
  const actual = closure.packages.find((pkg) => pkg.name === expected.name);
  assert.ok(actual, `manifest package ${expected.name}`);
  for (const field of ['version', 'rootRelative', 'packageJsonSha256', 'fileCount', 'totalBytes', 'treeSha256']) assert.equal(actual[field], expected[field], `${expected.name} ${field}`);
}
const treeSeal = (root) => {
  const records = [];
  const walk = (relative = '') => {
    const dir = join(root, relative);
    for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const child = relative ? join(relative, entry.name) : entry.name;
      const full = join(root, child);
      assert.ok(!entry.isSymbolicLink(), `dependency symlink ${child}`);
      if (entry.isDirectory()) walk(child);
      else records.push(`${child.replaceAll('\\', '/') }\0${readFileSync(full).length}\0${sha256(readFileSync(full))}`);
    }
  };
  walk();
  return { fileCount: records.length, totalBytes: records.reduce((n, x) => n + Number(x.split('\0')[1]), 0), treeSha256: sha256(`${records.join('\n')}\n`) };
};
const dependencyRoot = valueAfter('--dependency-root');
if (execute) {
  assert.ok(dependencyRoot, '--dependency-root is required for --execute');
  assert.ok(nobleEntry, '--noble-entry is required for --execute');
}
if (dependencyRoot) {
  const root = resolve(dependencyRoot);
  for (const pkg of closure.packages) {
    const packageRoot = join(root, pkg.rootRelative);
    const metadata = JSON.parse(readFileSync(join(packageRoot, 'package.json'), 'utf8'));
    assert.equal(metadata.name, pkg.name);
    assert.equal(metadata.version, pkg.version);
    assert.equal(sha256(readFileSync(join(packageRoot, 'package.json'))), pkg.packageJsonSha256);
    assert.deepEqual(treeSeal(packageRoot), { fileCount: pkg.fileCount, totalBytes: pkg.totalBytes, treeSha256: pkg.treeSha256 });
  }
  for (const edge of closure.edges) {
    const packageRecord = closure.packages.find((pkg) => pkg.name === edge.package);
    const edgePath = join(root, packageRecord.rootRelative, edge.packageRelativePath);
    assert.equal(sha256(readFileSync(edgePath)), edge.sha256, `dependency edge ${edge.specifier}`);
  }
  if (nobleEntry) assert.equal(resolve(nobleEntry), join(root, '@noble/curves/esm/bn254.js'));
  const nobleEdges = closure.edges.filter((edge) => edge.parent.startsWith('@noble/'));
  assert.equal(nobleEdges.length, 5, 'ordinary-library ESM edge count');
  if (process.execArgv.includes('--experimental-import-meta-resolve')) {
    for (const edge of nobleEdges) {
      const parent = realpathSync(join(root, edge.parent));
      const resolved = realpathSync(fileURLToPath(await import.meta.resolve(edge.specifier, pathToFileURL(parent).href)));
      const expected = realpathSync(join(root, closure.packages.find((pkg) => pkg.name === edge.package).rootRelative, edge.packageRelativePath));
      assert.equal(resolved, expected, `resolved edge ${edge.specifier}`);
    }
  } else if (execute || args.includes('--resolve-edges')) {
    throw new Error('--experimental-import-meta-resolve is required for ordinary-library ESM checks');
  }
  if (execute) {
    assert.ok(process.execArgv.includes('--experimental-import-meta-resolve'), 'actual ESM resolution flag required');
  }
}

const fixtureWords = () => {
  const out = [];
  for (const name of ['alpha', 'beta', 'gamma', 'delta']) {
    for (const coordinate of ['x', 'y']) {
      const value = fixture.vk[name][coordinate];
      if (typeof value === 'object') out.push(value.c0, value.c1);
      else out.push(value);
    }
  }
  for (const point of fixture.vk.ic) out.push(point.x, point.y);
  return out;
};
const words = fixtureWords();
assert.equal(words.length, 20);
assert.deepEqual(words, inputs.vkWords);
assert.equal(sha256(Buffer.from(words.join(','))), inputs.vkWordsSha256);
for (const row of Object.values(inputs.tables)) {
  assert.equal(row.length, 7);
  assert.equal(row[6], '1');
  row.slice(0, 6).forEach((x) => assert.ok(0n <= BigInt(x) && BigInt(x) < p));
}

const result = {
  schema: 'pub-fixed-preprocessing-public-proof-result/v3',
  status: execute ? 'RUNNING_EXPLICIT_MATH' : 'PASS_STATIC_PUBLIC_PLAN',
  scope: 'raw Miller to degree-six monic quotient-class relation for the fixed public VK/table inputs',
  notClaimed: [
    'native byte emission (owned by the current PUB003 v9 owner)',
    'VM/compiler/protocol equivalence',
    'arbitrary VK or arbitrary advice',
    'complete verifier or qualification/publication admission'
  ],
  inputs: {
    fixtureSha256: manifest.inputs.fixture.sha256,
    certificateInputsSha256: manifest.inputs.certificateInputs.sha256,
    fieldPrime: inputs.field.p,
    scalarOrder: inputs.field.r,
    polynomialModulus: inputs.field.modulus,
    flattenBasisDegrees: inputs.field.flattenBasisDegrees,
    tableRows: Object.keys(inputs.tables),
    tableRowHash: Object.fromEntries(Object.entries(inputs.tables).map(([name, row]) => [name, sha256(Buffer.from(row.join(',')))]))
  },
  ordinaryLibrary: manifest.ordinaryLibrary,
  independence: {
    pairing: 'ordinaryLibrary.bn254.pairing(P,Q,false), raw Miller value; no final exponentiation',
    quotient: 'local Fp[X]/(X^12-18X^6+82) multiplication, reduction, and six-by-six monic solve',
    ownerInputs: 'only shipped public-fixtures.json and v6 certificate-inputs.json',
    sourceImports: 0,
    privateCatalogInputs: false,
    vmRuns: 0,
    producerRuns: 0
  }
};

if (!execute) {
  console.log(JSON.stringify(result, null, 2));
  process.exit(0);
}

if (!nobleEntry) throw new Error('--noble-entry is required with --execute');
const nobleBytes = readFileSync(resolve(nobleEntry));
assert.equal(sha256(nobleBytes), manifest.ordinaryLibrary.entrySha256, 'ordinary field library entry pin');
const { bn254 } = await import(pathToFileURL(resolve(nobleEntry)).href);
const { Fp, Fr, Fp12: F12 } = bn254.fields;
assert.equal(Fp.ORDER, p, 'ordinary library field prime');
assert.equal(Fr.ORDER, r, 'ordinary library scalar order');

const reduceM = (a) => {
  const out = a.map(mod);
  for (let i = out.length - 1; i >= 12; i--) {
    const c = out[i];
    if (!c) continue;
    out[i] = 0n;
    out[i - 6] = mod(out[i - 6] + 18n * c);
    out[i - 12] = mod(out[i - 12] - 82n * c);
  }
  return Array.from({ length: 12 }, (_, i) => out[i] ?? 0n);
};
const pmul = (a, b) => {
  const out = Array(a.length + b.length - 1).fill(0n);
  for (let i = 0; i < a.length; i++) for (let j = 0; j < b.length; j++) out[i + j] = mod(out[i + j] + a[i] * b[j]);
  return reduceM(out);
};
const psubst = (a, k) => { let q = 1n; return a.map((x) => { const y = mod(x * q); q = mod(q * k); return y; }); };
const pconj = (a) => psubst(a, p - 1n);
const SLOT_DEG = [0, 2, 4, 1, 3, 5];
const flatten = (x) => {
  const slots = [x.c0.c0, x.c0.c1, x.c0.c2, x.c1.c0, x.c1.c1, x.c1.c2];
  const out = Array(12).fill(0n);
  slots.forEach((s, i) => { const d = SLOT_DEG[i]; out[d] = mod(s.c0 - 9n * s.c1); out[d + 6] = mod(s.c1); });
  return out;
};
const fromPoly = (a) => {
  const slots = SLOT_DEG.map((d) => ({ c0: mod(a[d] + 9n * a[d + 6]), c1: mod(a[d + 6]) }));
  return F12.create({ c0: { c0: slots[0], c1: slots[1], c2: slots[2] }, c1: { c0: slots[3], c1: slots[4], c2: slots[5] } });
};
const inv = (x) => Fp.inv(mod(x));
const solve = (A, b) => {
  const a = A.map((row, i) => [...row, b[i]].map(mod));
  for (let col = 0; col < a.length; col++) {
    let pivot = col; while (pivot < a.length && a[pivot][col] === 0n) pivot++;
    assert.ok(pivot < a.length, 'singular monic quotient chart');
    [a[col], a[pivot]] = [a[pivot], a[col]];
    const iv = inv(a[col][col]); a[col] = a[col].map((x) => mod(x * iv));
    for (let row = 0; row < a.length; row++) if (row !== col && a[row][col]) {
      const k = a[row][col]; a[row] = a[row].map((x, j) => mod(x - k * a[col][j]));
    }
  }
  return a.map((row) => row.at(-1));
};
const monic = (f) => {
  const cols = [0, 2, 4, 6, 8, 10].map((d) => reduceM(Array(d).fill(0n).concat(f)));
  const s = solve([6, 7, 8, 9, 10, 11].map((row) => cols.map((c) => c[row])), [1n, 0n, 0n, 0n, 0n, 0n]);
  const out = Array(12).fill(0n);
  cols.forEach((c, j) => c.forEach((x, i) => { out[i] = mod(out[i] + s[j] * x); }));
  assert.ok(out.slice(7).every((x) => x === 0n) && out[6] === 1n);
  return out.slice(0, 7);
};
const classEven = (a, b) => reduceM(pmul(a, pconj(b))).filter((x, i) => i % 2).every((x) => x === 0n);
const pointG1 = (x) => bn254.G1.Point.fromAffine({ x: BigInt(x.x), y: BigInt(x.y) });
const pointG2 = (x) => bn254.G2.Point.fromAffine({ x: { c0: BigInt(x.x.c0), c1: BigInt(x.x.c1) }, y: { c0: BigInt(x.y.c0), c1: BigInt(x.y.c1) } });
const powFp12 = (x, n) => F12.pow(x, n);
const VK = fixture.vk;
const gamma = pointG2(VK.gamma);
const ic = VK.ic.map(pointG1);
const mic = ic.map((point) => bn254.pairing(point, gamma, false));
const mab = bn254.pairing(pointG1(VK.alpha), pointG2(VK.beta), false);
const eta = (() => {
  const x = fromPoly([0n, 1n, ...Array(10).fill(0n)]);
  const frob = flatten(F12.frobeniusMap(x, 2));
  assert.ok(frob.every((value, index) => index === 1 || value === 0n), 'Frobenius^2(X) basis support');
  const e = frob[1];
  assert.notEqual(e, 0n, 'Frobenius^2(X) coefficient');
  assert.equal(Fp.pow(e, 6n), 1n, 'ETA order divides six');
  assert.equal(Fp.pow(e, 3n), p - 1n, 'ETA is primitive sixth root');
  assert.notEqual(Fp.pow(e, 2n), 1n, 'ETA is not order two');
  return e;
})();
const targetR = [1, 2].map((k) => [0, 1].map((i) => monic(flatten(powFp12(mic[k], i ? p : 1n)))));
const targetShift = [1, 2].map((k) => [0, 1].map((i) => monic(flatten(powFp12(mic[k], p ** BigInt(i + 2))))));
const targetEtaShift = targetR.map((row) => row.map((x) => psubst(x, eta)));
targetShift.forEach((row, k) => row.forEach((x, i) => assert.deepEqual(x, targetEtaShift[k][i], `eta shift k=${k} i=${i}`)));
for (const k of [1, 2]) for (let i = 0; i < 4; i++) {
  const raw = powFp12(mic[k], p ** BigInt(i));
  const rep = i < 2 ? targetR[k - 1][i] : targetEtaShift[k - 1][i - 2];
  assert.ok(flatten(raw).some((x) => x !== 0n));
  assert.ok(classEven(flatten(raw), rep), `R quotient class k=${k} i=${i}`);
}
let correction = F12.ONE;
for (const k of [1, 2]) for (let i = 0; i < 4; i++) correction = F12.mul(correction, powFp12(mic[k], p ** BigInt(i)));
const rawConst = F12.mul(F12.mul(mab, mic[0]), F12.pow(F12.inv(correction), 1n << 64n));
const targetConst = monic(flatten(rawConst));
assert.ok(flatten(rawConst).some((x) => x !== 0n));
assert.ok(classEven(flatten(rawConst), targetConst), 'Rconst quotient class');
const hashWords = (x) => sha256(Buffer.from(x.map((v) => v.toString()).join(',')));
const hashes = { R00: hashWords(targetR[0][0]), R01: hashWords(targetR[0][1]), R10: hashWords(targetR[1][0]), R11: hashWords(targetR[1][1]), Rconst: hashWords(targetConst) };
for (const [name, hash] of Object.entries(hashes)) assert.equal(hash, result.inputs.tableRowHash[name], `${name} table binding`);
result.status = 'PASS_PUBLIC_RAW_MILLER_MONIC_QUOTIENT_TRANSFER';
result.executedMath = { eta: eta.toString(), targetHashes: hashes, rawPairingCalls: 4, tableRows: 5, quotientChecks: 9, finalExponentiation: false };
console.log(JSON.stringify(result, (_, x) => typeof x === 'bigint' ? x.toString() : x, 2));
