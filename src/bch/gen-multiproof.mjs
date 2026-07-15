// Mint MULTIPLE distinct, valid Groth16 proofs under the SAME verifying key, so
// the benchmark can EMPIRICALLY confirm the singleton verifier is runtime-general
// (one fixed locking script verifies many different proofs) rather than a proof
// baked into the program. The verification equation is solved in the exponent over
// Fr exactly as gen-pairing-vectors.ts does -- but here alpha/beta/gamma/delta/IC
// (the VK) are held FIXED to the committed instance, and only the per-proof data
// varies: fresh public inputs (in0,in1) + fresh A,B, with C solved so the product
// is 1. Because the VK is unchanged, the on-chain locking (Groth16Verify, VK baked)
// is byte-for-byte the SAME for every proof -- we reuse the committed lockingOK and
// only the unlocking (A,B,C,in0,in1 witness) differs.
//
//   c_s = (a_s*b_s - alpha_s*beta_s - vkx_s*gamma_s) * delta_s^{-1}   (mod r)
//
// Each minted proof is verified two ways: in @noble/curves (the oracle) and on the
// loosened BCH 2026 VM against the actual committed locking. A tampered public
// input (in1+1) is included per proof and must be REJECTED. Output:
//   src/bch/groth16-singleton-multiproof-vectors.json
//
//   npm run gen:multiproof            mint EXTRA_PROOFS (default 3) extra proofs
//
// Lives in the verifier repo (not the contracts repo): it has NO cashc/.cash
// dependency — it reuses the COMMITTED singleton locking from the vectors JSON and
// only mints fresh witnesses. Run this before the contracts' build_vectors.mjs, which
// reads the multiproof JSON this writes. Paths are repo-root-relative (run via npm).
import { readFileSync, writeFileSync } from 'node:fs';
import {
  hexToBin, binToHex, bigIntToVmNumber,
  createVirtualMachine, createInstructionSetBch2026, createVirtualMachineBch2026,
  createTestAuthenticationProgramBch, ConsensusBch2025, ripemd160, secp256k1, sha1, sha256,
} from '@bitauth/libauth';
import { bn254 } from '@noble/curves/bn254.js';

const EXTRA = Number(process.env.EXTRA_PROOFS ?? 3);
const r = bn254.fields.Fr.ORDER;
const Fp12 = bn254.fields.Fp12;
const modr = (x) => ((x % r) + r) % r;
const invr = (x) => bn254.fields.Fr.inv(modr(x));
const G1 = (k) => bn254.G1.Point.BASE.multiply(modr(k));
const G2 = (k) => bn254.G2.Point.BASE.multiply(modr(k));

const HUGE = Number.MAX_SAFE_INTEGER;
const loosened = {
  ...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7,
  maximumMemorySlots: HUGE, maximumStandardLockingBytecodeLength: -1,
  maximumStandardUnlockingBytecodeLength: HUGE, maximumTokenCommitmentLength: 128,
  operationCostBudgetPerByte: HUGE, maximumStackItemLength: HUGE, maximumVmNumberByteLength: HUGE,
  maximumStackDepth: HUGE, maximumControlStackDepth: HUGE, maximumBytecodeLength: HUGE, maximumOperationCount: HUGE,
};
const looseVm = createVirtualMachine(createInstructionSetBch2026(false, { consensus: loosened, ripemd160, secp256k1, sha1, sha256 }));
const realVm = createVirtualMachineBch2026(false);
const evalPair = (vm, locking, unlocking) => {
  const program = createTestAuthenticationProgramBch({ lockingBytecode: locking, unlockingBytecode: unlocking, valueSatoshis: 1000n });
  const state = vm.evaluate(program);
  const top = state.stack[state.stack.length - 1];
  const accepted = state.error === undefined && state.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1;
  return { accepted, error: state.error, operationCost: state.metrics.operationCost };
};
const pushInt = (n) => {
  const d = bigIntToVmNumber(n);
  if (d.length === 0) return Uint8Array.from([0x00]);
  if (d.length === 1 && d[0] >= 1 && d[0] <= 16) return Uint8Array.from([0x50 + d[0]]);
  if (d.length === 1 && d[0] === 0x81) return Uint8Array.from([0x4f]);
  if (d.length <= 75) return Uint8Array.from([d.length, ...d]);
  if (d.length <= 255) return Uint8Array.from([0x4c, d.length, ...d]);
  return Uint8Array.from([0x4d, d.length & 0xff, (d.length >> 8) & 0xff, ...d]);
};
const unlockingFor = (args) => Uint8Array.from(args.slice().reverse().flatMap((a) => [...pushInt(a)]));

// spend(Ax,Ay, Bxa,Bxb,Bya,Byb, Cx,Cy, in0,in1)
const g1aff = (p) => { const a = p.toAffine(); return [a.x, a.y]; };
const g2aff = (p) => { const a = p.toAffine(); return [a.x.c0, a.x.c1, a.y.c0, a.y.c1]; };
const proofArgs = (A, B, C, inputs) => [...g1aff(A), ...g2aff(B), ...g1aff(C), ...inputs.map(BigInt)];

// --- fixed VK from the committed instance scalars ---
const vec = JSON.parse(readFileSync('src/checkpoints/pairing-vectors.json', 'utf8'));
const s = vec.scalars;
const alpha_s = BigInt(s.alpha), beta_s = BigInt(s.beta), gamma_s = BigInt(s.gamma), delta_s = BigInt(s.delta);
const ic_s = s.ic.map(BigInt);
const alpha = G1(alpha_s), beta = G2(beta_s), gamma = G2(gamma_s), delta = G2(delta_s), ic = ic_s.map(G1);

// sanity: reconstructed VK must equal the baked one (else lockingOK is for a different VK)
const aff = (p) => p.toAffine();
if (aff(ic[1]).x !== BigInt(vec.vk.ic[1].x) || aff(alpha).x !== BigInt(vec.vk.alpha.x)) {
  throw new Error('reconstructed VK != committed VK; cannot reuse the baked locking');
}

const nobleVerify = (A, B, C, inputs) => {
  let vkx = ic[0];
  inputs.forEach((inp, i) => { vkx = vkx.add(ic[i + 1].multiply(modr(inp))); });
  const prod = bn254.pairingBatch([{ g1: A.negate(), g2: B }, { g1: alpha, g2: beta }, { g1: vkx, g2: gamma }, { g1: C, g2: delta }], true);
  return Fp12.eql(prod, Fp12.ONE);
};

// --- reuse the COMMITTED locking (guarantees identical VK-baked program) ---
const single = JSON.parse(readFileSync('src/bch/groth16-singleton-vectors.json', 'utf8'));
const locking = hexToBin(single.lockingOK);

// --- deterministic PRNG (SplitMix64), seeded apart from gen-pairing-vectors.ts ---
let _st = 0xA5A5A5A5DEADBEEFn;
const MASK64 = (1n << 64n) - 1n;
const nextU64 = () => {
  _st = (_st + 0x9e3779b97f4a7c15n) & MASK64;
  let z = _st;
  z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & MASK64;
  z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & MASK64;
  return (z ^ (z >> 31n)) & MASK64;
};
const randScalar = () => { let a = 0n; for (let i = 0; i < 4; i++) a = (a << 64n) | nextU64(); return (a % r) || 1n; };

const mint = () => {
  const in0 = randScalar() % 1000000n || 11n;
  const in1 = randScalar() % 1000000n || 13n;
  const a_s = randScalar(), b_s = randScalar();
  const vkx_s = modr(ic_s[0] + in0 * ic_s[1] + in1 * ic_s[2]);
  const c_s = modr((a_s * b_s - alpha_s * beta_s - vkx_s * gamma_s) * invr(delta_s));
  const A = G1(a_s), B = G2(b_s), C = G1(c_s);
  return { inputs: [in0, in1], A, B, C };
};

// The legacy scalar-density fixture keeps all bits 0..252 set for the original/Shamir
// scalar loops. The grouped GLV fixtures below instead carry their exact four bounded
// witnesses in [k10,k20,k11,k21] order, so their public inputs can be checked against
// the BN254 endomorphism eigenvalue before source-contract generation.
const WORST_INPUT = (1n << 253n) - 1n; // largest contiguous-low-bits value < r
const GLV_LAMBDA = 4407920970296243842393367215006156084916469457145843978461n;
const GLV_BOUND = 1n << 128n;
const GLV_DENSE_SCALAR = GLV_BOUND - 1n;
const GLV_DENSITY_SCALARS = [
  GLV_DENSE_SCALAR, GLV_DENSE_SCALAR, GLV_DENSE_SCALAR, GLV_DENSE_SCALAR,
];
const GLV_DENSITY_INPUTS = [
  modr(GLV_DENSITY_SCALARS[0] + GLV_DENSITY_SCALARS[1] * GLV_LAMBDA),
  modr(GLV_DENSITY_SCALARS[2] + GLV_DENSITY_SCALARS[3] * GLV_LAMBDA),
];
const GLV_RESOURCE_SCALARS = [GLV_DENSE_SCALAR, 0n, 1n, 0n];
const GLV_RESOURCE_INPUTS = [GLV_DENSE_SCALAR, 1n];

[
  { label: 'GLV density', inputs: GLV_DENSITY_INPUTS, scalars: GLV_DENSITY_SCALARS },
  { label: 'GLV resource', inputs: GLV_RESOURCE_INPUTS, scalars: GLV_RESOURCE_SCALARS },
].forEach(({ label, inputs, scalars }) => {
  scalars.forEach((scalar, index) => {
    if (scalar < 0n || scalar >= GLV_BOUND) {
      throw new Error(`${label} scalar ${index} is outside [0, 2^128)`);
    }
  });
  const reconstructed = [
    modr(scalars[0] + scalars[1] * GLV_LAMBDA),
    modr(scalars[2] + scalars[3] * GLV_LAMBDA),
  ];
  if (reconstructed[0] !== inputs[0] || reconstructed[1] !== inputs[1]) {
    throw new Error(`${label} GLV witnesses do not reconstruct the public inputs`);
  }
});

const mintFixture = (label, inputs) => {
  const [in0, in1] = inputs;
  const a_s = randScalar(), b_s = randScalar();
  const vkx_s = modr(ic_s[0] + in0 * ic_s[1] + in1 * ic_s[2]);
  const c_s = modr((a_s * b_s - alpha_s * beta_s - vkx_s * gamma_s) * invr(delta_s));
  const candidate = { inputs: [in0, in1], A: G1(a_s), B: G2(b_s), C: G1(c_s) };
  const tampered = [candidate.inputs[0], modr(candidate.inputs[1] + 1n)];
  if (!nobleVerify(candidate.A, candidate.B, candidate.C, candidate.inputs)) {
    throw new Error(`${label} proof fails noble verify`);
  }
  if (nobleVerify(candidate.A, candidate.B, candidate.C, tampered)) {
    throw new Error(`${label} tamper unexpectedly verifies`);
  }
  const unlocking = unlockingFor(proofArgs(
    candidate.A, candidate.B, candidate.C, candidate.inputs,
  ));
  const invalidUnlocking = unlockingFor(proofArgs(
    candidate.A, candidate.B, candidate.C, tampered,
  ));
  const good = evalPair(looseVm, locking, unlocking);
  const bad = evalPair(looseVm, locking, invalidUnlocking);
  if (!good.accepted) throw new Error(`${label} proof REJECTED by committed locking: ${good.error}`);
  if (bad.accepted) throw new Error(`${label} tamper ACCEPTED by committed locking`);
  console.log(`  ${label}: VM accept=${good.accepted} reject-tamper=${!bad.accepted} op-cost=${good.operationCost.toLocaleString()} inputs=(${candidate.inputs.join(',')})`);
  return {
    publicInputs: candidate.inputs.map(String),
    unlocking: binToHex(unlocking),
    invalidUnlocking: binToHex(invalidUnlocking),
  };
};

// proof #0 is the COMMITTED instance (already in groth16-singleton-vectors.json);
// mint EXTRA fresh ones. All share the same locking.
const proofs = [];
const committedInputs = vec.publicInputs.map(BigInt);
proofs.push({
  publicInputs: committedInputs.map(String),
  unlocking: single.unlocking,
  invalidUnlocking: single.invalidUnlocking,
  committed: true,
});

console.log(`=== minting ${EXTRA} extra Groth16 proofs under the committed BN254 VK ===`);
for (let k = 0; k < EXTRA; k++) {
  const { inputs, A, B, C } = mint();
  const tampered = [inputs[0], modr(inputs[1] + 1n)];
  // noble oracle
  if (!nobleVerify(A, B, C, inputs)) throw new Error(`minted proof ${k} fails noble verify`);
  if (nobleVerify(A, B, C, tampered)) throw new Error(`minted proof ${k} tamper unexpectedly verifies`);
  // on-chain witnesses against the SAME committed locking
  const unlocking = unlockingFor(proofArgs(A, B, C, inputs));
  const invalidUnlocking = unlockingFor(proofArgs(A, B, C, tampered));
  const good = evalPair(looseVm, locking, unlocking);
  const bad = evalPair(looseVm, locking, invalidUnlocking);
  if (!good.accepted) throw new Error(`minted proof ${k} REJECTED by committed locking: ${good.error}`);
  if (bad.accepted) throw new Error(`minted proof ${k} tamper ACCEPTED by committed locking`);
  console.log(`  proof #${k + 1}: VM accept=${good.accepted} reject-tamper=${!bad.accepted} op-cost=${good.operationCost.toLocaleString()} inputs=(${inputs.join(',')})`);
  proofs.push({
    publicInputs: inputs.map(String),
    unlocking: binToHex(unlocking),
    invalidUnlocking: binToHex(invalidUnlocking),
    committed: false,
  });
}

// --- named density/resource proofs: same VK and locking ---
console.log('=== minting the WORST-CASE proof (dense public inputs = 2^253-1) ===');
const worstCaseProof = {
  ...mintFixture('worst-case', [WORST_INPUT, WORST_INPUT]),
  worstCase: true,
};

console.log('=== minting the GLV-DENSITY proof (all four GLV witnesses = 2^128-1) ===');
const glvDensityProof = {
  ...mintFixture('GLV density', GLV_DENSITY_INPUTS),
  glvScalars: GLV_DENSITY_SCALARS.map(String),
};

console.log('=== minting the GLV-RESOURCE proof (GLV witnesses = 2^128-1,0,1,0) ===');
const glvResourceProof = {
  ...mintFixture('GLV resource', GLV_RESOURCE_INPUTS),
  glvScalars: GLV_RESOURCE_SCALARS.map(String),
};

const out = {
  contract: single.contract,
  description:
    `${proofs.length} DISTINCT valid Groth16 proofs that all verify under ONE fixed locking (VK baked). ` +
    'Proof #0 is the committed instance; the rest are minted under the same VK (fresh public inputs + A,B, ' +
    'C solved in the exponent). Demonstrates the singleton verifier is RUNTIME-GENERAL: the program is not ' +
    'specialized to a single proof. Each invalidUnlocking tampers public input[1] (+1) and must be rejected. ' +
    'Named GLV fixtures include their exact bounded witnesses for source-side reconstruction checks.',
  lockingOK: single.lockingOK,
  lockingBytes: single.lockingBytes,
  numProofs: proofs.length,
  proofs,
  // dense-input proof for the chunked covenants' worst-case op-cost benchmark (the
  // chunk windows are sized for it). Same VK/locking; consumed by chunked build_vectors.
  worstCaseProof,
  // All four bounded GLV scalars have every usable bit set.
  glvDensityProof,
  // Full-valid asymmetric resource fixture; the universal ceiling is certified separately.
  glvResourceProof,
};
const outPath = 'src/bch/groth16-singleton-multiproof-vectors.json';
writeFileSync(outPath, JSON.stringify(out, null, 2));
console.log(`\nwrote ${outPath}  (${proofs.length} proofs, one shared locking)`);
