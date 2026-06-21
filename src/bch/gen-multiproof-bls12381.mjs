// Mint MULTIPLE distinct, valid BLS12-381 Groth16 proofs under the SAME verifying
// key, so the benchmark can EMPIRICALLY confirm the BLS singleton verifier is
// runtime-general (one fixed locking verifies many proofs) -- the same check the
// BN254 generator does, on nChain's curve. The VK scalars (alpha=3,beta=5,gamma=7,
// delta=11, IC=[2,4,6]) mirror bls_instance.mjs and are held FIXED; per proof we
// vary the public inputs + C, and solve A in the exponent over Fr (B = 1*G2):
//   A = alpha*beta + vkx*gamma + C*delta   (mod r)   =>   product == 1.
// Because the VK is unchanged, the committed lockingOK is reused byte-for-byte and
// only the unlocking (A,B,C,in0,in1 witness) differs. Each proof is verified in
// @noble/curves AND on the loosened BCH 2026 VM against the actual committed
// locking; a tampered public input must be rejected. Output:
//   src/bch/groth16-bls12381-singleton-multiproof-vectors.json
//
//   npm run gen:multiproof-bls       mint EXTRA_PROOFS (default 3) extra proofs
//
// Lives in the verifier repo (not the contracts repo): NO cashc/.cash dependency —
// reuses the COMMITTED singleton locking from the vectors JSON. Paths are repo-root-
// relative (run via npm).
import { readFileSync, writeFileSync } from 'node:fs';
import {
  hexToBin, binToHex, bigIntToVmNumber,
  createVirtualMachine, createInstructionSetBch2026,
  createTestAuthenticationProgramBch, ConsensusBch2025, ripemd160, secp256k1, sha1, sha256,
} from '@bitauth/libauth';
import { bls12_381 } from '@noble/curves/bls12-381.js';

const EXTRA = Number(process.env.EXTRA_PROOFS ?? 3);
const Fp12 = bls12_381.fields.Fp12;
const G1 = bls12_381.G1.Point, G2 = bls12_381.G2.Point;
const R = 52435875175126190479447740508185965837690552500527637822603658699938581184513n;
const mod = (x) => ((x % R) + R) % R;

// VK scalars -- mirror bls_instance.mjs (the committed instance's trusted setup)
const alpha_s = 3n, beta_s = 5n, gamma_s = 7n, delta_s = 11n;
const ic_s = [2n, 4n, 6n];
const vk = {
  alpha: G1.BASE.multiply(alpha_s), beta: G2.BASE.multiply(beta_s),
  gamma: G2.BASE.multiply(gamma_s), delta: G2.BASE.multiply(delta_s),
  ic: ic_s.map((k) => G1.BASE.multiply(k)),
};

const HUGE = Number.MAX_SAFE_INTEGER;
const loosened = {
  ...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7,
  maximumMemorySlots: HUGE, maximumStandardLockingBytecodeLength: -1,
  maximumStandardUnlockingBytecodeLength: HUGE, maximumTokenCommitmentLength: 128,
  operationCostBudgetPerByte: HUGE, maximumStackItemLength: HUGE, maximumVmNumberByteLength: HUGE,
  maximumStackDepth: HUGE, maximumControlStackDepth: HUGE, maximumBytecodeLength: HUGE, maximumOperationCount: HUGE,
};
const looseVm = createVirtualMachine(createInstructionSetBch2026(false, { consensus: loosened, ripemd160, secp256k1, sha1, sha256 }));
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

const computeVkx = (inputs) => { let acc = vk.ic[0]; inputs.forEach((s, i) => { acc = acc.add(vk.ic[i + 1].multiply(mod(s))); }); return acc; };
const nobleVerify = (A, B, C, inputs) => {
  const vkx = computeVkx(inputs);
  const prod = bls12_381.pairingBatch([{ g1: A.negate(), g2: B }, { g1: vk.alpha, g2: vk.beta }, { g1: vkx, g2: vk.gamma }, { g1: C, g2: vk.delta }], true);
  return Fp12.eql(prod, Fp12.ONE);
};

// reuse the COMMITTED locking (guarantees identical VK-baked program)
const single = JSON.parse(readFileSync('src/bch/groth16-bls12381-singleton-vectors.json', 'utf8'));
const locking = hexToBin(single.lockingOK);

// deterministic PRNG (SplitMix64)
let _st = 0xB15B15B1DEADC0DEn;
const MASK64 = (1n << 64n) - 1n;
const nextU64 = () => {
  _st = (_st + 0x9e3779b97f4a7c15n) & MASK64;
  let z = _st;
  z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & MASK64;
  z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & MASK64;
  return (z ^ (z >> 31n)) & MASK64;
};
const randScalar = () => { let a = 0n; for (let i = 0; i < 4; i++) a = (a << 64n) | nextU64(); return mod(a) || 1n; };

const mint = () => {
  const in0 = randScalar() % 1000000n || 11n;
  const in1 = randScalar() % 1000000n || 13n;
  const cS = randScalar();
  const vx = mod(ic_s[0] + in0 * ic_s[1] + in1 * ic_s[2]);
  const Ascalar = mod(alpha_s * beta_s + vx * gamma_s + cS * delta_s);
  return { inputs: [in0, in1], A: G1.BASE.multiply(Ascalar), B: G2.BASE, C: G1.BASE.multiply(cS) };
};

const proofs = [{
  publicInputs: undefined, // committed instance lives in groth16-bls12381-singleton-vectors.json
  unlocking: single.unlocking,
  invalidUnlocking: single.invalidUnlocking,
  committed: true,
}];

console.log(`=== minting ${EXTRA} extra BLS12-381 Groth16 proofs under the committed VK ===`);
for (let k = 0; k < EXTRA; k++) {
  const { inputs, A, B, C } = mint();
  const tampered = [inputs[0], mod(inputs[1] + 1n)];
  if (!nobleVerify(A, B, C, inputs)) throw new Error(`minted proof ${k} fails noble verify`);
  if (nobleVerify(A, B, C, tampered)) throw new Error(`minted proof ${k} tamper unexpectedly verifies`);
  const unlocking = unlockingFor(proofArgs(A, B, C, inputs));
  const invalidUnlocking = unlockingFor(proofArgs(A, B, C, tampered));
  const good = evalPair(looseVm, locking, unlocking);
  const bad = evalPair(looseVm, locking, invalidUnlocking);
  if (!good.accepted) throw new Error(`minted proof ${k} REJECTED by committed locking: ${good.error}`);
  if (bad.accepted) throw new Error(`minted proof ${k} tamper ACCEPTED by committed locking`);
  console.log(`  proof #${k + 1}: VM accept=${good.accepted} reject-tamper=${!bad.accepted} op-cost=${good.operationCost.toLocaleString()} inputs=(${inputs.join(',')})`);
  proofs.push({ publicInputs: inputs.map(String), unlocking: binToHex(unlocking), invalidUnlocking: binToHex(invalidUnlocking), committed: false });
}

const out = {
  contract: single.contract,
  description:
    `${proofs.length} DISTINCT valid BLS12-381 Groth16 proofs that all verify under ONE fixed locking (VK baked). ` +
    'Proof #0 is the committed instance; the rest are minted under the same VK (fresh public inputs + C, A solved ' +
    'in the exponent). Demonstrates the BLS singleton verifier is RUNTIME-GENERAL. Each invalidUnlocking tampers ' +
    'public input[1] (+1) and must be rejected.',
  lockingOK: single.lockingOK,
  lockingBytes: single.lockingBytes,
  numProofs: proofs.length,
  proofs,
};
const outPath = 'src/bch/groth16-bls12381-singleton-multiproof-vectors.json';
writeFileSync(outPath, JSON.stringify(out, null, 2));
console.log(`\nwrote ${outPath}  (${proofs.length} proofs, one shared locking)`);
