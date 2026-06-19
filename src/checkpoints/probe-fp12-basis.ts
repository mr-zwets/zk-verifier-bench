// Empirically confirm noble's bn254 Fp12 tower convention + byte serialization,
// so the basis doc (docs/pairing-checker.md) rests on observed facts, not just
// source reading. Run: npx tsx src/checkpoints/probe-fp12-basis.ts
import { bn254 } from '@noble/curves/bn254.js';

const Fp = bn254.fields.Fp;
const Fp2 = bn254.fields.Fp2;
const Fp6 = bn254.fields.Fp6;
const Fp12 = bn254.fields.Fp12;
const p = Fp.ORDER;

const hex = (x: bigint) => x.toString(16);

console.log('=== noble bn254 Fp12 tower probe ===');
console.log('p =', p.toString());
console.log('Fp.BYTES =', Fp.BYTES, ' Fp.isLE =', (Fp as any).isLE);
console.log('Fp2.BYTES =', Fp2.BYTES, ' Fp6.BYTES =', Fp6.BYTES, ' Fp12.BYTES =', Fp12.BYTES);

// --- Fp2: u^2 = ? ---  build u = (0,1), square it.
const u = Fp2.fromBigTuple([0n, 1n]);
const u2 = Fp2.sqr(u);
console.log('\nFp2: u^2 = (c0,c1) =', `(${u2.c0}, ${u2.c1})`, '=> expect (p-1, 0) i.e. u^2 = -1');
console.log('  u^2 == -1 :', Fp2.eql(u2, Fp2.fromBigTuple([p - 1n, 0n])));

// --- Fp2 NONRESIDUE (the sextic xi) ---
console.log('\nFp2.NONRESIDUE (xi for Fp6) = (c0,c1) =', `(${(Fp2 as any).NONRESIDUE.c0}, ${(Fp2 as any).NONRESIDUE.c1})`, '=> expect (9,1) i.e. xi = 9 + u');

// --- Fp6: v^3 = xi ?  v = (0,1,0) over Fp2 ---
const v = Fp6.fromBigSix([0n, 0n, 1n, 0n, 0n, 0n]); // c0=0, c1=1 (the v slot), c2=0
const v3 = Fp6.mul(Fp6.mul(v, v), v);
const xi = (Fp2 as any).NONRESIDUE;
console.log('\nFp6: v^3 = (as Fp2 c0) =', `(${v3.c0.c0}, ${v3.c0.c1})`, ' (c1,c2 should be 0)');
console.log('  v^3 == xi (=9+u) :', Fp2.eql(v3.c0, xi) && Fp2.is0(v3.c1) && Fp2.is0(v3.c2));

// --- Fp12: w^2 = v ?  w = (0,1) over Fp6 i.e. c0=0_Fp6, c1=ONE? no: w is the c1 unit ---
// w is represented as Fp12 = { c0: Fp6.ZERO, c1: Fp6.ONE } => the 'w' basis element.
const w = Fp12.create({ c0: Fp6.ZERO, c1: Fp6.ONE });
const w2 = Fp12.sqr(w);
// w^2 should equal v embedded in Fp12.c0 (the Fp6 'v' element), c1 = 0.
const vInFp12 = Fp12.create({ c0: v, c1: Fp6.ZERO });
console.log('\nFp12: w^2 == v (embedded in c0) :', Fp12.eql(w2, vInFp12));

// --- byte serialization order: build a known Fp12 with 12 distinct coords ---
const tuple = Array.from({ length: 12 }, (_, i) => BigInt(i + 1)) as any;
const f = Fp12.fromBigTwelve(tuple);
const bytes = Fp12.toBytes(f);
console.log('\nFp12.toBytes layout (12 x 32B = 384B), each coord big-endian:');
console.log('  total bytes =', bytes.length);
// decode each 32-byte limb back to an int to confirm order
const limbs: bigint[] = [];
for (let i = 0; i < 12; i++) {
  let acc = 0n;
  for (let j = 0; j < 32; j++) acc = (acc << 8n) | BigInt(bytes[i * 32 + j]!);
  limbs.push(acc);
}
console.log('  decoded limb order (should be 1..12) :', limbs.map(String).join(','));
console.log('  => order is c0.c0.c0, c0.c0.c1, c0.c1.c0, c0.c1.c1, c0.c2.c0, c0.c2.c1,');
console.log('              c1.c0.c0, c1.c0.c1, c1.c1.c0, c1.c1.c1, c1.c2.c0, c1.c2.c1');
console.log('  each limb big-endian (MSB first) :', limbs[0] === 1n && limbs[11] === 12n);

// --- Fp2 frobenius coefficient (p-power) ---
const frob = (Fp2 as any).FROBENIUS_COEFFICIENTS;
console.log('\nFp2.FROBENIUS_COEFFICIENTS (gamma_1,i for u): [', frob.map(hex).join(', '), ']');
console.log('  (FROBENIUS_COEFFICIENTS[1] should be p-1 = -1, since u^p = -u):', frob[1] === p - 1n);

// --- ONE round-trips ---
const oneBytes = Fp12.toBytes(Fp12.ONE);
let oneFirst = 0n;
for (let j = 0; j < 32; j++) oneFirst = (oneFirst << 8n) | BigInt(oneBytes[j]!);
console.log('\nFp12.ONE first limb =', oneFirst.toString(), '(expect 1), rest zero:',
  oneBytes.slice(32).every((b) => b === 0));
