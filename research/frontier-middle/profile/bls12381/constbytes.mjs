// big constant pushes (>=40 B) in the top frame, by first-executing segment (singletons)
import { readFileSync } from 'node:fs';
import { hexToBin, decodeAuthenticationInstructions, encodeAuthenticationInstruction } from '@bitauth/libauth';
const B='/home/mrzwets/BCH-projects/verifier.cash/zk-verifier-bench/src/bch/';
for (const [w, f] of [['plain','groth16-bls12381-singleton-vectors.json'],['opt','groth16-bls12381-singleton-opcode-optimized-vectors.json']]) {
  const v = JSON.parse(readFileSync(B+f,'utf8')); const d = JSON.parse(readFileSync(`out-${w}.json`,'utf8'));
  const s = JSON.parse(readFileSync(`seg-${w}.json`,'utf8'));
  // rebuild tl->segment by re-running the python rules is heavy; use seg file's tlseg if present
  const tlseg = s.tlseg;
  const ins = decodeAuthenticationInstructions(hexToBin(v.lockingOK)); let o = 0; const big = {}; let pre = 0, preN = 0;
  for (const i of ins) { const len = encodeAuthenticationInstruction(i).length; if (i.data && i.data.length >= 40) { const t = d.topOff[`1:${o}`]; const sg = t ? tlseg[t.tl] : 'never-executed'; big[sg] = (big[sg] ?? 0) + len; } o += len; }
  console.log(w, JSON.stringify(big));
}
