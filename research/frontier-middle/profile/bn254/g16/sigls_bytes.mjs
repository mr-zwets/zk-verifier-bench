import {decodeAuthenticationInstructions, encodeAuthenticationInstruction} from '@bitauth/libauth';
import {buildRedeem} from './script.mjs';
const {redeem, info} = buildRedeem(); const ins = decodeAuthenticationInstructions(redeem);
const marks = info.marks.slice().sort((a, b) => a.off - b.off); let off = 0; const out = {};
for (const x of ins) { const n = encodeAuthenticationInstruction(x).length; let s = 'prologue'; for (const m of marks) if (m.off <= off) s = m.name; off += n;
  const k = x.data && x.data.length === 512 ? 'pile' : x.data && x.data.length >= 20 && x.data.length < 512 ? 'const' : 'code'; out[s] ??= {}; out[s][k] = (out[s][k] ?? 0) + n; }
console.log(JSON.stringify(out));
