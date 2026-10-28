import { compileFile, utils } from 'cashc';
import { hexToBin, decodeAuthenticationInstructions, encodeAuthenticationInstruction } from '@bitauth/libauth';
export function lineMap(path, opts) {
  const art = compileFile(path, opts);
  const bc = utils.asmToBytecode(art.bytecode);
  const ins = decodeAuthenticationInstructions(bc);
  const sm = art.debug.sourceMap.split(';');
  let prev = [0, 0, 0, 0, 0]; const lines = [];
  for (const e of sm) { const f = e.split(':'); const cur = prev.map((p, i) => (f[i] === undefined || f[i] === '' ? p : Number(f[i]))); lines.push(cur[0]); prev = cur; }
  const offs = []; let o = 0; for (const i of ins) { offs.push(o); o += encodeAuthenticationInstruction(i).length; }
  return { art, bc, ins, offs, lines };
}
if (process.argv[1]?.endsWith("srcmap.mjs") && process.argv[2]) { const { ins, lines, offs } = lineMap(process.argv[2], { rescheduleStacks: true }); console.log('instr', ins.length, 'srcmap entries', lines.length); console.log(lines.slice(0, 40).join(','), '...', lines.slice(-40).join(',')); }
