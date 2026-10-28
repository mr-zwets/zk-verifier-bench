import { compileFile } from 'cashc';
import { writeFileSync } from 'node:fs';
const t=Date.now();
const a = compileFile(process.argv[2], (process.env.OPTS ? JSON.parse(process.env.OPTS) : { optimizeFor: 'size', rescheduleStacks: true }));
console.log('ms', Date.now()-t, Object.keys(a), Object.keys(a.debug), a.debug.bytecode.length/2);
writeFileSync(process.argv[3], JSON.stringify(a));
console.log((a.debug.sourceMap||'').slice(0,300));
