// Summarize node-check results: node summarize.mjs timing.jsonl [policy.jsonl] > summary.md (also writes <timing>.csv)
import {readFileSync, writeFileSync} from 'node:fs';
const [tf, pf] = process.argv.slice(2);
const rows = (f) => (f ? readFileSync(f, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)) : []);
const T = rows(tf), P = rows(pf);
const pct = (x) => (x === undefined ? '' : (100 * x).toFixed(2) + '%');
const groupOf = (r) => r.group ?? '';
const out = [];
out.push('## Valid workloads (timing node: acceptnonstdtxn=1, block validation)', '',
  '| workload | tx B | in | max unl. B | K | BCHN | libauth cons/std | Verify ms/tx (median) | spread | worst input op/budget: libauth cons | + DEFINE (cons) | libauth std + DEFINE | testmempoolaccept (policy node) |',
  '|---|--:|--:|--:|--:|---|---|--:|--:|--:|--:|--:|---|');
const pol = new Map(P.map((r) => [r.id, r]));
for (const r of T.filter((x) => x.kind === 'valid' || (x.expect === 'accept' && x.kind !== 'define-probe'))) {
  if (r.error) { out.push(`| ${r.id} | ERROR ${r.error.slice(0, 80)} |`); continue; }
  const p = pol.get(r.id);
  const pv = p ? (p.error ? 'ERROR ' + p.error.slice(0, 60) : p.allowed ? 'allowed' : 'REJECTED: ' + p.rejectReason + (p.feeRetry ? (p.feeRetry.allowed ? '; allowed with fee' : '; with fee: ' + p.feeRetry.rejectReason) : '')) : 'n/a';
  out.push(`| ${r.id} | ${r.txBytes} | ${r.inputs} | ${r.maxUnlocking} | ${r.copies} | ${r.bchnAccepted ? 'accept' : 'REJECT ' + r.submitResult} | ${r.libauthCons ? 'accept' : 'reject'}/${r.libauthStd ? 'accept' : 'reject'} | ${r.verifyStats ? (r.verifyStats.median / r.copies).toFixed(3) : ''} | ${r.verifyStats ? r.verifyStats.spreadPct.toFixed(1) + '%' : ''} | ${pct(r.worst.opCons)} | ${pct(r.worst.bchnAdjCons)} | ${pct(r.worst.bchnAdjStd)} | ${pv} |`);
}
out.push('', '## Rejection tests (K = 1; BCHN block verdict, libauth consensus verdict, BCHN mempool script error)', '',
  '| group | cases | BCHN rejected | libauth rejected | both as expected | mempool reasons |', '|---|--:|--:|--:|--:|---|');
const rej = T.filter((x) => x.expect === 'reject' && x.kind !== 'define-probe');
for (const g of [...new Set(rej.map(groupOf))]) {
  const rs = rej.filter((x) => groupOf(x) === g);
  const reasons = [...new Set(rs.map((x) => (Array.isArray(x.mempool) ? x.mempool[0]?.['reject-reason'] : JSON.stringify(x.mempool))?.replace(/\s*\(.*$/, '')))].join('; ');
  out.push(`| ${g} | ${rs.length} | ${rs.filter((x) => x.bchnAccepted === false).length} | ${rs.filter((x) => x.libauthCons === false).length} | ${rs.filter((x) => x.asExpected).length} | ${reasons} |`);
}
const bad = T.filter((x) => x.error || !x.asExpected);
out.push('', `Not as expected / errors: ${bad.length ? bad.map((x) => `${x.id}${x.error ? ' ERROR ' + x.error : ` (BCHN ${x.bchnAccepted}, libauth ${x.libauthCons}) ${x.submitResult ?? ''}`}`).join('; ') : 'none'}`);
const probes = T.filter((x) => x.kind === 'define-probe');
if (probes.length) {
  out.push('', '## OP_DEFINE probes (one input\'s FILL sized one byte under / at the libauth consensus op-cost + DEFINE body bytes)', '',
    '| probe | description | libauth cons | BCHN block | BCHN mempool |', '|---|---|---|---|---|');
  for (const r of probes) out.push(`| ${r.id} | ${r.description} | ${r.libauthCons ? 'accept' : 'reject'} | ${r.bchnAccepted ? 'accept' : 'reject: ' + r.submitResult} | ${Array.isArray(r.mempool) ? (r.mempool[0].allowed ? 'allowed' : r.mempool[0]['reject-reason']) : ''} |`);
}
if (P.length) {
  out.push('', '## Policy node (acceptnonstdtxn=0): testmempoolaccept of every valid workload tx', '',
    '| workload | chained inputs | tx B | fee sat/B (as exported) | allowed | reject reason | after fee retry |', '|---|--:|--:|--:|---|---|---|');
  for (const p of P) out.push(p.error ? `| ${p.id} | ERROR ${p.error.slice(0, 100)} |||||` : `| ${p.id} | ${p.chainedInputs} | ${p.txBytes} | ${p.feeRateSatPerB.toFixed(2)} | ${p.allowed} | ${p.rejectReason ?? ''} | ${p.feeRetry ? (p.feeRetry.allowed ? 'allowed' : 'REJECTED: ' + p.feeRetry.rejectReason) + ` (${p.feeRetry.feeRateSatPerB.toFixed(2)} sat/B)` : ''} |`);
}
console.log(out.join('\n'));
if (tf) writeFileSync(tf.replace(/\.jsonl$/, '.csv'), ['id,kind,expect,bchnAccepted,libauthCons,libauthStd,asExpected,txBytes,inputs,copies,verifyMedianMs,verifyMsPerTx,spreadPct,worstOpCons,worstBchnAdjCons,worstBchnAdjStd,submitResult',
  ...T.map((r) => [r.id, r.kind, r.expect, r.bchnAccepted, r.libauthCons, r.libauthStd, r.asExpected, r.txBytes, r.inputs, r.copies, r.verifyStats?.median, r.verifyStats ? r.verifyStats.median / r.copies : '', r.verifyStats?.spreadPct, r.worst?.opCons, r.worst?.bchnAdjCons, r.worst?.bchnAdjStd, r.submitResult ?? r.error ?? '']
    .map((x) => (x === undefined || x === null ? '' : JSON.stringify(x))).join(','))].join('\n') + '\n');
