// Summarize the Track 8 node-check run: node summarize-t8.mjs DATA_DIR raw/NAME > raw/NAME-summary.md
// Joins NAME-{timing,policy,mempool}.jsonl with the export files (Track 8's own libauth numbers, field t8).
import {readFileSync, readdirSync, existsSync} from 'node:fs';
const [dataDir, prefix] = process.argv.slice(2);
const rows = (f) => (existsSync(f) ? readFileSync(f, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)) : []);
const T = rows(`${prefix}-timing.jsonl`), P = rows(`${prefix}-policy.jsonl`), M = rows(`${prefix}-mempool.jsonl`);
const E = new Map();
for (const f of readdirSync(dataDir).filter((x) => /^t8-.*\.json$/.test(x))) for (const w of JSON.parse(readFileSync(`${dataDir}/${f}`, 'utf8')).workloads) E.set(w.id, w);
const pct = (x) => (100 * x).toFixed(2) + '%';
const mm = (xs, d = 2) => { const a = Math.min(...xs), b = Math.max(...xs); return a === b ? a.toFixed(d) : `${a.toFixed(d)}–${b.toFixed(d)}`; };
const planOf = (id) => id.slice(3, 6);
const out = [];
const errs = [...T, ...P, ...M].filter((r) => r.error);
out.push(`# Track 8 node-check summary (${prefix.split('/').pop()})`, '', `timing rows ${T.length}, policy rows ${P.length}, mempool groups ${M.length}, driver errors ${errs.length}${errs.length ? ': ' + errs.map((r) => `${r.id ?? r.group} ${r.error}`).join('; ') : ''}`,
  `bench libauth charges OP_DEFINE bodies: ${[...new Set(T.map((r) => r.libauthChargesDefine))].join('/')}`, '');
for (const plan of ['1tx', '2tx']) {
  const V = T.filter((r) => planOf(r.id) === plan && r.kind === 'valid' && !r.error), R = T.filter((r) => planOf(r.id) === plan && r.expect === 'reject' && !r.error);
  const PV = P.filter((r) => planOf(r.id) === plan && !r.error);
  const stmts = new Set(V.map((r) => r.group));
  out.push(`## ${plan}: ${stmts.size} statements`, '');
  const nTx = Math.max(...V.map((r) => E.get(r.id).chainLength));
  out.push('| tx | n | tx B | inputs | K | BCHN accept | libauth (bench, patched) cons/std | libauth (Track 8) cons/std | Verify ms/tx (median of 11) | spread max | ns/op-cost | worst input: bench libauth cons / std (incl. DEFINE) | Track 8 libauth std alone / + DEFINE / max(std,cons)+DEFINE | testmempoolaccept allowed | fee sat/B |',
    '|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|---|---|--:|--:|');
  for (let t = 0; t < nTx; t++) {
    const vs = V.filter((r) => E.get(r.id).chainIndex === t); const ps = PV.filter((r) => E.get(r.id).chainIndex === t);
    const t8 = vs.map((r) => E.get(r.id).t8);
    const w = (f) => Math.max(...t8.map((x) => Math.max(...x.perInput.map((p) => f(p) / p.budget))));
    out.push(`| tx${t} | ${vs.length} | ${mm(vs.map((r) => r.txBytes), 0)} | ${vs[0].inputs} | ${mm(vs.map((r) => r.copies), 0)} | ${vs.filter((r) => r.bchnAccepted).length}/${vs.length} | ${vs.filter((r) => r.libauthCons).length}/${vs.filter((r) => r.libauthStd).length} | ${t8.filter((x) => x.cons).length}/${t8.filter((x) => x.std).length} | ${mm(vs.map((r) => r.verifyStats.median / r.copies))} | ${Math.max(...vs.map((r) => r.verifyStats.spreadPct)).toFixed(1)}% | ${mm(vs.map((r) => r.nsPerOpCost), 3)} | ${pct(Math.max(...vs.map((r) => r.worst.opCons)))} / ${pct(Math.max(...vs.map((r) => r.worst.opStd)))} | ${pct(w((p) => p.opStd))} / ${pct(w((p) => p.opStd + p.defineBytes))} / ${pct(w((p) => p.bchnAdj))} | ${ps.filter((r) => r.allowed).length}/${ps.length} | ${mm(ps.map((r) => r.feeRateSatPerB))} |`);
  }
  if (nTx > 1) {
    const byG = new Map(); for (const r of V) byG.set(r.group, (byG.get(r.group) ?? 0) + r.verifyStats.median / r.copies);
    out.push('', `Whole proof (sum of the tx medians per statement): ${mm([...byG.values()])} ms`);
  }
  // patched vs Track 8 per input, every valid input: difference of the op-cost bases
  let n = 0, diffC = 0, diffS = 0;
  for (const r of V) { const t8 = E.get(r.id).t8; r.perInput.forEach((p, i) => { n++; if (p.opCons !== t8.perInput[i].opCons + t8.perInput[i].defineBytes) diffC++; if (p.opStd !== t8.perInput[i].opStd + t8.perInput[i].defineBytes) diffS++; }); }
  out.push('', `Per input: bench libauth (patched) op-cost = Track 8 libauth op-cost + defineBytes on ${n - diffC}/${n} inputs (consensus), ${n - diffS}/${n} (standard).`);
  const roles = {};
  for (const r of V) { const t8 = E.get(r.id).t8; r.perInput.forEach((p, i) => { const k = `tx${E.get(r.id).chainIndex} ${t8.perInput[i].role}`; (roles[k] ??= []).push(p.bchnAdjStd / p.budget); }); }
  out.push('', '| input role | n | BCHN-adjusted standard op-cost / budget |', '|---|--:|--:|', ...Object.entries(roles).map(([k, xs]) => `| ${k} | ${xs.length} | ${mm(xs.map((x) => 100 * x))}% |`));
  // rejections
  out.push('', `Rejections: ${R.length} cases; BCHN block rejected ${R.filter((r) => r.bchnAccepted === false).length}; bench libauth cons rejected ${R.filter((r) => r.libauthCons === false).length}; Track 8 libauth rejected ${R.filter((r) => E.get(r.id).t8.cons === false).length}; as expected ${R.filter((r) => r.asExpected && r.repsAllAsExpected).length}`, '');
  out.push('| case | statement | tx | rejecting input (Track 8) | BCHN block | libauth (bench) | BCHN mempool reason (timing node) |', '|---|---|--:|---|---|---|---|');
  for (const r of R) { const e = E.get(r.id); const mp = Array.isArray(r.mempool) ? r.mempool[0]['reject-reason'] : JSON.stringify(r.mempool);
    out.push(`| ${e.description.replace(/ \(tx\d\)$/, '')} | ${r.group.replace(/^t8-..x-m1-s7-/, '').replace('-Z128_cap5', '')} | ${e.t8.tx} | ${e.t8.rejectingInput} ${e.t8.rejectingRole} | ${r.bchnAccepted ? 'ACCEPTED' : r.submitResult} | ${r.libauthCons ? 'ACCEPTED' : 'reject'} | ${mp} |`); }
  const pbad = PV.filter((r) => !r.allowed);
  out.push('', `Policy: ${PV.filter((r) => r.allowed).length}/${PV.length} allowed at the exported fee; chained (tx1 spends mined tx0's NFT): ${PV.filter((r) => r.chainedInputs > 0).length}; mined after: ${PV.filter((r) => r.minedAfter).length}${pbad.length ? '; not allowed: ' + pbad.map((r) => `${r.id} ${r.rejectReason}${r.feeRetry ? ' (fee retry ' + (r.feeRetry.allowed ? 'allowed' : r.feeRetry.rejectReason) + ')' : ''}`).join('; ') : ''}`, '');
}
if (M.length) {
  out.push('## Mempool mode (2tx, tx1 sent with tx0 unconfirmed)', '', '| statement | tma tx0 | send tx0 | tma tx1 (parent unconfirmed) | send tx1 | child alone first | mined in 1 block | chain B | fee sat/B |', '|---|---|---|---|---|---|---|--:|--:|');
  for (const g of M) { if (g.error) { out.push(`| ${g.group} | ERROR ${g.error} |`); continue; }
    const s = g.steps; const ca = Array.isArray(g.pre.childAloneTma) ? g.pre.childAloneTma[0]['reject-reason'] : JSON.stringify(g.pre.childAloneTma);
    out.push(`| ${g.group.replace('t8-2tx-m1-s7-', '').replace('-Z128_cap5', '')} | ${s[0].testmempoolaccept?.allowed} | ${s[0].inMempool} | ${s[1].testmempoolaccept?.allowed} | ${s[1].inMempool} | ${ca} | ${g.block.accepted && g.block.allChainTxsIncluded ? `yes (h ${g.block.height}, ${g.block.txCount} tx)` : 'NO'} | ${g.totalBytes} | ${g.chainFeeRateSatPerB.toFixed(3)} |`); }
  out.push('', `All sent: ${M.filter((g) => g.allSent).length}/${M.length}; all mined in one block: ${M.filter((g) => g.block?.allChainTxsIncluded).length}/${M.length}; mempool empty after: ${M.filter((g) => Array.isArray(g.mempoolAfter) && g.mempoolAfter.length === 0).length}/${M.length}`);
}
console.log(out.join('\n'));
