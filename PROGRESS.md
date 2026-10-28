# PROGRESS (wip/pq-hash-kernels) -- work note, must never land on main

Kernels phase (SPEC.md section 8). Files: research/pq-hash/kernels/.
- lib/asm.mjs (assembler + symbolic stack), lib/slp.mjs (straight-line program compiler), lib/measure.mjs (marker-based
  op-cost measurement on libauth BCH_2026, loosened + real P2SH32 check), lib/fp3.mjs, lib/ref-field.mjs, lib/ref-rpo.mjs.
- run.mjs -> results/*.json; table.mjs -> results/RESULTS.md; ratios.mjs -> results/RATIOS.md.
- Done: K1, K2, K3, K4, K5, K6, K7, K8 (blob + item-based), K9, K10, K11 (IDFT + binary folds, O1), K12, K13, K14,
  K15 (bit-serial, 4-bit windowed, holes), K16 (Blake2s, RPO computed/witnessed, Tip5 full permutation), K17, K19.
- Not done: K18 (lattice, optional); BCHN timing (optional).
- REPORT.md: the subagent Write tool refused .md report files; the full report text was returned in the phase's final
  output (orchestrator should place it at research/pq-hash/kernels/REPORT.md).
- Note: asm() treats a Uint8Array as a DATA push; splice code with {raw: bytes}.
- Key findings for Build: final polynomial (256 coeffs) ~0.71M/query; P128 per-query kernel sum 1.47M (model 0.99M);
  layout (b) P128 projection 71.9M = 94% of TXv5-as-written budget; layout (a) op-bound at 4 queries/input.

# PROGRESS (wip/pq-hash-verifier) -- Verifier phase, must never land on main
Sources: groth16_cashscript wip/pq-hash-verifier, research/pq-hash/verifier (worktree work/pq-hash/verifier).
This worktree: research/pq-hash/verifier/ = crosscheck.ts (this harness's own VM wrappers), crosscheck.json, results/
(copies of the source repo's results), REPORT.md. Nothing registered; no REGISTRY/results.json/score-history changes.
- REPORT.md: the Write tool refused the report file; its full text is in the Verifier phase's final output (orchestrator
  places it at research/pq-hash/verifier/REPORT.md).
