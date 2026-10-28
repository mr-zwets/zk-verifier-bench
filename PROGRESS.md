# PROGRESS (wip/pq-hash-kernels) -- work note, must never land on main

Kernels phase (SPEC.md section 8). Files: research/pq-hash/kernels/.
- lib/asm.mjs (assembler + symbolic stack), lib/slp.mjs (straight-line program compiler), lib/measure.mjs (marker-based
  op-cost measurement on libauth BCH_2026, loosened + real P2SH32 check), lib/ref-field.mjs.
- run.mjs runs k-*.mjs; results/*.json.
- Done: k-field (K1, K2, K19, comparison fields), k-hash (K5, K6, K7, K17), k-gf128 (K15), k-rpo (K16 RPO, K4 chain).
- Note: asm() treats a Uint8Array as a DATA push; splice code with {raw: bytes} (bit me twice).
