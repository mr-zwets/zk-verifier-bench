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
- 2026-10-28 Design phase:
  - SPEC.md written;
  - calculator at research/pq-hash/params.py (outputs params-output.txt/json).
- Sources fetched for the bounds:
  - BCIKS20: ECCC TR20-083 rev 2 (Thm 8.3 formula checked verbatim);
  - BCHKS25: ECCC TR25-169 (Thm 1.5, sensitivity only).
  - Could not fetch: ePrint PDFs (403) for ethSTARK, Block et al. and Haboeck. The ALI/DEEP list-size terms and the RBR per-round claim are flagged for the Analysis phase (SPEC 4.1).
- Open for later phases:
  - Kernels: K1-K19 (SPEC 8).
  - Build: wip/pq-hash-build in groth16_cashscript.
  - Model risks: op-cost model only rough (OPC constants); code size 4 KB estimated; P128 single-input margin 4.3 KB.
- Review fixes: SPEC.md moved to research/pq-hash/SPEC.md; committed .pyc dropped (__pycache__ ignored); λ labelled
  classical, new §4.5 with indicative quantum levels (BHT collisions ~67 bits at h=25, ~85 at h=32; Grover halves
  grinding/RBR terms); §4.1 states the open RBR check as an explicit condition with margins (P128 commit 0.31 bits,
  query 0.19 bits; P100 ~24 bits commit margin).
- Review fix: k-rpo.mjs calls the RPO reference selfTest() (Miden's 19 hash vectors) at load time, as k-tip5 does;
  results byte-identical. Merged wip/pq-hash-design (SPEC.md moved to research/pq-hash/, .pyc dropped).
