# PROGRESS (wip/pq-hash-design) -- work note, must never land on main

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
