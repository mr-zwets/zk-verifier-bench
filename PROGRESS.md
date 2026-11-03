# PROGRESS: wip/batching-proof (wip branch only; not for main)

Task: write research/pq-stark/BATCHING-PROOF.md, which states and proves the "powers-batching adaptation" behind the
Track 5/8 128-bit figures, or reduces it to published results.

## 2026-11-03
- Worktree from origin/main 0a83c22.
- Read [BCIKS20] ECCC rev. 3 (Thm 7.2/7.4, §8.2), [BCHKS25] ECCC TR25-169 (Thm 1.5, 4.2, Cor. 4.4) and [ADK] CiC
  version (Protocol 1/2, Thm 2 and App. B). Read Plonky3 0d80373 fri/src (open_input ladder, roll-in, fold_row,
  hiding_pcs). Could not fetch ePrint PDFs (HTTP 403): ethSTARK doc 2021/582 and Haböck 2022/1216 are not read.
- Finding: the batching step is a direct application of [BCIKS20] Thm 7.2 (published curve theorem). The FRI wrapper
  (per-height ladders, roll-ins) is proved in BATCHING-PROOF.md §4 (Theorem 2, RBR state function). The DEEP-ALI front
  end is still a reduction to [ADK] Thm 2.
- Added design-t8/batching8.py and its output. It reproduces Track 8: batch 136.33 / 135.15, independent 142.87 /
  141.87, fold1 128.06 / 128.87. Exact Thm 2 gives M2 batch 135.89. BCHKS25 sensitivity: 155.58 / 155.15.
- Open: external review; reading [Sta21] and [Hab22]; the maintainer's decision on the proposed label (§0).
