# PROGRESS (wip/pq-stark-soundness; never merge this file to main)

- [x] worktree from origin/main (7819629), upstream unset
- [x] sources read: BGKTTZ ASIACRYPT'23 (Thm 6-8, Cor 4/5, Lemma 1), BCIKS20 ECCC rev3 (Thm 1.2/1.5/1.6/7.2/7.4, Lemma 8.2 proof), ADK CiC 3(2) (Thm 1-3)
- [x] params5.py: per-round RBR bounds (JB, UD, DKT sensitivity), Track 4 sets, Track-4-format search incl. commit grinding, Plonky3 FriParameters search
- [x] SOUNDNESS.md
- [ ] not done: executing p3-security as a cross-check (build of external crate was not permitted); UD terms hand-checked against source instead

## Fix round (review findings), 2026-10-29
- Merged wip/pq-stark-soundness 9989e0d (powers-batching sketch in SOUNDNESS.md 2.1, stock cubic trinomial, byte labels).
- security.py labels: "JB, powers-batching adaptation, unpublished" for every Plonky3 set; security.json numbers unchanged.
- Results copies and README synced from groth16_cashscript wip/pq-stark-verifier (BCHN on standard basis).
