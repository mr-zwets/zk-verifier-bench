# genpow-promotions: progress

Task: a read-only report on whether the corrected genpow singletons can be marked reviewed. Nothing is merged.

- [x] Worktree on wip/genpow-promotions (bench origin/main 37e35f2). The source checkout is detached at origin/main 838431c under .src/, which is untracked and not committed.
- [x] lockingOK hashes on main checked against the reviewed bytes (both match).
- [x] Both programs rebuilt from source on main, byte for byte.
- [x] Ordinary rejection runs: tools/genpow-reject.mts. BN: 22 fast cases plus 3 full neutral runs. BLS: 24 fast cases. All rejected.
- [x] Constructive soundness re-check by reading: identity, neutral points, G2 domain.
- [x] `pnpm benchmark genpow`: both PASS (27.5 min).

Done: report delivered. Nothing merged.
- [x] NOTES.md written.
