# PROGRESS — Track 11 (real keys), branch wip/real-keys (bench side)

- [x] research/node-check/export-realkeys.mjs, run-t11.sh
- [x] runs t11a (timing + POLICY=1) and t11b (timing rerun, valid only); every node stopped
- [x] README section "Track 11"
- No leaderboard entry registered (by design).

The verifier side lives in groth16_cashscript wip/real-keys, chunked/bn254/real-keys.

## Fix round
- [x] export-realkeys.mjs exports the new real-public-input-deep runs; covenant wrong-program runs come through the cov reports.
- [x] run t11c (timing + POLICY=1, fresh nodes, stopped); README Track 11 updated (F7 attribution fix).
