# Track 2 BLS12-381 research designs: measurement glue (not leaderboard entries)

`impls.ts` defines two Implementation objects. They are NOT added to the harness REGISTRY, and results.json /
score-history.json are untouched. `run.ts` runs them through the harness's own `benchmark()` plus loosened-budget
evaluations and E_k. Run it from the bench root:

    npx tsx --max-old-space-size=8192 research/frontier-middle/bls12381/run.ts research/frontier-middle/bls12381/results-bls12381.json

- T1 `research-bls12381-t1-sigls-dproj`: vectors `sigls-dproj-vectors.json`, exported by
  groth16_cashscript `research/frontier-middle/bls12381/sigls-dproj/export.mjs`.
- T2 `research-bls12381-t2-minop-rolled-{p2sh32,bare}`: redeem `minop-rolled-redeem.hex`, compiled from
  `research/frontier-middle/bls12381/minop-rolled/groth16_minop_rolled.cash`. The valid and invalid inputs are the
  EXISTING `src/bch/groth16-bls12381-singleton-minop*-vectors.json` (same spend() interface).

Sources and soundness arguments: groth16_cashscript branch `wip/frontier-middle-build-bls12381`,
`research/frontier-middle/bls12381/README.md`. Output: `results-bls12381.json`, `run.log`.
