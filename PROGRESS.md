# PROGRESS — Track 12 (program-pinned covenant template), branch wip/pinned-template (bench side)

- [x] research/node-check/export-pinned.mjs, run-t12.sh
- [x] t12a (groth16_cashscript c2894d3, 100,000-sat inputs): 88 pinned workloads as expected; 2 duplicated-payout runs failed bad-txns-in-belowout before the script
- [x] t12b (043d1b7, 200,000-sat inputs, + risc0-v3): 92/92 as expected, BCHN = libauth, 9/9 valid allowed by POLICY=1; nodes stopped
- [x] node-check README section "Track 12"
- [x] Track 12 fix round: re-export (groth16_cashscript a7edd02) and BCHN run t12c (fresh nodes, stopped): 108 pinned workloads as expected, BCHN = libauth.
