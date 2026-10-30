# PROGRESS (wip/node-check only; never merge to main)

Track 8a node-check: research verifiers on stock BCHN 29.1.0.

- worktrees: bench = work/node-check/bench (wip/node-check), g16 = work/node-check/g16 (detached origin/main 3af2ad8; node_modules symlinks in plonk-kzg/verifier and pq-stark/verifier, not committed)
- datadirs: work/node-check/bchn-<NAME> (OPCOST_DIR=work/node-check)

## Log
- setup done; rig read (node.sh is localhost-only: rpcbind/rpcallowip 127.0.0.1, listen=0, connect=0)
- wrote research/node-check/{export-plonk.mjs, export-stark.mjs, nc.ts, node.sh}; faucet category (coinbase h=1) e1230da92b60cc12cd6e40af745826c86812c0aeb4fda2513cef9f8ec6b6f18c
- PLONK exports -> work/node-check/data/plonk-<c>.json (mul2 done: 27 workloads incl. 2 define probes)
- STARK exports OK (sizes match REPORT §6 exactly: 83,515; 65,350+58,102; 71,142+65,414; 80,591+80,331+73,631)
- smoke timing run OK (nc-smoke1, stopped): all as expected; DEFINE probe: BCHN block rejects budget 1 B under libauth cons+DEFINE, accepts at/over
- FINDING: with acceptnonstdtxn=1 BCHN mempool does NOT set SCRIPT_VM_LIMITS_STANDARD (validation.cpp:1590, needs fRequireStandard) -> std op-cost (hash iter 192) only on a POLICY=1 node. Added std-basis probes.
