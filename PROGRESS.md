# PROGRESS (wip/node-check only; never merge to main)

Track 8a node-check: research verifiers on stock BCHN 29.1.0.

- worktrees: bench = work/node-check/bench (wip/node-check), g16 = work/node-check/g16 (detached origin/main 3af2ad8; node_modules symlinks in plonk-kzg/verifier and pq-stark/verifier, not committed)
- datadirs: work/node-check/bchn-<NAME> (OPCOST_DIR=work/node-check)

## Log
- setup done; rig read (node.sh is localhost-only: rpcbind/rpcallowip 127.0.0.1, listen=0, connect=0)
