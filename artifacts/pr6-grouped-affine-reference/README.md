# Frozen PR6 grouped-affine programs

These are the two existing compiled code artifacts for the isolated PR6 finite
`vk_x` component. They contain no proof or witness data. The paired source PR34
pins [the source reference](https://github.com/mr-zwets/groth16_cashscript/tree/651b59f989e0893a61111c9c55ceb6154572a324/chunked/pairing/pr6-grouped-affine-reference) at `651b59f` with the saved CashScript
sources, historical patch, mathematical scope and verification/rebuild commands.

- Window `[0,21)`: 2244 bytes, SHA256 `976d70be87b1f3f52076eda7cf38e6f53c299480a81c44fc19dec9886d3c521f`.
- Window `[21,43)`: 2179 bytes, SHA256 `d807841a5ae74baa0347348e53402968b42eb24ec437ed83345007b40980dc3d`.

The windows are internal GLV loop positions in two component inputs. Their theorem
assumes the specified graph/table/successor interfaces and finite total
`T = IC0 + n0*IC1 + n1*IC2 != O`. It does not qualify a complete Groth16 verifier,
producer, transaction or resource budget. The `75` prefix drops an extra top stack
padding item before the declared CashScript parameters.

`archive-search.json` records the bounded scan of 1436 vector paths, deduplicated
to 261 raw files. No pre-fallback or complete affine final program matched. The
near-match is a different projective final with a 608-byte successor layout and
no affine inverse parameter. It cannot validate the 704-byte affine successor
interface by substituting code alone. No new fixture or re-encoded witness was
created. No VM replay is credited to these programs.

The existing `bn254-grouped-glv-component` reference and its six positive input
evaluations remain separate. This directory is not loaded by the registry and
does not change scores or prior claims.
