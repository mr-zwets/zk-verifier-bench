# PUB003 native binding transfer v9

V9 preserves the v8 actual-native decoder and adds the certificate bindings
that were still missing from v8.

The certificate field is pinned to the BN254 base prime, scalar order, and
BN254 parameter. The twenty fixture words are interpreted as decimal field
elements, range-checked against the pinned base prime, encoded as unsigned
little-endian 32-byte words in the declared alpha/beta/gamma/delta/IC order,
and hashed to the exact VK digest
`181aeefd9c0ce8d103ad084f4ef8174546852b0af46ac58a8061d4f38d346a6e`.

The actual decoded TRANS body must begin with one 51-byte push equal to the
19-byte ASCII tag `BNMX3/DEGREE6-EVAL1` followed by that VK digest. This binds
the native TAG commitment to the public fixture rather than trusting a
certificate self-hash.

The reachable function-ID domain is explicit: the current 24 definitions use
only `OP_1NEGATE` for `-1`, small-integer opcodes, and direct small positive
pushes for IDs `0..25`. V9 does not rely on a multi-byte signed-ID fallback
for this corpus.

All three current positive rows are scanned by the same push decoder and must
end with a literal push equal to the current 61-byte redeem script. V8's C0/C1
extraction, 24 native prologue/body/ID bindings, instruction-boundary table
checks, and independent GLS arithmetic remain active. V9 does not claim the
pairing relation, VM/compiler semantics, canonical resource theorem, or full
qualification.
