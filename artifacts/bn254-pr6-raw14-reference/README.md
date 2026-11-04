# Repaired BN254 raw14 reference

One retained positive proof/public tuple is replayed across fourteen fixed programs. `program-bodies.json` owns the code; `existing-positive-context.json` stores only padding/argument prefixes and covenant commitments. No old redeem code is duplicated in that context.

```sh
node replay.mjs ARTIFACT_DIRECTORY ARTIFACT_DIRECTORY/existing-positive-context.json LIBAUTH_INDEX_JS OUTPUT_RECEIPT
```

The external libauth entry must match `libauth-pin.json`. The source/rebuild counterpart is `chunked/pairing/pr6-raw14-reference/` in source PR35. Import paths alone were relocated; the fixed rebuild reproduces all14 program bytes and ABIs.

All14 existing stages accept in both standard and consensus VM modes. These are independent synthetic per-input contexts. A valid designated NFT lineage, the exact graph and standard field/group/hash premises remain required; no linked live transaction, relay/mainnet, arbitrary-key or universal producer claim follows.

Stage4 owns finite raw-B curve encoding and stage13 the subgroup relation. Raw-B infinity is outside the domain. The separate grouped-affine code reference is a component, not a full verifier. Original historical withdrawals remain unchanged.
