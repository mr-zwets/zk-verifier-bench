# BN254 native affine verifier contribution

This directory contains the fixed-VK mathematical claims, source recipe and
validation evidence for `bch-groth16-bn254-sound-native-affine-candidate`.
The normal implementation and two runtime vector files live in repository
`src/`; uniform vectors are diagnostic evidence in `diagnostic/`.
The repository's general contributor and claims guides are preserved.
`publication-manifest.json` inventories the proposed repository files;
`docs/evidence-ownership.md` explains current evidence, predecessor snapshots,
and the external package roots needed to check their pins.

Read `docs/submission-claims.md` for the exact synthetic VK, finite point/scalar
domain, equation, binding owners and typed-random-function assumptions.
`docs/public-evidence/dynamic-consumer-v2.md` supplies the terminal equation
join; `capture-frame-contract.md` and `memory-contract.md` in that same directory
separate static capture and conditional canonical memory from accepted-run
soundness. `docs/resource-argument.md` and the 65-row resource-owner data retain
all baseline instruction charges and add the priced local change, including
`100*delta(opcodeCount)`. The old resource-transfer phase label is not a new
memory failure: the current canonical memory contract supplies 990 <= 996 < 1000
under its stated lowering/caller/branch-loop contracts. No arbitrary-advice
resource bound or honest-producer premise for soundness is claimed.

The current submitted module hash is
`9efdbbd88add5f2b3d34aabf4b7a050ce600a5b91c453b3659986b4b4d936d56`.
It differs from the standalone 14e2 module in exactly two documentation paths;
reversing those substitutions recovers the prior module byte-for-byte. Code C,
redeem R, locking programs, loaders, proof/public locators and vector bytes are
unchanged. Current typecheck and registered CLI evidence is in
`docs/public-evidence/validation.json`; older raw/native certificate execution
has its own predecessor/snapshot scope and was not rerun for documentation.

The benchmark model reports 27,682 bytes (27,533 script + 149 overhead), 58 above the
captured public 27,624-byte entry. No score win is claimed. The frozen direct
existing-fixture evidence contains 324 input evaluations. One separate original
benchmark and three additional public integration benchmark calls are distinct;
internal evaluation counts of those benchmark calls are not inferred.

From the repository root, run the maintainer commands:

```text
pnpm typecheck
pnpm benchmark bch-groth16-bn254-sound-native-affine-candidate
```

The packet-local native certificate command is documented in
`docs/vk-v9/README.md` for this repository layout. The ordinary raw-Miller checker
retains artifact-local fixture/table/closure paths and requires the separately
pinned source dependency root; its field-library packages differ from the VM
runtime dependency set. `docs/public-provenance-v3.md` describes source capture
under `source/reproduce-v2`. These recipes do not mint new proof fixtures.

Local peer reviews used separate tasks within the same agent pipeline. They
are not external constructive assurance. Independent maintainer rebuild and
review remain required before upstream reviewed/admitted status. This fixed-key
benchmark contribution makes no production-setup, arbitrary-key, application
knowledge/privacy, relay, chipnet or mainnet deployment claim.
