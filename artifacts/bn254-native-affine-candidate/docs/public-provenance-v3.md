# C-first prefix-extraction public source recipe

Status: `PUBLIC_RECIPE_WITHOUT_CAPTURE_DEPENDENCY`.

This public successor describes the eight source modules, the unchanged public
fixture, the fourteen ordered patches, the clean base commit, and the external
three-package dependency closure. It checks generated C/R/locking identities
against the public expected hashes in `public-reproduction-plan-v3.json`.

The recipe is intentionally independent of an adjacent qualified catalog or a
private receipt. Historical source-capture evidence may corroborate the result,
but it is not an input needed to generate or identity-check the artifact. The
dependency trees remain external and must be supplied at the pinned relative
package roots; no registry install, network access, or hidden resolver search is
part of this recipe. A staging copy may expose those trees through a local
`source/node_modules` link, while the sealed source packet remains unchanged.

Before import, the driver checks the source and fixture bytes, all fourteen patch
identities, package metadata and complete package-tree hashes, all twelve
package-relative dependency edges, Node v26.12.0 and its binary identity, the
resolver flag, and the eight cleared controls. The source build/capture boundary
does not include VM, prover, compiler, benchmark, or fixture generation.

The expected artifact identities and all source/dependency pins are relative and
portable. Exact reproduction remains conditional on supplying the independently
checked external dependency root; this document makes no qualification,
publication, network, application, or full-verifier claim.
