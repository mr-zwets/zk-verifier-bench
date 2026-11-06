# Evidence ownership and reproduction paths

The repository root owns `src/`, package configuration and maintainer commands.
The artifact root is `artifacts/bn254-native-affine-candidate`. Construction
notes refer to `docs/`, `source/`, `diagnostic/` and `registry-patch.diff` from
that artifact root. Executable checker paths are resolved by their source;
the native certificate README gives a complete command from the repository root.
The publication manifest lists proposed files using repository-relative paths.
It excludes itself from its hash list.

The current runtime module is the 3261-byte 9ef metadata successor. The current
public validation export binds that module and the patched registry to the
actual typecheck and registered CLI results. All four repository `src/` files
in this contribution are byte-identical to that tested projection. Documentation
and exported evidence were finalized afterward; no extra fixture evaluations
are inferred from those edits.

`public-evidence/typecheck-inputs.json` is the input inventory for the tested
repository snapshot, not a claim that every listed input is added by this PR.
Project input paths belong to the repository at the recorded base plus these
four source changes. Package inputs belong to the recorded external packages.
`public-evidence/compiler-payload.json` paths belong to the external TypeScript
6.0.3 package root. No dependency payload is vendored by this contribution.
Those external inventories can be checked only with the declared package
owners; artifact-local path lookup would be incorrect.

The native certificate's fixed tables, source modules, fourteen patches,
source fixture, and ordinary raw-Miller checker retain their reviewed bytes.
The public execution summary records earlier component actions and historical
commands, not a fresh run of the 9ef module. Its native command's
`<packet-positive-vectors>` placeholder is the current repository positive
vectors; use the complete command in `vk-v9/README.md` to reproduce it.
The source recipe and raw-Miller checker require the separately pinned source
dependency root. The ordinary field-library package versions differ from the
VM runtime packages recorded in `public-evidence/validation.json`.

Preparation-phase records, including fixed-preprocessing plan results and
resource-transfer reports, describe their captured phases. Their old
unexecuted or memory-hold labels do not supersede subsequent component
execution or the current conditional memory contract. Bare predecessor hashes
identify historical records; they are not promises that those private records
are shipped or that their whole file maps describe this repository layout.

The claims sheet and current dynamic/capture/memory notes state the mathematical
contracts. File hashes and fixture observations cannot prove generic VM
semantics, universal resource bounds, or an equation theorem. Local peer review
comes from separate tasks within the same agent pipeline. An independent
maintainer rebuild and constructive review are still required for reviewed
upstream admission. No deployment or arbitrary-key support is claimed.
