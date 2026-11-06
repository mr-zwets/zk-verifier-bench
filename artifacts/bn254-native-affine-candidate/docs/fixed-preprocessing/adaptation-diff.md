# Fixed-preprocessing checker relocation

This packet-local copy preserves the v3 checker bytes and arithmetic. The only
adaptation is IO relocation: the fixture resolves to
`../../source/chunked/bn254/densless-recovered/public-fixtures.json`, the v6
certificate inputs resolve to `./certificate-inputs.json`, and the dependency
closure resolves to `../../source/reproduce-v2/dependency-closure.json`.
The manifest and report use the corresponding packet-relative paths. The safe
action is `--check-plan`; `--execute` remains an explicit root-owned arithmetic
action requiring the external pinned dependency root and Noble entry.
