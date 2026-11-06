# Static capture and conditional caller contract

This note exposes the source/capture boundary for the current C7553/R61 program.
It derives byte identity, extraction and caller composition under the declared
primitive VM, source-lowering, function-frame, hash-binding and authenticated
transaction contracts. It does not prove those primitive contracts by measuring
fixtures, and it does not turn a symbolic assembler capture into VM execution.

## Byte and span ownership

The packet's eight source modules and fourteen ordered patches have a portable
capture recipe in `source/reproduce-v2`. Its pinned public outputs identify C
as 7553 bytes and R as 61 bytes. `docs/vk-v9/native-artifact.json` supplies the
actual code, redeem, ordered two-piece layout, 24 bodies and role IDs 23/24/25.
The packet-local native certificate independently checks the host C slices,
body/function-ID associations, dispatcher tail, fixed tables and all three
positive-row final redeem pushes. The recipe and these checks establish the
identity inputs to this note; they do not replace the lowering premise.

The adjacent `capture-frame.json` exposes the existing symbolic capture: 54
kernel events and 98 assembler contexts. The terminal Frobenius/R kernel has
two duplicate projections, events 28 and 49, which agree. Its one code interval
is [6746,7167), 421 bytes, SHA256
`649b592964b0b4d99071432b2d4f3975e97f50f2da673eeaa620dea959f04057`.
The captured entry and post counts are 120 and 112 words. Count this interval
once. The symbolic DAG and names are included, so the degree-six consumer note
can identify which source expression the lowering contract must preserve.
Neither these frame counts nor any observed peak is a universal memory bound.

## R14 extraction law

For a byte string U and nonnegative fixed d,L, the old sequence
`SPLIT(d), NIP, SPLIT(L), DROP` and the current sequence
`SPLIT(d+L), DROP, SPLIT(d), NIP` both succeed exactly when |U| >= d+L.
Both leave U[d:d+L]. This follows directly from the ordered prefix/suffix
semantics of SPLIT, NIP and DROP; no witness-constructor premise is used.
Current host parameters are d=3 and L=3889 for input0, L=3664 for input1.
Their concatenation therefore supplies exactly 7553 bytes. R14 checks its
literal C digest, defines function01 and invokes it. Hash binding identifies
the authenticated C independently of arbitrary bytes outside the two slices.

Under ordinary P2SH32 semantics, the final literal redeem item is authenticated
against the current 35-byte locking commitment. That commitment equals
HASH256 of the exact 61-byte R; its construction is independently recomputed
for this transfer. Source field and group predicates are reached through this
current R/C path; no old redeem bytes or historical remaining-cost scalar is
needed for the implication.

## Three-role composition

Require all three current inputs in one transaction to accept, without state
override. Under the declared introspection/caller semantics, GRAPH establishes
the three-input graph and equality of the current locking programs. The C
dispatcher uses INPUTINDEX+23 to select roles23,24,25. Their source-owned layouts
are `C,S,DS,FILL`, `C,S,HAND,DS,FILL`, and
`DG,STMT,S,HAND,DS,FILL,WQ`. Range/length/depth checks and checked successor
HAND encodings give the source predicate its exact input views. The predicate
map, fixed offsets, transcript-tail exclusion and endpoint checks are written
in `docs/proof-transfer-001-002.md` and `docs/submission-claims.md`.

Consequently, under the same function-frame and lowering contracts, ordinary
all-three-input acceptance supplies the C-only equation proof with its required
current code, roles and checked values. The dynamic consumer proof then links
those values to the table/Frobenius/GLS and final quotient implications. No
honest-advice or canonical-producer premise is added to accepted-execution
soundness. Standard field/group/pairing and typed random-function assumptions
remain explicit; this is not a fixed-SHA zero-error assertion.

## Canonical construction and resources are separate

For completeness, current canonical field/group witnesses are serialized in
the exact source layout. At role0/1 targets9964/9875, raw fixed parts9336/9337
leave filler payloads625/535. For role2, target9907 minus fixed5101 is4806;
subtracting the canonical WQ push size leaves the filler push size for each
of the132 existing width rows. FILL2 and WQ begin after fixed offset5039, and
the current final62-byte redeem push is excluded from ZT. Thus moving C to the
source-owned prefix and using R14 does not change the stated arithmetic or
ordinary hash inputs for the corresponding constructed witness.

The resource argument must independently charge all retained instructions,
disjoint arithmetic/push/digest owners, actual redeem-length changes and
caller/pile reserves. The resource induction note owns the resulting bounds;
the capture data here proves neither a universal memory bound nor a cost bound.
No new fixture, prover, assembler, compiler, VM or benchmark execution is part
of this transfer. Maintainer admission, official status, application correctness,
privacy and chipnet/mainnet deployment are not consequences of this note.
