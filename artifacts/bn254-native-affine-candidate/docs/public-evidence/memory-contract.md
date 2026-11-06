# Current C7553/R14 canonical memory contract

For the named canonical constructor/caller, primitive VM and generic lowering
contracts, current C7553/R14 retains the source-frame induction
`6*155+2+14+25+10+9 = 990 <= 996 < 1000`.
This is a conditional canonical-witness resource result. Accepted-execution
soundness has no honest-producer or resource-honesty premise, and no resource
bound is claimed for arbitrary oversized advice.

## Which program is current

The current C is 7553 bytes with SHA256
`63f12474082916e22ab62faf6c6f0483bedcbb08a9700e4d7eb02415c9d8c242`.
The current R14 is 61 bytes with SHA256
`0563cd756e2d300b7653e10fd2e39ba5951e404210ba78f18d8ba4549719a030`.
The previous C-first R13 also had61 bytes, with a different hash. First transfer
the C7551 frame theorem through the C-first role changes, then transfer the
redeem bootstrap to R14. Neither equal redeem lengths nor a source capture
alone proves this composition.

## C-first role micropeaks

After FILL, role0 has4 words and role1 has5. The old SWAP selected C without
changing depth. The new depth literal plus ROLL peaks at5/6 words: ROLL consumes
the literal and moves the selected C, restoring depth4/5. SIZE and its expected
length literal then peak at6/7, followed by NUMEQUALVERIFY and DROP. The old
complete SIZE check already peaked at6/7. These sequential peaks are not added.
Both paths reach the same named post-drop lower stack. All21 helper bodies,
54 kernel interfaces/ordered DAGs/bytes and98 captured source contexts preserve
the inherited shapes. Literal lengths and offsets still occupy one word.
The current terminal kernel transient is9 words, within reserve14.

## Current redeem and registration bootstraps

After ordinary P2SH32 removes the redeem item, at most7 role data words remain.
For the first host slice R14 pushes the input index, reads INPUTBYTECODE,
pushes d+L, splits/drops the suffix, then pushes d and splits/removes the header.
This needs at most2 items above the residual prefix. The second host slice
retains the first piece, so needs at most3. CAT, DUP, SHA256, the expected
digest, EQUALVERIFY, DEFINE and INVOKE never exceed residual+3. Hence the
current R14 bootstrap peak is10. Each C body/ID registration uses at most2
extra items and the final INPUTINDEX+23 dispatch obeys the same bound, giving
C peak9. C has24 definitions; including R14's C entry gives25 stored definitions.
These are primitive opcode/count implications, not a sampled execution peak.

## Conditional frame induction

Each permitted canonical entry has the declared local layout. LOCAL preserves
the caller floor; BOUND preserves data below its window and obeys its touched-
depth bound. Branches restore their common layout and loops restore their
entry layout on repetition. The canonical WSp and Dp piles require at most12
and4 physical cells. The graph is finite and nonrecursive; the longest body
chain is role -> LOOP -> BNDSTEP -> EA -> P. Its five body contexts and one
enclosing program context give six allowances.

The155-word symbolic combined-frame envelope is used with these finite layout,
value-domain, pile and restoration contracts. A finite capture observation of155
would not independently prove that envelope for arbitrary VM-accepted advice.
Under the stated induction the body allowance is6*155+2+14=946. Add25 stored
definitions, R14 peak10 and C peak9 to obtain990. Retaining ceiling996 is
conservative. The C-first micropeak calculation and unchanged helper/kernel
shapes preserve the induction; the current R14 token calculation supplies its
changed bootstrap. Generic lowering, LOCAL/BOUND and caller/loop restoration
remain explicit semantic premises rather than being inferred from fixtures.

## Array widths and scope

The10000-byte stack-item cap is separate from the1000-slot limit. Current C7553,
its3889/3664 pieces, R61 and quotient of at most132*32=4224 bytes fit that cap.
The source-owned current raw targets9964/9875/9907 have filler payloads625/535
and576..4770 across the132 quotient widths. For any canonical role2 raw target
at most10000, the transcript tail after5039 and before the final62-byte redeem
push is at most4899; its64-byte-prefixed hash preimage is at most4963.
Unchanged arithmetic/decoder size bounds retain their named field contracts.

This note supplies no operation-cost, score or byte-optimum conclusion. The
separate resource owner ledger supplies cost accounting; the dynamic-consumer
and typed-random-function notes supply the accepted-equation argument. Local
peer reviews come from separate tasks in the same agent pipeline; external
constructive review and maintainer admission remain pending. No new proof,
fixture, VM, source, compiler, prover or benchmark execution is used here.
