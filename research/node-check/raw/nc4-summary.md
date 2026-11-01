# Track 8 node-check summary (nc4)

timing rows 178, policy rows 72, mempool groups 24, driver errors 0
bench libauth charges OP_DEFINE bodies: true

## 1tx: 24 statements

| tx | n | tx B | inputs | K | BCHN accept | libauth (bench, patched) cons/std | libauth (Track 8) cons/std | Verify ms/tx (median of 11) | spread max | ns/op-cost | worst input: bench libauth cons / std (incl. DEFINE) | Track 8 libauth std alone / + DEFINE / max(std,cons)+DEFINE | testmempoolaccept allowed | fee sat/B |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|---|---|--:|--:|
| tx0 | 24 | 98690 | 12 | 4 | 24/24 | 24/24 | 24/24 | 16.64–17.00 | 4.6% | 0.264–0.269 | 89.69% / 91.01% | 90.45% / 91.01% / 91.01% | 24/24 | 1.24 |

Per input: bench libauth (patched) op-cost = Track 8 libauth op-cost + defineBytes on 288/288 inputs (consensus), 288/288 (standard).

| input role | n | BCHN-adjusted standard op-cost / budget |
|---|--:|--:|
| tx0 HEAD | 24 | 25.14–25.17% |
| tx0 CODE1 | 24 | 73.02–73.10% |
| tx0 CODE2 | 24 | 66.51–66.63% |
| tx0 FIN | 24 | 72.17–72.39% |
| tx0 QRY | 192 | 90.67–91.01% |

Rejections: 46 cases; BCHN block rejected 46; bench libauth cons rejected 46; Track 8 libauth rejected 46; as expected 46

| case | statement | tx | rejecting input (Track 8) | BCHN block | libauth (bench) | BCHN mempool reason (timing node) |
|---|---|--:|---|---|---|---|
| tampered:cap: cap: cap.trace[0] byte 0 | 0 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| tampered:ood: ood: ood[0].trace_local[0] c0 + 1 | 0 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| tampered:random: random: random_values.random[0][0][0] c0 + 1 | 0 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| tampered:pow: pow: pow.batch + 1 | 0 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| tampered:final: final: final_poly[0] c0 + 1 | 0 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| tampered:row: row: random matrix 0 (instance 0, 2^20) q0 col 0 + 1 | 0 | 0 | 4 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| tampered:salt: salt: random matrix 0 (instance 0, 2^20) q0 salt 0 + 1 | 0 | 0 | 4 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| tampered:sibling: sibling: sib.random[0] byte 0 | 0 | 0 | 8 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| tampered:fri_value: fri_value: fri[0] q0 value 0 c0 + 1 | 0 | 0 | 4 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| tampered:statement: statement: NF[0] + 1 | 0 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| tx: output value - 1 sat (CTX differs) | 0 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| root: script ROOT[3] + 1 | 0 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| constants: FIN: TBL byte 0 flipped | 0 | 0 | 3 FIN | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| constants: CODE: ACC_1 + 1 and ACC_2 compensated (HEAD sum unchanged) | 0 | 0 | 1 CODE1 | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| constants: HEAD: NF lane 0 byte 0 flipped | 0 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| input: HEAD: OOD byte 100 flipped | 0 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| input: QRY: hint T + 1 | 0 | 0 | 4 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| input: QRY: path byte (input tree) flipped | 0 | 0 | 4 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| input: QRY: last query (L, path) missing | 0 | 0 | 4 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| graph: CODE 1: code blob byte flipped | 0 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| graph: two QRY inputs swapped (order) | 0 | 0 | 4 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| graph: one input with another locking (R + one byte) | 0 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| mix: one QRY input from another statement (m1-s7-1-Z128_cap5) | 0 | 0 | 5 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| tampered:cap: cap: cap.trace[0] byte 0 | 23 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| tampered:ood: ood: ood[0].trace_local[0] c0 + 1 | 23 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| tampered:random: random: random_values.random[0][0][0] c0 + 1 | 23 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| tampered:pow: pow: pow.batch + 1 | 23 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| tampered:final: final: final_poly[0] c0 + 1 | 23 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| tampered:row: row: random matrix 0 (instance 0, 2^20) q0 col 0 + 1 | 23 | 0 | 4 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| tampered:salt: salt: random matrix 0 (instance 0, 2^20) q0 salt 0 + 1 | 23 | 0 | 4 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| tampered:sibling: sibling: sib.random[0] byte 0 | 23 | 0 | 7 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| tampered:fri_value: fri_value: fri[0] q0 value 0 c0 + 1 | 23 | 0 | 4 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| tampered:statement: statement: NF[0] + 1 | 23 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| tx: output value - 1 sat (CTX differs) | 23 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| root: script ROOT[3] + 1 | 23 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| constants: FIN: TBL byte 0 flipped | 23 | 0 | 3 FIN | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| constants: CODE: ACC_1 + 1 and ACC_2 compensated (HEAD sum unchanged) | 23 | 0 | 1 CODE1 | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| constants: HEAD: NF lane 0 byte 0 flipped | 23 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| input: HEAD: OOD byte 100 flipped | 23 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| input: QRY: hint T + 1 | 23 | 0 | 4 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| input: QRY: path byte (input tree) flipped | 23 | 0 | 4 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| input: QRY: last query (L, path) missing | 23 | 0 | 4 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| graph: CODE 1: code blob byte flipped | 23 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| graph: two QRY inputs swapped (order) | 23 | 0 | 4 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| graph: one input with another locking (R + one byte) | 23 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| mix: one QRY input from another statement (m1-s7-0-Z128_cap5) | 23 | 0 | 5 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |

Policy: 24/24 allowed at the exported fee; chained (tx1 spends mined tx0's NFT): 0; mined after: 24

## 2tx: 24 statements

| tx | n | tx B | inputs | K | BCHN accept | libauth (bench, patched) cons/std | libauth (Track 8) cons/std | Verify ms/tx (median of 11) | spread max | ns/op-cost | worst input: bench libauth cons / std (incl. DEFINE) | Track 8 libauth std alone / + DEFINE / max(std,cons)+DEFINE | testmempoolaccept allowed | fee sat/B |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|---|---|--:|--:|
| tx0 | 24 | 91059 | 11 | 4 | 24/24 | 24/24 | 24/24 | 15.32–15.57 | 6.1% | 0.268–0.272 | 89.77% / 91.10% | 90.54% / 91.10% / 91.10% | 24/24 | 2.31 |
| tx1 | 24 | 40497 | 5 | 19–20 | 24/24 | 24/24 | 24/24 | 2.85–2.93 | 10.0% | 0.271–0.278 | 89.62% / 90.95% | 90.39% / 90.95% / 90.95% | 24/24 | 2.74 |

Whole proof (sum of the tx medians per statement): 18.20–18.47 ms

Per input: bench libauth (patched) op-cost = Track 8 libauth op-cost + defineBytes on 384/384 inputs (consensus), 384/384 (standard).

| input role | n | BCHN-adjusted standard op-cost / budget |
|---|--:|--:|
| tx0 HEAD | 24 | 25.23–25.26% |
| tx0 CODE1 | 24 | 71.53–71.62% |
| tx0 CODE2 | 24 | 65.16–65.28% |
| tx0 FIN | 24 | 72.29–72.51% |
| tx0 QRY | 168 | 90.76–91.10% |
| tx1 HEAD | 24 | 10.02–10.02% |
| tx1 CODE1 | 24 | 3.07% |
| tx1 CODE2 | 24 | 3.07% |
| tx1 FIN | 24 | 72.15–72.37% |
| tx1 QRY | 24 | 90.67–90.95% |

Rejections: 60 cases; BCHN block rejected 60; bench libauth cons rejected 60; Track 8 libauth rejected 60; as expected 60

| case | statement | tx | rejecting input (Track 8) | BCHN block | libauth (bench) | BCHN mempool reason (timing node) |
|---|---|--:|---|---|---|---|
| tampered:cap: cap: cap.trace[0] byte 0 | 0 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| tampered:ood: ood: ood[0].trace_local[0] c0 + 1 | 0 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| tampered:random: random: random_values.random[0][0][0] c0 + 1 | 0 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| tampered:pow: pow: pow.batch + 1 | 0 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| tampered:final: final: final_poly[0] c0 + 1 | 0 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| tampered:row: row: random matrix 0 (instance 0, 2^20) q0 col 0 + 1 | 0 | 0 | 4 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| tampered:salt: salt: random matrix 0 (instance 0, 2^20) q0 salt 0 + 1 | 0 | 0 | 4 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| tampered:sibling: sibling: sib.random[0] byte 0 | 0 | 0 | 8 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| tampered:fri_value: fri_value: fri[0] q0 value 0 c0 + 1 | 0 | 0 | 4 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| tampered:statement: statement: NF[0] + 1 | 0 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| tx: output value - 1 sat (CTX differs) | 0 | 1 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| root: script ROOT[3] + 1 | 0 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| constants: FIN: TBL byte 0 flipped | 0 | 0 | 3 FIN | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| constants: CODE: ACC_1 + 1 and ACC_2 compensated (HEAD sum unchanged) | 0 | 0 | 1 CODE1 | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| constants: HEAD: NF lane 0 byte 0 flipped | 0 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| input: HEAD: OOD byte 100 flipped | 0 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| input: QRY: hint T + 1 | 0 | 0 | 4 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| input: QRY: path byte (input tree) flipped | 0 | 0 | 4 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| input: QRY: last query (L, path) missing | 0 | 0 | 4 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| graph: CODE 1: code blob byte flipped | 0 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| graph: two QRY inputs swapped (order) | 0 | 0 | 4 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| graph: one input with another locking (R + one byte) | 0 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| mix: one QRY input from another statement (m1-s7-1-Z128_cap5) | 0 | 0 | 5 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| mix: transaction 1 (all inputs) from another statement, the NFT of this proof (replay) | 0 | 1 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| thread: tx1: spends an NFT minted for another proof (commitment of another G) | 0 | 1 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| thread: tx1: input 0 NFT is mutable | 0 | 1 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| thread: tx1: input 0 without the NFT | 0 | 1 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Invalid OP_SPLIT range) |
| thread: tx1: a QRY input of tx0 (queries 0-2) instead of its own | 0 | 1 | 4 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| thread: tx0: baton not returned (output 0 is the NFT only) | 0 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| thread: tx0: thread NFT minted mutable | 0 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| tampered:cap: cap: cap.trace[0] byte 0 | 23 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| tampered:ood: ood: ood[0].trace_local[0] c0 + 1 | 23 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| tampered:random: random: random_values.random[0][0][0] c0 + 1 | 23 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| tampered:pow: pow: pow.batch + 1 | 23 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| tampered:final: final: final_poly[0] c0 + 1 | 23 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| tampered:row: row: random matrix 0 (instance 0, 2^20) q0 col 0 + 1 | 23 | 0 | 4 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| tampered:salt: salt: random matrix 0 (instance 0, 2^20) q0 salt 0 + 1 | 23 | 0 | 4 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| tampered:sibling: sibling: sib.random[0] byte 0 | 23 | 0 | 7 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| tampered:fri_value: fri_value: fri[0] q0 value 0 c0 + 1 | 23 | 0 | 4 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| tampered:statement: statement: NF[0] + 1 | 23 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| tx: output value - 1 sat (CTX differs) | 23 | 1 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| root: script ROOT[3] + 1 | 23 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| constants: FIN: TBL byte 0 flipped | 23 | 0 | 3 FIN | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| constants: CODE: ACC_1 + 1 and ACC_2 compensated (HEAD sum unchanged) | 23 | 0 | 1 CODE1 | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| constants: HEAD: NF lane 0 byte 0 flipped | 23 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| input: HEAD: OOD byte 100 flipped | 23 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| input: QRY: hint T + 1 | 23 | 0 | 4 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| input: QRY: path byte (input tree) flipped | 23 | 0 | 4 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| input: QRY: last query (L, path) missing | 23 | 0 | 4 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| graph: CODE 1: code blob byte flipped | 23 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| graph: two QRY inputs swapped (order) | 23 | 0 | 4 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| graph: one input with another locking (R + one byte) | 23 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| mix: one QRY input from another statement (m1-s7-0-Z128_cap5) | 23 | 0 | 5 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| mix: transaction 1 (all inputs) from another statement, the NFT of this proof (replay) | 23 | 1 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| thread: tx1: spends an NFT minted for another proof (commitment of another G) | 23 | 1 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| thread: tx1: input 0 NFT is mutable | 23 | 1 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| thread: tx1: input 0 without the NFT | 23 | 1 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Invalid OP_SPLIT range) |
| thread: tx1: a QRY input of tx0 (queries 0-2) instead of its own | 23 | 1 | 4 QRY | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_NUMEQUALVERIFY operation) |
| thread: tx0: baton not returned (output 0 is the NFT only) | 23 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |
| thread: tx0: thread NFT minted mutable | 23 | 0 | 0 HEAD | blk-bad-inputs | reject | 16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation) |

Policy: 48/48 allowed at the exported fee; chained (tx1 spends mined tx0's NFT): 24; mined after: 48

## Mempool mode (2tx, tx1 sent with tx0 unconfirmed)

| statement | tma tx0 | send tx0 | tma tx1 (parent unconfirmed) | send tx1 | child alone first | mined in 1 block | chain B | fee sat/B |
|---|---|---|---|---|---|---|--:|--:|
| 0 | true | true | true | true | missing-inputs | yes (h 223, 3 tx) | 131556 | 2.440 |
| 1 | true | true | true | true | missing-inputs | yes (h 225, 3 tx) | 131556 | 2.440 |
| 2 | true | true | true | true | missing-inputs | yes (h 227, 3 tx) | 131556 | 2.440 |
| 3 | true | true | true | true | missing-inputs | yes (h 229, 3 tx) | 131556 | 2.440 |
| 4 | true | true | true | true | missing-inputs | yes (h 231, 3 tx) | 131556 | 2.440 |
| 5 | true | true | true | true | missing-inputs | yes (h 233, 3 tx) | 131556 | 2.440 |
| 6 | true | true | true | true | missing-inputs | yes (h 235, 3 tx) | 131556 | 2.440 |
| 7 | true | true | true | true | missing-inputs | yes (h 237, 3 tx) | 131556 | 2.440 |
| 8 | true | true | true | true | missing-inputs | yes (h 239, 3 tx) | 131556 | 2.440 |
| 9 | true | true | true | true | missing-inputs | yes (h 241, 3 tx) | 131556 | 2.440 |
| 10 | true | true | true | true | missing-inputs | yes (h 243, 3 tx) | 131556 | 2.440 |
| 11 | true | true | true | true | missing-inputs | yes (h 245, 3 tx) | 131556 | 2.440 |
| 12 | true | true | true | true | missing-inputs | yes (h 247, 3 tx) | 131556 | 2.440 |
| 13 | true | true | true | true | missing-inputs | yes (h 249, 3 tx) | 131556 | 2.440 |
| 14 | true | true | true | true | missing-inputs | yes (h 251, 3 tx) | 131556 | 2.440 |
| 15 | true | true | true | true | missing-inputs | yes (h 253, 3 tx) | 131556 | 2.440 |
| 16 | true | true | true | true | missing-inputs | yes (h 255, 3 tx) | 131556 | 2.440 |
| 17 | true | true | true | true | missing-inputs | yes (h 257, 3 tx) | 131556 | 2.440 |
| 18 | true | true | true | true | missing-inputs | yes (h 259, 3 tx) | 131556 | 2.440 |
| 19 | true | true | true | true | missing-inputs | yes (h 261, 3 tx) | 131556 | 2.440 |
| 20 | true | true | true | true | missing-inputs | yes (h 263, 3 tx) | 131556 | 2.440 |
| 21 | true | true | true | true | missing-inputs | yes (h 265, 3 tx) | 131556 | 2.440 |
| 22 | true | true | true | true | missing-inputs | yes (h 267, 3 tx) | 131556 | 2.440 |
| 23 | true | true | true | true | missing-inputs | yes (h 269, 3 tx) | 131556 | 2.440 |

All sent: 24/24; all mined in one block: 24/24; mempool empty after: 24/24
