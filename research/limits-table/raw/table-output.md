## Track 10 G2, layout a' (grade-lim.mjs, libauth 3.1.0-next.8 + BCHN DEFINE adjustment), vector g2-0

| layout | unlocking limit | tx limit | txs | inputs | bytes | per-tx bytes | q/QRY | worst input % | reason the plan search stopped at the next-fewer txs |
|---|--:|--:|--:|--:|--:|---|--:|--:|---|
| opt sib,lad,state,cap=3 | 10,000 | 100,000 | 4 | 57 | 355,817 | 99,491 + 85,442 + 85,442 + 85,442 | 1 | 91.62 | tx bytes 99,227 + 114,745 + 120,643 > 100,000 |
| opt sib,lad,state,cap=3 | 10,000 | 200,000 | 2 | 51 | 313,785 | 199,438 + 114,347 | 1 | 92.21 | tx bytes 293,514 > 200,000 |
| opt sib,lad,state,cap=3 | 10,000 | 400,000 | 1 | 48 | 293,514 | 293,514 | 1 | 92.78 | — |
| opt sib,lad,state,cap=3 | 10,000 | 1,000,000 (consensus only) | 1 | 48 | 293,514 | 293,514 | 1 | 90.93 | — |
| opt sib,lad,state,cap=3 | 100,000 | 100,000 | 4 | 29 | 353,713 | 93,252 + 79,015 + 90,723 + 90,723 | 3 | 86.92 | tx bytes 92,988 + 114,038 + 125,746 > 100,000 |
| opt sib,lad,state,cap=3 | 100,000 | 200,000 | 2 | 23 | 312,209 | 198,433 + 113,776 | 3 | 86.74 | tx bytes 291,940 > 200,000 |
| opt sib,lad,state,cap=3 | 100,000 | 400,000 | 1 | 20 | 291,940 | 291,940 | 3 | 91.65 | — |
| opt sib,lad,state,cap=3 | 100,000 | 1,000,000 (consensus only) | 1 | 20 | 291,940 | 291,940 | 3 | 89.81 | — |
| opt sib,lad,state,cap=3 | 150,000 | 100,000 | 4 | 29 | 353,713 | 93,252 + 79,015 + 90,723 + 90,723 | 3 | 86.92 | tx bytes 92,988 + 114,038 + 125,746 > 100,000 |
| opt sib,lad,state,cap=3 | 150,000 | 200,000 | 2 | 23 | 312,209 | 198,433 + 113,776 | 3 | 86.74 | tx bytes 291,940 > 200,000 |
| opt sib,lad,state,cap=3 | 150,000 | 400,000 | 1 | 20 | 291,940 | 291,940 | 3 | 91.65 | — |
| opt sib,lad,state,cap=3 | 150,000 | 1,000,000 (consensus only) | 1 | 20 | 291,940 | 291,940 | 3 | 89.81 | — |
| baseline | 10,000 | 100,000 | 7 | 78 | 639,351 | 91,633 + 89,848 + 89,848 + 89,848 + 89,848 + 89,848 + 98,478 | 1 | 92.72 | tx bytes 99,705 + 98,174 + 98,174 + 98,174 + 98,174 + 106,804 > 100,000 |
| baseline | 10,000 | 200,000 | 3 | 58 | 482,424 | 158,444 + 157,675 + 166,305 | 1 | 92.6 | tx bytes 218,295 + 226,410 > 200,000 |
| baseline | 10,000 | 400,000 | 2 | 53 | 444,705 | 218,295 + 226,410 | 1 | 92.69 | tx bytes 407,290 > 400,000 |
| baseline | 10,000 | 1,000,000 (consensus only) | 1 | 48 | 407,290 | 407,290 | 1 | 91.7 | — |
| baseline | 100,000 | 100,000 | 5 | 40 | 464,659 | 85,371 + 94,822 + 94,822 + 94,822 + 94,822 | 3 | 93.07 | tx bytes 84,813 + 113,804 + 113,804 + 113,804 > 100,000 |
| baseline | 100,000 | 200,000 | 2 | 25 | 351,185 | 160,843 + 190,342 | 3 | 92.95 | tx bytes 314,268 > 200,000 |
| baseline | 100,000 | 400,000 | 1 | 20 | 314,268 | 314,268 | 3 | 92.97 | — |
| baseline | 100,000 | 1,000,000 (consensus only) | 1 | 20 | 314,268 | 314,268 | 3 | 91.7 | — |
| baseline | 150,000 | 100,000 | 5 | 40 | 464,659 | 85,371 + 94,822 + 94,822 + 94,822 + 94,822 | 3 | 93.07 | tx bytes 84,813 + 113,804 + 113,804 + 113,804 > 100,000 |
| baseline | 150,000 | 200,000 | 2 | 25 | 351,185 | 160,843 + 190,342 | 3 | 92.95 | tx bytes 314,268 > 200,000 |
| baseline | 150,000 | 400,000 | 1 | 20 | 314,268 | 314,268 | 3 | 92.97 | — |
| baseline | 150,000 | 1,000,000 (consensus only) | 1 | 20 | 314,268 | 314,268 | 3 | 91.7 | — |

## Modelled cells

- Groth16 sound-native as 1 input: unlocking <= 27,426 B (needs unlocking limit >= 27,426); op-cost <= 20,804,423 + 7,310 DEFINE = 20,811,733 vs budget 21,973,600 -> 94.7% (worst-case proof; results.json benchmarks.worstCase.opCost). Tx stays 1; only the input count changes (3 -> 1).
- G2 layout b3 at unlocking limit 100,000: queries 12/16/15; inputs 98,432 B, op <= 51,380,036 (65.2%); 83,504 B, op <= 51,869,042 (77.6%); 78,285 B, op <= 51,869,042 (82.8%); stack item = input 0 unlocking 98,432 <= 100,000: true; tx about 260,462 B -> 1 tx iff tx limit >= about 260,462.
  (b2 measured: lib 25,230 B, per-query 5219 B, input-0 fixed part 35,804 B, proof 224,814 B.)
- G2 lower bound at tx limit 100,000: >= 3 tx (proof 224,814 B must be pushed once)
- G2 lower bound at tx limit 200,000: >= 2 tx (proof 224,814 B must be pushed once)
- G2 lower bound at tx limit 400,000: >= 1 tx (proof 224,814 B must be pushed once)
- G2 lower bound at tx limit 1,000,000: >= 1 tx (proof 224,814 B must be pushed once)
