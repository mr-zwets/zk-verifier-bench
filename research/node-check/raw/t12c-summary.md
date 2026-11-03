## Valid workloads (timing node: acceptnonstdtxn=1, block validation)

| workload | tx B | in | max unl. B | K | BCHN | libauth cons/std | Verify ms/tx (median) | spread | worst input op/budget: libauth cons | + DEFINE (cons) | libauth std + DEFINE | testmempoolaccept (policy node) |
|---|--:|--:|--:|--:|---|---|--:|--:|--:|--:|--:|---|
| pinned-risc0:risc0:valid:control: real proof risc0-test-receipt-V5_0 re-randomized, PLAIN verifier core (no application binding) | 27548 | 3 | 9359 | 10 | accept | accept/accept | 3.470 | 2.2% | 93.54% | 93.54% | 94.00% | allowed |
| pinned-risc0-v3:risc0:valid:control: real proof risc0-test-receipt-V3_0 re-randomized, PLAIN verifier core (no application binding) | 27562 | 3 | 9358 | 10 | accept | accept/accept | 3.471 | 2.0% | 93.54% | 93.54% | 94.00% | allowed |
| pinned-sp1-v5:sp1:valid:control: real proof silvana-add re-randomized, PLAIN verifier core (no application binding) | 27536 | 3 | 9326 | 10 | accept | accept/accept | 3.475 | 2.5% | 93.54% | 93.54% | 94.00% | allowed |
| pinned-test:sp1:valid:control: proof of the exact statement (2 outputs: P2PKH payout 200,000 sat + OP_RETURN memo) | 27604 | 3 | 9342 | 10 | accept | accept/accept | 3.487 | 1.9% | 93.54% | 93.54% | 93.99% | allowed |
| pinned-test:sp1:valid:control: a 1-output statement (payout only), its own proof | 27634 | 3 | 9327 | 10 | accept | accept/accept | 3.487 | 7.9% | 93.54% | 93.54% | 94.00% | allowed |
| pinned-test:sp1:valid:control: the proof RE-RANDOMIZED (A, B, C all differ), same outputs | 27609 | 3 | 9344 | 10 | accept | accept/accept | 3.503 | 2.4% | 93.53% | 93.53% | 93.99% | allowed |
| pinned-test:risc0:valid:control: proof of the exact statement (2 outputs: P2PKH payout 200,000 sat + OP_RETURN memo) | 27738 | 3 | 9385 | 10 | accept | accept/accept | 3.471 | 1.8% | 93.50% | 93.50% | 93.99% | allowed |
| pinned-test:risc0:valid:control: a 1-output statement (payout only), its own proof | 27692 | 3 | 9385 | 10 | accept | accept/accept | 3.479 | 1.7% | 93.49% | 93.49% | 93.97% | allowed |
| pinned-test:risc0:valid:control: the proof RE-RANDOMIZED (A, B, C all differ), same outputs | 27738 | 3 | 9385 | 10 | accept | accept/accept | 3.471 | 2.3% | 93.51% | 93.51% | 94.00% | allowed |
| bch-groth16-bn254-sound-native:valid | 27519 | 3 | 9316 | 10 | accept | accept/accept | 3.481 | 2.0% | 93.74% | 93.74% | 94.20% | REJECTED: 66: min relay fee not met; allowed with fee |
| bch-groth16-bn254-sound-native:extra0 | 27053 | 3 | 9221 | 11 | accept | accept/accept | 3.424 | 2.4% | 93.74% | 93.74% | 94.21% | REJECTED: 66: min relay fee not met; allowed with fee |
| bch-groth16-bn254-sound-native:extra1 | 27026 | 3 | 9221 | 11 | accept | accept/accept | 3.419 | 2.3% | 93.73% | 93.73% | 94.21% | REJECTED: 66: min relay fee not met; allowed with fee |
| bch-groth16-bn254-sound-native:extra2 | 27079 | 3 | 9221 | 11 | accept | accept/accept | 3.420 | 7.1% | 93.72% | 93.72% | 94.19% | REJECTED: 66: min relay fee not met; allowed with fee |
| bch-groth16-bn254-sound-native:worst | 28082 | 3 | 9345 | 10 | accept | accept/accept | 3.484 | 2.2% | 93.72% | 93.72% | 94.19% | REJECTED: 66: min relay fee not met; allowed with fee |
| bch-groth16-bls12381-sound-native:valid | 34089 | 4 | 9755 | 9 | accept | accept/accept | 2.979 | 2.0% | 90.46% | 90.46% | 91.51% | REJECTED: 66: min relay fee not met; allowed with fee |
| bch-groth16-bls12381-sound-native:extra0 | 34473 | 4 | 9755 | 9 | accept | accept/accept | 2.993 | 1.6% | 88.79% | 88.79% | 89.05% | REJECTED: 66: min relay fee not met; allowed with fee |
| bch-groth16-bls12381-sound-native:extra1 | 36105 | 4 | 9755 | 8 | accept | accept/accept | 3.107 | 3.4% | 93.63% | 93.63% | 93.90% | REJECTED: 66: min relay fee not met; allowed with fee |
| bch-groth16-bls12381-sound-native:extra2 | 34041 | 4 | 9755 | 9 | accept | accept/accept | 2.977 | 1.3% | 90.70% | 90.70% | 91.75% | REJECTED: 66: min relay fee not met; allowed with fee |
| bch-groth16-bls12381-sound-native:extra3 | 35385 | 4 | 9755 | 9 | accept | accept/accept | 3.053 | 2.6% | 93.61% | 93.61% | 93.87% | REJECTED: 66: min relay fee not met; allowed with fee |
| bch-groth16-bls12381-sound-native:extra4 | 35673 | 4 | 9755 | 9 | accept | accept/accept | 3.031 | 2.0% | 90.56% | 90.56% | 90.82% | REJECTED: 66: min relay fee not met; allowed with fee |
| bch-groth16-bls12381-sound-native:extra5 | 34041 | 4 | 9755 | 9 | accept | accept/accept | 3.031 | 2.7% | 93.02% | 93.02% | 94.07% | REJECTED: 66: min relay fee not met; allowed with fee |
| bch-groth16-bls12381-sound-native:worst | 37497 | 4 | 9805 | 8 | accept | accept/accept | 3.114 | 2.6% | 93.74% | 93.74% | 93.99% | REJECTED: 66: min relay fee not met; allowed with fee |

## Rejection tests (K = 1; BCHN block verdict, libauth consensus verdict, BCHN mempool script error)

| group | cases | BCHN rejected | libauth rejected | both as expected | mempool reasons |
|---|--:|--:|--:|--:|---|
| pinned-risc0 | 3 | 3 | 3 | 3 | 16: mandatory-script-verify-flag-failed |
| pinned-risc0-v3 | 3 | 3 | 3 | 3 | 16: mandatory-script-verify-flag-failed |
| pinned-sp1-v5 | 9 | 9 | 9 | 9 | 16: mandatory-script-verify-flag-failed |
| pinned-test | 84 | 84 | 84 | 84 | 16: mandatory-script-verify-flag-failed |
| sound-native | 2 | 2 | 2 | 2 | 66: min relay fee not met |

Not as expected / errors: none

## Policy node (acceptnonstdtxn=0): testmempoolaccept of every valid workload tx

| workload | chained inputs | tx B | fee sat/B (as exported) | allowed | reject reason | after fee retry |
|---|--:|--:|--:|---|---|---|
| pinned-risc0:risc0:valid:control: real proof risc0-test-receipt-V5_0 re-randomized, PLAIN verifier core (no application binding) | 0 | 27548 | 21.74 | true |  |  |
| pinned-risc0-v3:risc0:valid:control: real proof risc0-test-receipt-V3_0 re-randomized, PLAIN verifier core (no application binding) | 0 | 27562 | 21.73 | true |  |  |
| pinned-sp1-v5:sp1:valid:control: real proof silvana-add re-randomized, PLAIN verifier core (no application binding) | 0 | 27536 | 21.75 | true |  |  |
| pinned-test:sp1:valid:control: proof of the exact statement (2 outputs: P2PKH payout 200,000 sat + OP_RETURN memo) | 0 | 27604 | 14.49 | true |  |  |
| pinned-test:sp1:valid:control: a 1-output statement (payout only), its own proof | 0 | 27634 | 14.47 | true |  |  |
| pinned-test:sp1:valid:control: the proof RE-RANDOMIZED (A, B, C all differ), same outputs | 0 | 27609 | 14.49 | true |  |  |
| pinned-test:risc0:valid:control: proof of the exact statement (2 outputs: P2PKH payout 200,000 sat + OP_RETURN memo) | 0 | 27738 | 14.42 | true |  |  |
| pinned-test:risc0:valid:control: a 1-output statement (payout only), its own proof | 0 | 27692 | 14.44 | true |  |  |
| pinned-test:risc0:valid:control: the proof RE-RANDOMIZED (A, B, C all differ), same outputs | 0 | 27738 | 14.42 | true |  |  |
| bch-groth16-bn254-sound-native:valid | 0 | 27519 | 0.07 | false | 66: min relay fee not met | allowed (2.00 sat/B) |
| bch-groth16-bn254-sound-native:extra0 | 0 | 27053 | 0.07 | false | 66: min relay fee not met | allowed (2.00 sat/B) |
| bch-groth16-bn254-sound-native:extra1 | 0 | 27026 | 0.07 | false | 66: min relay fee not met | allowed (2.00 sat/B) |
| bch-groth16-bn254-sound-native:extra2 | 0 | 27079 | 0.07 | false | 66: min relay fee not met | allowed (2.00 sat/B) |
| bch-groth16-bn254-sound-native:worst | 0 | 28082 | 0.07 | false | 66: min relay fee not met | allowed (2.00 sat/B) |
| bch-groth16-bls12381-sound-native:valid | 0 | 34089 | 0.09 | false | 66: min relay fee not met | allowed (2.00 sat/B) |
| bch-groth16-bls12381-sound-native:extra0 | 0 | 34473 | 0.09 | false | 66: min relay fee not met | allowed (2.00 sat/B) |
| bch-groth16-bls12381-sound-native:extra1 | 0 | 36105 | 0.08 | false | 66: min relay fee not met | allowed (2.00 sat/B) |
| bch-groth16-bls12381-sound-native:extra2 | 0 | 34041 | 0.09 | false | 66: min relay fee not met | allowed (2.00 sat/B) |
| bch-groth16-bls12381-sound-native:extra3 | 0 | 35385 | 0.08 | false | 66: min relay fee not met | allowed (2.00 sat/B) |
| bch-groth16-bls12381-sound-native:extra4 | 0 | 35673 | 0.08 | false | 66: min relay fee not met | allowed (2.00 sat/B) |
| bch-groth16-bls12381-sound-native:extra5 | 0 | 34041 | 0.09 | false | 66: min relay fee not met | allowed (2.00 sat/B) |
| bch-groth16-bls12381-sound-native:worst | 0 | 37497 | 0.08 | false | 66: min relay fee not met | allowed (2.00 sat/B) |
