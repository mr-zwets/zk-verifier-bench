## Valid workloads (timing node: acceptnonstdtxn=1, block validation)

| workload | tx B | in | max unl. B | K | BCHN | libauth cons/std | Verify ms/tx (median) | spread | worst input op/budget: libauth cons | + DEFINE (cons) | libauth std + DEFINE | testmempoolaccept (policy node) |
|---|--:|--:|--:|--:|---|---|--:|--:|--:|--:|--:|---|
| plonk-mul2:valid0 | 83171 | 10 | 9228 | 4 | accept | accept/accept | 10.867 | 2.3% | 98.03% | 98.56% | 99.20% | allowed |
| plonk-mul2:valid1 | 82923 | 10 | 9228 | 4 | accept | accept/accept | 11.182 | 5.4% | 98.04% | 98.57% | 99.19% | allowed |
| plonk-mul2:valid2 | 83093 | 10 | 9228 | 4 | accept | accept/accept | 10.947 | 7.4% | 98.04% | 98.57% | 99.19% | allowed |
| plonk-mul2:valid3 | 82888 | 10 | 9228 | 4 | accept | accept/accept | 10.908 | 8.8% | 98.05% | 98.58% | 99.20% | allowed |
| plonk-mul2:valid4 | 83086 | 10 | 9228 | 4 | accept | accept/accept | 10.938 | 7.1% | 98.04% | 98.57% | 99.19% | allowed |
| plonk-merkle16:valid0 | 85109 | 10 | 9461 | 4 | accept | accept/accept | 12.553 | 44.6% | 98.79% | 99.29% | 99.88% | allowed |
| plonk-merkle16:valid1 | 85187 | 10 | 9461 | 4 | accept | accept/accept | 12.400 | 30.1% | 98.68% | 99.18% | 99.77% | allowed |
| plonk-merkle16:valid2 | 85019 | 10 | 9461 | 4 | accept | accept/accept | 11.127 | 2.1% | 98.55% | 99.05% | 99.64% | allowed |
| plonk-merkle16:valid3 | 85164 | 10 | 9461 | 4 | accept | accept/accept | 11.935 | 23.2% | 98.75% | 99.25% | 99.84% | allowed |
| plonk-merkle16:valid4 | 85157 | 10 | 9461 | 4 | accept | accept/accept | 11.880 | 51.9% | 98.91% | 99.41% | 100.00% | allowed |
| plonk-range64:valid0 | 89150 | 10 | 9721 | 3 | accept | accept/accept | 11.833 | 7.0% | 98.59% | 99.09% | 99.59% | allowed |
| plonk-range64:valid1 | 88909 | 10 | 9721 | 3 | accept | accept/accept | 11.803 | 7.3% | 98.31% | 98.85% | 99.39% | allowed |
| plonk-range64:valid2 | 89034 | 10 | 9721 | 3 | accept | accept/accept | 11.840 | 7.8% | 98.23% | 98.75% | 99.29% | allowed |
| plonk-range64:valid3 | 88993 | 10 | 9721 | 3 | accept | accept/accept | 11.860 | 2.1% | 98.57% | 99.06% | 99.57% | allowed |
| plonk-range64:valid4 | 88969 | 10 | 9721 | 3 | accept | accept/accept | 11.810 | 3.8% | 98.23% | 98.75% | 99.28% | allowed |
| plonk-merkle16rc:valid0 | 89398 | 10 | 9773 | 3 | accept | accept/accept | 11.853 | 7.4% | 98.27% | 98.78% | 99.31% | allowed |
| plonk-merkle16rc:valid1 | 89272 | 10 | 9773 | 3 | accept | accept/accept | 11.750 | 7.2% | 98.27% | 98.78% | 99.31% | allowed |
| plonk-merkle16rc:valid2 | 89181 | 10 | 9773 | 3 | accept | accept/accept | 11.793 | 6.6% | 98.28% | 98.79% | 99.31% | allowed |
| plonk-merkle16rc:valid3 | 89514 | 10 | 9773 | 3 | accept | accept/accept | 11.817 | 7.2% | 98.28% | 98.78% | 99.31% | allowed |
| plonk-merkle16rc:valid4 | 89509 | 10 | 9773 | 3 | accept | accept/accept | 11.990 | 6.8% | 98.28% | 98.79% | 99.31% | allowed |
| stark-mimc-S128-0:valid-tx0 | 65350 | 9 | 8755 | 6 | accept | accept/accept | 8.360 | 7.5% | 84.79% | 85.09% | 86.53% | allowed |
| stark-mimc-S128-0:valid-tx1 | 58102 | 8 | 8755 | 7 | accept | accept/accept | 7.321 | 8.8% | 84.79% | 85.10% | 86.53% | allowed |
| stark-mimc-S100b-0:valid-tx0 | 83515 | 12 | 8269 | 5 | accept | accept/accept | 11.700 | 8.9% | 92.04% | 92.48% | 94.00% | allowed |
| stark-fib-S100z-zkmin-0:valid-tx0 | 71142 | 13 | 6278 | 5 | accept | accept/accept | 12.630 | 8.5% | 91.90% | 92.44% | 94.00% | allowed |
| stark-fib-S100z-zkmin-0:valid-tx1 | 65414 | 12 | 6278 | 6 | accept | accept/accept | 11.488 | 8.2% | 91.90% | 92.44% | 94.00% | allowed |
| stark-fib-S128z-zkmin-0:valid-tx0 | 80591 | 12 | 7471 | 5 | accept | accept/accept | 11.964 | 3.2% | 92.05% | 92.50% | 94.00% | allowed |
| stark-fib-S128z-zkmin-0:valid-tx1 | 80331 | 12 | 7471 | 5 | accept | accept/accept | 12.158 | 8.4% | 92.05% | 92.50% | 94.00% | allowed |
| stark-fib-S128z-zkmin-0:valid-tx2 | 73631 | 11 | 7471 | 5 | accept | accept/accept | 10.762 | 9.0% | 92.05% | 92.50% | 94.00% | allowed |
| bch-groth16-bn254-sound-native:valid | 27519 | 3 | 9316 | 10 | accept | accept/accept | 3.522 | 7.4% | 93.54% | 93.54% | 94.00% | REJECTED: 66: min relay fee not met; allowed with fee |
| bch-groth16-bn254-sound-native:extra0 | 27053 | 3 | 9221 | 11 | accept | accept/accept | 3.463 | 2.5% | 93.52% | 93.52% | 94.00% | REJECTED: 66: min relay fee not met; allowed with fee |
| bch-groth16-bn254-sound-native:extra1 | 27026 | 3 | 9221 | 11 | accept | accept/accept | 3.451 | 3.6% | 93.52% | 93.52% | 93.99% | REJECTED: 66: min relay fee not met; allowed with fee |
| bch-groth16-bn254-sound-native:extra2 | 27079 | 3 | 9221 | 11 | accept | accept/accept | 3.461 | 2.5% | 93.50% | 93.50% | 93.98% | REJECTED: 66: min relay fee not met; allowed with fee |
| bch-groth16-bn254-sound-native:worst | 28082 | 3 | 9345 | 10 | accept | accept/accept | 3.545 | 8.2% | 93.53% | 93.53% | 94.00% | REJECTED: 66: min relay fee not met; allowed with fee |
| bch-groth16-bls12381-sound-native:valid | 34089 | 4 | 9755 | 9 | accept | accept/accept | 3.010 | 6.6% | 90.21% | 90.21% | 91.26% | REJECTED: 66: min relay fee not met; allowed with fee |
| bch-groth16-bls12381-sound-native:extra0 | 34473 | 4 | 9755 | 9 | accept | accept/accept | 3.006 | 6.6% | 88.59% | 88.59% | 88.86% | REJECTED: 66: min relay fee not met; allowed with fee |
| bch-groth16-bls12381-sound-native:extra1 | 36105 | 4 | 9755 | 8 | accept | accept/accept | 3.147 | 6.0% | 93.44% | 93.44% | 93.70% | REJECTED: 66: min relay fee not met; allowed with fee |
| bch-groth16-bls12381-sound-native:extra2 | 34041 | 4 | 9755 | 9 | accept | accept/accept | 3.000 | 6.4% | 90.45% | 90.45% | 91.50% | REJECTED: 66: min relay fee not met; allowed with fee |
| bch-groth16-bls12381-sound-native:extra3 | 35385 | 4 | 9755 | 9 | accept | accept/accept | 3.071 | 2.6% | 93.41% | 93.41% | 93.67% | REJECTED: 66: min relay fee not met; allowed with fee |
| bch-groth16-bls12381-sound-native:extra4 | 35673 | 4 | 9755 | 9 | accept | accept/accept | 3.060 | 2.4% | 90.36% | 90.36% | 90.62% | REJECTED: 66: min relay fee not met; allowed with fee |
| bch-groth16-bls12381-sound-native:extra5 | 34041 | 4 | 9755 | 9 | accept | accept/accept | 3.066 | 2.6% | 92.76% | 92.76% | 93.82% | REJECTED: 66: min relay fee not met; allowed with fee |
| bch-groth16-bls12381-sound-native:worst | 37497 | 4 | 9805 | 8 | accept | accept/accept | 3.152 | 3.1% | 93.58% | 93.58% | 93.81% | REJECTED: 66: min relay fee not met; allowed with fee |

## Rejection tests (K = 1; BCHN block verdict, libauth consensus verdict, BCHN mempool script error)

| group | cases | BCHN rejected | libauth rejected | both as expected | mempool reasons |
|---|--:|--:|--:|--:|---|
| plonk-mul2 | 20 | 20 | 20 | 20 | 16: mandatory-script-verify-flag-failed |
| plonk-merkle16 | 20 | 20 | 20 | 20 | 16: mandatory-script-verify-flag-failed |
| plonk-range64 | 20 | 20 | 20 | 20 | 16: mandatory-script-verify-flag-failed |
| plonk-merkle16rc | 20 | 20 | 20 | 20 | 16: mandatory-script-verify-flag-failed |
| stark-mimc-S128-0 | 14 | 14 | 14 | 14 | 16: mandatory-script-verify-flag-failed |
| stark-mimc-S100b-0 | 12 | 12 | 12 | 12 | 16: mandatory-script-verify-flag-failed |
| stark-fib-S100z-zkmin-0 | 15 | 15 | 15 | 15 | 16: mandatory-script-verify-flag-failed |
| stark-fib-S128z-zkmin-0 | 15 | 15 | 15 | 15 | 16: mandatory-script-verify-flag-failed |
| sound-native | 2 | 2 | 2 | 2 | 66: min relay fee not met |

Not as expected / errors: none

## OP_DEFINE probes (one input's FILL sized one byte under / at the libauth consensus op-cost + DEFINE body bytes)

| probe | description | libauth cons | BCHN block | BCHN mempool |
|---|---|---|---|---|
| plonk-mul2:define-probe-cons-under | input 9 (SI) FILL 1940: budget 6455200, libauth consensus op 6420618 + DEFINE bodies 34713 = 6455331 (over budget by 131) | accept | reject: blk-bad-inputs | 16: mandatory-script-verify-flag-failed (VM cost limit exceeded) |
| plonk-mul2:define-probe-cons-over | input 9 (SI) FILL 1941: budget 6456000, libauth consensus op 6420620 + DEFINE bodies 34713 = 6455333 (within budget by 667) | accept | accept | allowed |
| plonk-mul2:define-probe-std-under | input 9 (SI) FILL 1991: budget 6496000, libauth standard op 6461424 + DEFINE bodies 34713 = 6496137 (over budget by 137) | accept | accept | allowed |
| plonk-mul2:define-probe-std-over | input 9 (SI) FILL 1992: budget 6496800, libauth standard op 6461426 + DEFINE bodies 34713 = 6496139 (within budget by 661) | accept | accept | allowed |
| plonk-merkle16:define-probe-cons-under | input 9 (SI) FILL 2052: budget 6852000, libauth consensus op 6815966 + DEFINE bodies 36335 = 6852301 (over budget by 301) | accept | reject: blk-bad-inputs | 16: mandatory-script-verify-flag-failed (VM cost limit exceeded) |
| plonk-merkle16:define-probe-cons-over | input 9 (SI) FILL 2053: budget 6852800, libauth consensus op 6815968 + DEFINE bodies 36335 = 6852303 (within budget by 497) | accept | accept | allowed |
| plonk-merkle16:define-probe-std-under | input 9 (SI) FILL 2105: budget 6894400, libauth standard op 6858312 + DEFINE bodies 36335 = 6894647 (over budget by 247) | accept | accept | allowed |
| plonk-merkle16:define-probe-std-over | input 9 (SI) FILL 2106: budget 6895200, libauth standard op 6858314 + DEFINE bodies 36335 = 6894649 (within budget by 551) | accept | accept | allowed |
| plonk-range64:define-probe-cons-under | input 9 (SI) FILL 1246: budget 7231200, libauth consensus op 7193694 + DEFINE bodies 38043 = 7231737 (over budget by 537) | accept | reject: blk-bad-inputs | 16: mandatory-script-verify-flag-failed (VM cost limit exceeded) |
| plonk-range64:define-probe-cons-over | input 9 (SI) FILL 1247: budget 7232000, libauth consensus op 7193696 + DEFINE bodies 38043 = 7231739 (within budget by 261) | accept | accept | allowed |
| plonk-range64:define-probe-std-under | input 9 (SI) FILL 1301: budget 7275200, libauth standard op 7237836 + DEFINE bodies 38043 = 7275879 (over budget by 679) | accept | accept | allowed |
| plonk-range64:define-probe-std-over | input 9 (SI) FILL 1302: budget 7276000, libauth standard op 7237838 + DEFINE bodies 38043 = 7275881 (within budget by 119) | accept | accept | allowed |
| plonk-merkle16rc:define-probe-cons-under | input 9 (SI) FILL 1093: budget 7252000, libauth consensus op 7213397 + DEFINE bodies 38624 = 7252021 (over budget by 21) | accept | reject: blk-bad-inputs | 16: mandatory-script-verify-flag-failed (VM cost limit exceeded) |
| plonk-merkle16rc:define-probe-cons-over | input 9 (SI) FILL 1094: budget 7252800, libauth consensus op 7213399 + DEFINE bodies 38624 = 7252023 (within budget by 777) | accept | accept | allowed |
| plonk-merkle16rc:define-probe-std-under | input 9 (SI) FILL 1149: budget 7296800, libauth standard op 7258309 + DEFINE bodies 38624 = 7296933 (over budget by 133) | accept | accept | allowed |
| plonk-merkle16rc:define-probe-std-over | input 9 (SI) FILL 1150: budget 7297600, libauth standard op 7258311 + DEFINE bodies 38624 = 7296935 (within budget by 665) | accept | accept | allowed |

## Policy node (acceptnonstdtxn=0): testmempoolaccept of every valid workload tx

| workload | chained inputs | tx B | fee sat/B (as exported) | allowed | reject reason | after fee retry |
|---|--:|--:|--:|---|---|---|
| plonk-mul2:valid0 | 0 | 83171 | 12.01 | true |  |  |
| plonk-mul2:valid1 | 0 | 82923 | 12.05 | true |  |  |
| plonk-mul2:valid2 | 0 | 83093 | 12.02 | true |  |  |
| plonk-mul2:valid3 | 0 | 82888 | 12.05 | true |  |  |
| plonk-mul2:valid4 | 0 | 83086 | 12.02 | true |  |  |
| plonk-mul2:define-probe-cons-under | 0 | 83053 | 12.03 | false | 16: mandatory-script-verify-flag-failed (VM cost limit exceeded) |  |
| plonk-mul2:define-probe-cons-over | 0 | 83054 | 12.03 | false | 16: mandatory-script-verify-flag-failed (VM cost limit exceeded) |  |
| plonk-mul2:define-probe-std-under | 0 | 83104 | 12.02 | false | 16: mandatory-script-verify-flag-failed (VM cost limit exceeded) |  |
| plonk-mul2:define-probe-std-over | 0 | 83105 | 12.02 | true |  |  |
| plonk-merkle16:valid0 | 0 | 85109 | 11.74 | true |  |  |
| plonk-merkle16:valid1 | 0 | 85187 | 11.73 | true |  |  |
| plonk-merkle16:valid2 | 0 | 85019 | 11.75 | true |  |  |
| plonk-merkle16:valid3 | 0 | 85164 | 11.73 | true |  |  |
| plonk-merkle16:valid4 | 0 | 85157 | 11.73 | true |  |  |
| plonk-merkle16:define-probe-cons-under | 0 | 84989 | 11.75 | false | 16: mandatory-script-verify-flag-failed (VM cost limit exceeded) |  |
| plonk-merkle16:define-probe-cons-over | 0 | 84990 | 11.75 | false | 16: mandatory-script-verify-flag-failed (VM cost limit exceeded) |  |
| plonk-merkle16:define-probe-std-under | 0 | 85042 | 11.75 | false | 16: mandatory-script-verify-flag-failed (VM cost limit exceeded) |  |
| plonk-merkle16:define-probe-std-over | 0 | 85043 | 11.75 | true |  |  |
| plonk-range64:valid0 | 0 | 89150 | 11.21 | true |  |  |
| plonk-range64:valid1 | 0 | 88909 | 11.24 | true |  |  |
| plonk-range64:valid2 | 0 | 89034 | 11.22 | true |  |  |
| plonk-range64:valid3 | 0 | 88993 | 11.23 | true |  |  |
| plonk-range64:valid4 | 0 | 88969 | 11.23 | true |  |  |
| plonk-range64:define-probe-cons-under | 0 | 89027 | 11.22 | false | 16: mandatory-script-verify-flag-failed (VM cost limit exceeded) |  |
| plonk-range64:define-probe-cons-over | 0 | 89028 | 11.22 | false | 16: mandatory-script-verify-flag-failed (VM cost limit exceeded) |  |
| plonk-range64:define-probe-std-under | 0 | 89082 | 11.21 | false | 16: mandatory-script-verify-flag-failed (VM cost limit exceeded) |  |
| plonk-range64:define-probe-std-over | 0 | 89083 | 11.21 | true |  |  |
| plonk-merkle16rc:valid0 | 0 | 89398 | 11.17 | true |  |  |
| plonk-merkle16rc:valid1 | 0 | 89272 | 11.19 | true |  |  |
| plonk-merkle16rc:valid2 | 0 | 89181 | 11.20 | true |  |  |
| plonk-merkle16rc:valid3 | 0 | 89514 | 11.16 | true |  |  |
| plonk-merkle16rc:valid4 | 0 | 89509 | 11.16 | true |  |  |
| plonk-merkle16rc:define-probe-cons-under | 0 | 89275 | 11.19 | false | 16: mandatory-script-verify-flag-failed (VM cost limit exceeded) |  |
| plonk-merkle16rc:define-probe-cons-over | 0 | 89276 | 11.19 | false | 16: mandatory-script-verify-flag-failed (VM cost limit exceeded) |  |
| plonk-merkle16rc:define-probe-std-under | 0 | 89331 | 11.18 | false | 16: mandatory-script-verify-flag-failed (VM cost limit exceeded) |  |
| plonk-merkle16rc:define-probe-std-over | 0 | 89332 | 11.18 | true |  |  |
| stark-mimc-S128-0:valid-tx0 | 0 | 65350 | 1.35 | true |  |  |
| stark-mimc-S128-0:valid-tx1 | 1 | 58102 | 1.20 | true |  |  |
| stark-mimc-S100b-0:valid-tx0 | 0 | 83515 | 1.42 | true |  |  |
| stark-fib-S100z-zkmin-0:valid-tx0 | 0 | 71142 | 1.80 | true |  |  |
| stark-fib-S100z-zkmin-0:valid-tx1 | 1 | 65414 | 1.68 | true |  |  |
| stark-fib-S128z-zkmin-0:valid-tx0 | 0 | 80591 | 1.45 | true |  |  |
| stark-fib-S128z-zkmin-0:valid-tx1 | 1 | 80331 | 1.37 | true |  |  |
| stark-fib-S128z-zkmin-0:valid-tx2 | 1 | 73631 | 1.36 | true |  |  |
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
