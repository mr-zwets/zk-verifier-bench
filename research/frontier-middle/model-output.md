## BN254

### Validation (model vs measured)

| entry | model B | meas B | model op M | meas op M |
|---|--:|--:|--:|--:|
| singleton (plain) | 8206 | 8206 | 771.1 | 771.3 |
| singleton-opcode-optimized | 6236 | 6237 | 799.6 | 800.2 |
| singleton-minop | 58285 | 58073 | 64.8 | 64.8 |

### Predicted Pareto set (bytes, op-cost), nominal

| design | bytes (lo-hi) | op M (lo-hi) | worst-proof op M | inputs |
|---|--:|--:|--:|--:|
| F12/red shared res vkx=jac B=proj g=proj d=proj rolled +outline | 4536 (4285-4889) | 358.1 (343.1-375.9) | 416.5 | 1 |
| F12/red shared res vkx=glv_jac B=proj g=proj d=proj rolled +outline | 5033 (4751-5428) | 323.2 (308.4-341.4) | 336.6 | 1 |
| F12/red shared res vkx=glv_aff B=proj g=proj d=proj rolled +outline | 6251 (5956-6664) | 322.4 (308.3-339.6) | 330.4 | 1 |
| F12/red shared res vkx=glv_jac B=proj g=proj d=proj rolled | 6449 (6449-6449) | 311.7 (304.7-323.5) | 325.1 | 1 |
| F12/lazy shared res vkx=jac B=proj g=proj d=proj rolled +outline | 6536 (5717-7845) | 155.6 (133.8-186.8) | 214.1 | 1 |
| F12/lazy shared res vkx=glv_jac B=proj g=proj d=proj rolled +outline | 7093 (6244-8445) | 121.0 (99.2-152.6) | 134.4 | 1 |
| F12/lazy shared res vkx=glv_jac B=proj g=proj d=proj rolled | 8235 (7650-9125) | 117.5 (98.3-146.1) | 130.9 | 1 |
| F12/lazy shared res vkx=glv_aff B=proj g=proj d=proj rolled | 9517 (8932-10407) | 116.7 (98.1-144.4) | 124.7 | 1 |
| F12/lazy shared res vkx=glv_jac B=proj g=proj d=pile rolled +outline | 13188 (11987-15033) | 104.2 (87.1-129.2) | 117.5 | 1 |
| F12/lazy shared res vkx=glv_aff B=proj g=proj d=pile rolled +outline | 14432 (13217-16295) | 103.4 (86.9-127.4) | 111.4 | 1 |
| F12/lazy shared res vkx=glv_jac B=proj g=proj d=pile rolled | 15388 (14803-16278) | 101.1 (86.2-123.6) | 114.5 | 1 |
| ZEV/single delta=proj B=keep m=2 | 16453 (16333-16633) | 31.9 (30.0-34.5) | 31.9 | 1 |
| ZEV/single delta=pile B=keep m=2 | 21915 (21915-21915) | 23.3 (23.3-23.3) | 23.3 | 1 |
| ZEV/native delta=pile B=keep m=2 | 27624 (27624-27624) | 20.6 (20.6-20.6) | 20.6 | 3 |

### Best effective size per k (KB): predicted (pessimistic band) vs today

| k | today | predicted best | design | pessimistic | change |
|--:|--:|--:|---|--:|--:|
| 1 | 27.6 | 27.6 | (today's entry) | 27.6 | +0% |
| 2 | 21.9 | 19.9 | ZEV/single delta=proj B=keep m=2 | 21.5 | -9% |
| 5 | 21.9 | 16.5 | ZEV/single delta=proj B=keep m=2 | 16.6 | -25% |
| 10 | 21.9 | 13.2 | F12/lazy shared res vkx=glv_jac B=proj g=proj d=pile rolled +outline | 16.1 | -40% |
| 25 | 21.9 | 7.1 | F12/lazy shared res vkx=glv_jac B=proj g=proj d=proj rolled +outline | 8.4 | -68% |
| 50 | 19.2 | 6.5 | F12/lazy shared res vkx=jac B=proj g=proj d=proj rolled +outline | 7.8 | -66% |
| 100 | 9.6 | 4.5 | F12/red shared res vkx=jac B=proj g=proj d=proj rolled +outline | 4.9 | -53% |

### Named designs

| design | bytes (lo-hi) | op M (lo-hi) | worst op M | in | per-input script <=10 kB | k_min bch-2026 | k_min bch-spec | E1 | E2 | E5 | E10 | E25 | E50 | E100 |
|---|--:|--:|--:|--:|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| T1 SI-GLS + on-chain projective delta walk | 16453 (16333-16633) | 31.9 (30.0-34.5) | 31.9 | 1 | no (bch-spec) | 2.43 | 1.51 | 39.8 | 19.9 | 16.5 | 16.5 | 16.5 | 16.5 | 16.5 |
| T2 rolled lazy-tower residue singleton (all walks projective, GLV-Jacobian vk_x) | 8235 (7650-9125) | 117.5 (98.3-146.1) | 130.9 | 1 | yes | 17.96 | 8.10 | 146.8 | 73.4 | 29.3 | 14.6 | 8.2 | 8.2 | 8.2 |
| T2+outline (recompiler pass) | 7093 (6244-8445) | 121.0 (99.2-152.6) | 134.4 | 1 | yes | 21.50 | 8.90 | 151.2 | 75.6 | 30.2 | 15.1 | 7.1 | 7.1 | 7.1 |
| T2 with delta slope pile (build flag) | 15388 (14803-16278) | 101.1 (86.2-123.6) | 114.5 | 1 | no (bch-spec) | 8.24 | 5.00 | 126.4 | 63.2 | 25.2 | 15.4 | 15.4 | 15.4 | 15.4 |
| R reduced-tower residue singleton (plain singleton minus FE/subgroup walk/4 loops) | 5033 (4751-5428) | 323.2 (308.4-341.4) | 336.6 | 1 | yes | 81.19 | 27.05 | 404.0 | 202.0 | 80.8 | 40.4 | 16.1 | 8.0 | 5.0 |
| native + on-chain projective delta (multi-input, bch-2026 sizes) | 22193 (22073-22373) | 29.2 (27.3-31.7) | 29.2 | 3 | yes | 1.66 | 0.70 | 36.3 | 22.2 | 22.2 | 22.2 | 22.2 | 22.2 | 22.2 |
| native + on-chain projective delta + projective B (multi-input, bch-2026 sizes) | 19871 (19751-20051) | 33.4 (30.6-36.8) | 33.4 | 3 | yes | 2.12 | 0.84 | 41.6 | 20.7 | 19.9 | 19.9 | 19.9 | 19.9 | 19.9 |
| rolled minop with slope piles (hint-heavy F12) | 26858 (26648-27208) | 72.7 (68.3-80.3) | 80.7 | 1 | no (bch-spec) | 3.39 | 2.47 | 90.9 | 45.4 | 26.9 | 26.9 | 26.9 | 26.9 | 26.9 |

#### T1 SI-GLS + on-chain projective delta walk: component rows (op M, code B, hint B)

| row | op M | code B | hint B |
|---|--:|--:|--:|
| measured base (BN254 single) | 23.337 | 21915 | 0 |
| delta: drop baked slope pile | -4.263 | -5858 | 0 |
| delta: projective walk on-chain (B kernel reused) | 12.8 | 300 | 0 |
| delta: projective delta lines raise max chunk degree (+~3 quotient words) | 0.02 | 96 | 0 |

#### T2 rolled lazy-tower residue singleton (all walks projective, GLV-Jacobian vk_x): component rows (op M, code B, hint B)

| row | op M | code B | hint B |
|---|--:|--:|--:|
| input checks | 0.082 | 230 | 0 |
| fused endpoint G2 check | 0.254 | 220 | 0 |
| vk_x glv_jac | 1.9 | 1500 | 45 |
| Fp12 squarings x65 | 11.466 | 0 | 0 |
| pair B: 88 lines | 15.4 | 0 | 0 |
| pair B: projective walk | 16.3 | 0 | 0 |
| pair gamma: 88 lines | 15.4 | 0 | 0 |
| pair gamma: projective walk | 16.3 | 0 | 0 |
| pair delta: 88 lines | 15.4 | 0 | 0 |
| pair delta: projective walk | 16.3 | 0 | 0 |
| general 034 line kernel | 0 | 1200 | 0 |
| projective G2 kernels | 0 | 450 | 0 |
| tower kernels (sqr, helpers, torus mul) | 0 | 1849 | 0 |
| baked e(alpha,beta) constant | 0.18 | 198 | 0 |
| VK G2 constants (gamma, delta walk starts) | 0 | 256 | 0 |
| residue c-folds | 3.793 | 0 | 0 |
| residue terminal | 0.777 | 1000 | 198 |
| rolled loop | 3.87 | 700 | 0 |
| cleanup | 0.05 | 10 | 0 |

#### T2 with delta slope pile (build flag): component rows (op M, code B, hint B)

| row | op M | code B | hint B |
|---|--:|--:|--:|
| input checks | 0.082 | 230 | 0 |
| fused endpoint G2 check | 0.254 | 220 | 0 |
| vk_x glv_jac | 1.9 | 1500 | 45 |
| Fp12 squarings x65 | 11.466 | 0 | 0 |
| pair B: 88 lines | 15.4 | 0 | 0 |
| pair B: projective walk | 16.3 | 0 | 0 |
| pair gamma: 88 lines | 15.4 | 0 | 0 |
| pair gamma: projective walk | 16.3 | 0 | 0 |
| pair delta: 88 lines | 12.206 | 0 | 0 |
| pair delta: slope pile + x/c recursion | 3.08 | 5632 | 0 |
| unit line kernel + unit coords | 0.059 | 1272 | 99 |
| general 034 line kernel | 0 | 1200 | 0 |
| projective G2 kernels | 0 | 450 | 0 |
| pile recursion code | 0 | 150 | 0 |
| tower kernels (sqr, helpers, torus mul) | 0 | 1849 | 0 |
| baked e(alpha,beta) constant | 0.18 | 198 | 0 |
| VK G2 constants (gamma, delta walk starts) | 0 | 256 | 0 |
| residue c-folds | 3.793 | 0 | 0 |
| residue terminal | 0.777 | 1000 | 198 |
| rolled loop | 3.87 | 700 | 0 |
| cleanup | 0.05 | 10 | 0 |

## BLS12-381

### Validation (model vs measured)

| entry | model B | meas B | model op M | meas op M |
|---|--:|--:|--:|--:|
| singleton (plain) | 7510 | 7510 | 994.6 | 994.6 |
| singleton-opcode-optimized | 5999 | 5999 | 1003.5 | 1003.5 |
| singleton-minop | 59241 | 58841 | 145.7 | 145.6 |

### Predicted Pareto set (bytes, op-cost), nominal

| design | bytes (lo-hi) | op M (lo-hi) | worst-proof op M | inputs |
|---|--:|--:|--:|--:|
| F12/red shared res vkx=straus B=proj g=proj d=proj rolled +outline | 5282 (5014-5657) | 412.2 (405.7-420.8) | 475.2 | 1 |
| F12/red shared res vkx=glv_jac B=proj g=proj d=proj rolled +outline | 6107 (5791-6551) | 404.8 (398.4-413.4) | 430.3 | 1 |
| F12/lazy shared res vkx=straus B=proj g=proj d=proj rolled +outline | 6200 (5666-7059) | 202.5 (196.5-209.8) | 265.6 | 1 |
| F12/lazy shared res vkx=glv_jac B=proj g=proj d=proj rolled +outline | 7089 (6506-8016) | 195.0 (189.1-202.2) | 220.5 | 1 |
| F12/lazy shared res vkx=glv_jac B=proj g=proj d=proj rolled | 8189 (7919-8639) | 189.3 (187.3-193.5) | 214.9 | 1 |
| F12/lazy shared res vkx=straus B=proj g=proj d=pile rolled +outline | 11958 (11085-13291) | 187.4 (179.7-197.5) | 250.4 | 1 |
| F12/lazy shared res vkx=glv_jac B=proj g=proj d=pile rolled +outline | 12847 (11925-14248) | 179.9 (172.4-189.9) | 205.4 | 1 |
| F12/lazy shared res vkx=glv_jac B=proj g=proj d=pile rolled | 14963 (14693-15413) | 174.7 (170.7-181.7) | 200.2 | 1 |
| F12/lazy shared res vkx=straus B=proj g=pile d=pile rolled +outline | 17588 (16384-19385) | 172.3 (163.0-185.2) | 235.3 | 1 |
| F12/lazy shared res vkx=glv_jac B=proj g=pile d=pile rolled +outline | 18477 (17224-20342) | 164.8 (155.6-177.6) | 190.3 | 1 |
| ZEV/single delta=proj B=proj m=2 | 18661 (18541-18841) | 37.3 (34.7-40.6) | 37.3 | 1 |
| ZEV/single delta=proj B=keep m=2 | 20159 (20039-20339) | 35.9 (33.6-39.0) | 35.9 | 1 |
| ZEV/single delta=pile B=proj m=2 | 24986 (24986-24986) | 27.4 (27.1-27.7) | 27.4 | 1 |
| ZEV/single delta=pile B=keep m=2 | 26484 (26484-26484) | 26.1 (26.1-26.1) | 26.1 | 1 |
| ZEV/native delta=pile B=keep m=2 | 34229 (34229-34229) | 24.0 (24.0-24.0) | 24.0 | 4 |

### Best effective size per k (KB): predicted (pessimistic band) vs today

| k | today | predicted best | design | pessimistic | change |
|--:|--:|--:|---|--:|--:|
| 1 | 32.5 | 32.5 | (today's entry) | 32.5 | +0% |
| 2 | 26.5 | 22.4 | ZEV/single delta=proj B=keep m=2 | 24.3 | -15% |
| 5 | 26.5 | 18.7 | ZEV/single delta=proj B=proj m=2 | 18.8 | -30% |
| 10 | 26.5 | 18.7 | ZEV/single delta=proj B=proj m=2 | 18.8 | -30% |
| 25 | 26.5 | 9.4 | F12/lazy shared res vkx=glv_jac B=proj g=proj d=proj rolled | 9.6 | -64% |
| 50 | 24.8 | 6.2 | F12/lazy shared res vkx=straus B=proj g=proj d=proj rolled +outline | 7.1 | -75% |
| 100 | 12.4 | 5.3 | F12/red shared res vkx=straus B=proj g=proj d=proj rolled +outline | 5.7 | -57% |

### Named designs

| design | bytes (lo-hi) | op M (lo-hi) | worst op M | in | per-input script <=10 kB | k_min bch-2026 | k_min bch-spec | E1 | E2 | E5 | E10 | E25 | E50 | E100 |
|---|--:|--:|--:|--:|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| T1 SI-GLS + on-chain projective delta walk + all-projective B | 18661 (18541-18841) | 37.3 (34.7-40.6) | 37.3 | 1 | no (bch-spec) | 2.50 | 1.63 | 46.5 | 23.2 | 18.7 | 18.7 | 18.7 | 18.7 | 18.7 |
| T1a SI-GLS + on-chain projective delta walk (keep affine B segment) | 20159 (20039-20339) | 35.9 (33.6-39.0) | 35.9 | 1 | no (bch-spec) | 2.23 | 1.49 | 44.8 | 22.4 | 20.2 | 20.2 | 20.2 | 20.2 | 20.2 |
| T2 rolled minop: gamma/delta lines computed on-chain (projective) | 8189 (7919-8639) | 189.3 (187.3-193.5) | 214.9 | 1 | yes | 29.10 | 13.08 | 236.6 | 118.3 | 47.3 | 23.6 | 9.4 | 8.2 | 8.2 |
| T2+outline (recompiler pass) | 7089 (6506-8016) | 195.0 (189.1-202.2) | 220.5 | 1 | yes | 34.67 | 14.35 | 243.7 | 121.8 | 48.7 | 24.3 | 9.7 | 7.1 | 7.1 |
| R reduced-tower residue singleton | 5282 (5014-5657) | 412.2 (405.7-420.8) | 475.2 | 1 | yes | 98.60 | 33.93 | 515.1 | 257.6 | 103.0 | 51.5 | 20.6 | 10.3 | 5.3 |
| native + on-chain projective delta + projective B (multi-input, bch-2026 sizes) | 21155 (21035-21335) | 40.2 (36.6-44.6) | 40.2 | 4 | yes | 2.40 | 0.83 | 50.1 | 25.0 | 21.2 | 21.2 | 21.2 | 21.2 | 21.2 |
| rolled minop with baked lines as data (hint-heavy F12) | 48461 (48191-48911) | 149.9 (147.8-154.1) | 175.4 | 1 | no (bch-spec) | 3.87 | 3.21 | 187.4 | 93.7 | 48.5 | 48.5 | 48.5 | 48.5 | 48.5 |

#### T1 SI-GLS + on-chain projective delta walk + all-projective B: component rows (op M, code B, hint B)

| row | op M | code B | hint B |
|---|--:|--:|--:|
| measured base (BLS12-381 single) | 26.071 | 26484 | 0 |
| delta: drop baked slope pile | -5.611 | -6769 | 0 |
| delta: projective walk on-chain (B kernel reused) | 15.422 | 300 | 0 |
| delta: projective delta lines raise max chunk degree (+~3 quotient words) | 0.027 | 144 | 0 |
| B walk: all projective (drop witnessed affine slopes) | 1.347 | -250 | -1248 |

#### T2 rolled minop: gamma/delta lines computed on-chain (projective): component rows (op M, code B, hint B)

| row | op M | code B | hint B |
|---|--:|--:|--:|
| input checks | 0.207 | 304 | 0 |
| fused endpoint G2 check | 0.147 | 239 | 0 |
| vk_x glv_jac | 3.607 | 1961 | 56 |
| Fp12 squarings x64 | 27.085 | 0 | 0 |
| pair B: 69 lines | 30.774 | 0 | 0 |
| pair B: projective walk | 19.5 | 0 | 0 |
| pair gamma: 69 lines | 30.774 | 0 | 0 |
| pair gamma: projective walk | 19.5 | 0 | 0 |
| pair delta: 69 lines | 30.774 | 0 | 0 |
| pair delta: projective walk | 19.5 | 0 | 0 |
| projective G2 kernels | 0 | 0 | 0 |
| tower kernels (sqr, helpers, torus mul) | 0 | 2583 | 0 |
| baked e(alpha,beta) constant | 0.42 | 300 | 0 |
| VK G2 constants (gamma, delta walk starts) | 0 | 384 | 0 |
| residue c-folds | 2.494 | 0 | 0 |
| residue terminal | 0.366 | 654 | 294 |
| rolled loop | 4.14 | 900 | 0 |
| cleanup | 0.05 | 10 | 0 |

