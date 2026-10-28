#!/usr/bin/env python3
"""Effective size E_k = max(bytes, op/(800k) - 41*inputs) for today's reviewed entries
and the Track 2 research designs. Op-cost is libauth + executed OP_DEFINE body bytes
(BCHN-adjusted), committed proof; 'worst' is the bench worst-case proof vector.
Size caps (bch-2026 10,000 B per input) are ignored, as in the model."""
KS = [1, 2, 5, 10, 25, 50, 100]
D = {
 "BN254": {
  "today": [  # id, bytes, op (BCHN-adj, committed), inputs
   ("singleton-opcode-optimized", 6237, 800158630, 1),
   ("singleton", 8206, 771304255, 1),
   ("singleton-minop", 58073, 64844252, 1),
   ("sound-si-gls-single", 21915, 23338058, 1),
   ("bn254-sound-native", 27624, 20616435, 3),
  ],
  "new": [  # name, bytes, op, worst op, inputs
   ("T1 sigls-dproj", 16571, 33318543, 33334850, 1),
   ("T1 sigls-dproj inline", 17203, 32022832, 32039485, 1),
   ("T2 rolled-residue", 9776, 130303393, 139083823, 1),
   ("T2 rolled-residue mulc", 9116, 147419350, 156206071, 1),
  ],
 },
 "BLS12-381": {
  "today": [
   ("bls12381-singleton-opcode-optimized", 5999, 1003515113, 1),
   ("bls12381-singleton", 7510, 994592972, 1),
   ("bls12381-singleton-minop", 58841, 145599283, 1),
   ("bls12381-sound-si-gls-single", 26484, 26073214, 1),
   ("bls12381-sound-native", 34229, 24091590, 4),
  ],
  "new": [
   ("T1 sigls-dproj", 18892, 36897147, 37866341, 1),
   ("T2 minop-rolled", 8712, 192761316, 218291714, 1),
  ],
 },
}
def E(b, op, k, n): return max(b, op / (800 * k) - 41 * n)
for curve, d in D.items():
    print(f"\n{curve}")
    print("| k | today best | design | new best (committed) | design | worst-case proof | change |")
    for k in KS:
        tb, tn = min((E(b, o, k, n), i) for i, b, o, n in d["today"])
        nb, nn = min((E(b, o, k, n), i) for i, b, o, w, n in d["new"])
        nw = min(E(b, w, k, n) for i, b, o, w, n in d["new"])
        best = min(tb, nb)
        print(f"| {k} | {tb/1000:.1f} | {tn} | {nb/1000:.1f} | {nn} | {nw/1000:.1f} | {100*(nb-tb)/tb:+.0f}% |")
    for i, b, o, w, n in d["new"]:
        print(i, " ".join(f"{E(b,o,k,n)/1000:.1f}/{E(b,w,k,n)/1000:.1f}" for k in KS))
