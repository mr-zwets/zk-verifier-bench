#!/bin/bash
# LIMITS-TABLE: Track 10 G2 layout a' over the limits grid, one job at a time, nice 19
set -u
cd "$(dirname "$0")/research/pq-wrap/onchain"
V=/home/mrzwets/BCH-projects/verifier.cash/work/t10-gates/cache/g2/vec0/tw2x18x16-g2-0-Z128_lb5_lf8_q43_bpow20_cpow11_cap0.json
OUT=../../../out
for OPTSET in opt base; do
  for U in 10000 100000 150000; do
    for X in 100000 200000 400000 1000000; do
      tag="g2-$OPTSET-u$U-t$X"
      [ -s "$OUT/$tag.json" ] && continue
      if [ $OPTSET = opt ]; then O=(--opt sib,lad,state,cap=3); else O=(); fi
      echo "== $tag $(date +%T)"
      LIMITS_UNL=$U UV_THREADPOOL_SIZE=2 nice -n 19 node grade-lim.mjs --nc 3 "${O[@]}" --unl $U --tx $X --pers 3,2,1 --out $OUT/$tag.json $V > $OUT/$tag.log 2>&1
      head -1 $OUT/$tag.log | cut -c1-260
    done
  done
done
echo DONE
