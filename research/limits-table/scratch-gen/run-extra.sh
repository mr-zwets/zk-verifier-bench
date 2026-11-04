#!/bin/bash
set -u
cd "$(dirname "$0")/research/pq-wrap/onchain"
C=/home/mrzwets/BCH-projects/verifier.cash/work/t10-gates/cache/g2/vec0
V0=$C/tw2x18x16-g2-0-Z128_lb5_lf8_q43_bpow20_cpow11_cap0.json; V1=$C/tw2x18x16-g2-1-Z128_lb5_lf8_q43_bpow20_cpow11_cap0.json
OUT=../../../out; O=(--nc 3 --opt sib,lad,state,cap=3)
run() { tag=$1; U=$2; shift 2; echo "== $tag $(date +%T)"; LIMITS_UNL=$U nice -n 19 node grade-lim.mjs "$@" --out $OUT/$tag.json > $OUT/$tag.log 2>&1; head -1 $OUT/$tag.log | cut -c55-250; }
run g2-opt-u10000-t100000 10000 "${O[@]}" --unl 10000 --tx 100000 --pers 3,2,1 $V0
run x-g2-opt-u10000-t293514 10000 "${O[@]}" --unl 10000 --tx 293514 --pers 3,2,1 $V0
run x-g2-opt-u10000-t293513 10000 "${O[@]}" --unl 10000 --tx 293513 --pers 3,2,1 $V0
run x-g2-opt-u10000-t300000 10000 "${O[@]}" --unl 10000 --tx 300000 --pers 3,2,1 $V0
run x-g2-opt-u100000-t400000-per4 100000 "${O[@]}" --unl 100000 --tx 400000 --per 4 $V0
run x-g2-opt-u10000-t400000-vec1 10000 "${O[@]}" --unl 10000 --tx 400000 --pers 3,2,1 $V1
run x-g2-opt-u10000-t100000-vec1 10000 "${O[@]}" --unl 10000 --tx 100000 --pers 3,2,1 $V1
echo DONE
