#!/usr/bin/env bash
# node-check, Track 10 gate G2 (shape twin, layouts a' and b2; copy of run-t8.sh): three fresh nodes, each stopped at the end:
#   NAME-t  timing node (acceptnonstdtxn=1): block validation of every workload (valid + reject sample), Verify ms
#   NAME-p  policy node (POLICY=1, acceptnonstdtxn=0): testmempoolaccept of every valid tx (2tx: tx1 spends mined tx0)
#   NAME-m  policy node: mempool mode, the a' chains sent with tx0 unconfirmed
#   run-g2.sh NAME NODE_CPU DRIVER_CPU REPS   (DATA=<dir of export-g2.mjs outputs>)
set -euo pipefail
NAME=${1:?name}; NODE_CPU=${2:-9}; DRV_CPU=${3:-7}; REPS=${4:-11}
HERE=$(cd "$(dirname "$0")" && pwd); BENCH=$(cd "$HERE/../.." && pwd)
export OPCOST_DIR=${OPCOST_DIR:-/home/mrzwets/BCH-projects/verifier.cash/work/t10-gates/cache/node}
DATA=${DATA:-$OPCOST_DIR/data/g2}
G16=${G16:-/home/mrzwets/BCH-projects/verifier.cash/work/t10-gates/code}
OUT=$HERE/raw; mkdir -p "$OUT"
SRCS=(); for f in $(ls "$DATA"/g2-*.json | sort -V); do SRCS+=(--src "json:$f"); done
SRCS2=(); for f in $(ls "$DATA"/g2-*.json | sort -V); do SRCS2+=(--src "json:$f"); done
{
  echo "date: $(date -Is)"; echo "host: $(uname -srm)"
  lscpu | grep -E "Model name"
  echo "governor(cpu$NODE_CPU): $(cat /sys/devices/system/cpu/cpu$NODE_CPU/cpufreq/scaling_governor) epp: $(cat /sys/devices/system/cpu/cpu$NODE_CPU/cpufreq/energy_performance_preference 2>/dev/null)"
  echo "bchn: $($HOME/BCH-infra/bitcoin-cash-node-29.1.0/bin/bitcoind -version | head -1)"
  echo "bench: $(git -C "$BENCH" rev-parse --short HEAD)  groth16_cashscript: $(git -C "$G16" rev-parse --short HEAD)"
  echo "node cpu: $NODE_CPU driver cpu: $DRV_CPU reps: $REPS"
  echo "workload files:"; for f in $(ls "$DATA"/g2-*.json | sort -V); do echo "  $(sha256sum "$f" | cut -c1-16) $(basename "$f")"; done
  echo "loadavg start: $(cat /proc/loadavg)"
} > "$OUT/$NAME-env.txt"
cd "$BENCH"
export BENCH_DIR="$BENCH" GOMAXPROCS=4
"$HERE/node.sh" start "$NAME-t" "$NODE_CPU" >> "$OUT/$NAME-env.txt"
nice -n 5 taskset -c "$DRV_CPU" npx tsx "$HERE/nc.ts" timing --node "$NAME-t" "${SRCS[@]}" --reps "$REPS" --out "$OUT/$NAME-timing.jsonl" 2> "$OUT/$NAME-timing.log" || echo "timing driver failed" >> "$OUT/$NAME-env.txt"
"$HERE/node.sh" stop "$NAME-t" >> "$OUT/$NAME-env.txt" || true
echo "loadavg after timing: $(cat /proc/loadavg)" >> "$OUT/$NAME-env.txt"
POLICY=1 "$HERE/node.sh" start "$NAME-p" "$NODE_CPU" >> "$OUT/$NAME-env.txt"
nice -n 5 taskset -c "$DRV_CPU" npx tsx "$HERE/nc.ts" policy --node "$NAME-p" "${SRCS[@]}" --out "$OUT/$NAME-policy.jsonl" 2> "$OUT/$NAME-policy.log" || echo "policy driver failed" >> "$OUT/$NAME-env.txt"
"$HERE/node.sh" stop "$NAME-p" >> "$OUT/$NAME-env.txt" || true
POLICY=1 "$HERE/node.sh" start "$NAME-m" "$NODE_CPU" >> "$OUT/$NAME-env.txt"
nice -n 5 taskset -c "$DRV_CPU" npx tsx "$HERE/nc.ts" mempool --node "$NAME-m" "${SRCS2[@]}" --out "$OUT/$NAME-mempool.jsonl" 2> "$OUT/$NAME-mempool.log" || echo "mempool driver failed" >> "$OUT/$NAME-env.txt"
"$HERE/node.sh" stop "$NAME-m" >> "$OUT/$NAME-env.txt" || true
echo "loadavg end: $(cat /proc/loadavg)" >> "$OUT/$NAME-env.txt"
