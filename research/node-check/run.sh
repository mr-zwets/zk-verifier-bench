#!/usr/bin/env bash
# node-check full run: a fresh timing node (acceptnonstdtxn=1, block validation, Verify timing) and a fresh policy node
# (acceptnonstdtxn=0, testmempoolaccept), each stopped at the end.
#   run.sh NAME NODE_CPU DRIVER_CPU REPS     (writes research/node-check/raw/NAME-{timing,policy}.jsonl, env, logs)
set -euo pipefail
NAME=${1:?name}; NODE_CPU=${2:-9}; DRV_CPU=${3:-7}; REPS=${4:-11}
HERE=$(cd "$(dirname "$0")" && pwd); BENCH=$(cd "$HERE/../.." && pwd)
export OPCOST_DIR=${OPCOST_DIR:-/home/mrzwets/BCH-projects/verifier.cash/work/node-check}
DATA=${DATA:-$OPCOST_DIR/data}
OUT=$HERE/raw; mkdir -p "$OUT"
SRCS=()
for c in mul2 merkle16 range64 merkle16rc; do SRCS+=(--src "json:$DATA/plonk-$c.json"); done
for v in mimc-S128-0 mimc-S100b-0 fib-S100z-zkmin-0 fib-S128z-zkmin-0; do SRCS+=(--src "json:$DATA/stark-$v.json"); done
SRCS+=(--src builtin:sound-native)
{
  echo "date: $(date -Is)"; echo "host: $(uname -srm)"
  lscpu | grep -E "Model name"
  echo "governor(cpu$NODE_CPU): $(cat /sys/devices/system/cpu/cpu$NODE_CPU/cpufreq/scaling_governor) epp: $(cat /sys/devices/system/cpu/cpu$NODE_CPU/cpufreq/energy_performance_preference 2>/dev/null)"
  echo "bchn: $($HOME/BCH-infra/bitcoin-cash-node-29.1.0/bin/bitcoind -version | head -1)"
  echo "bench: $(git -C "$BENCH" rev-parse --short HEAD)  groth16_cashscript: $(git -C /home/mrzwets/BCH-projects/verifier.cash/work/node-check/g16 rev-parse --short HEAD)"
  echo "node cpu: $NODE_CPU driver cpu: $DRV_CPU reps: $REPS"
  echo "workload files:"; for f in "$DATA"/plonk-*.json "$DATA"/stark-*.json; do echo "  $(sha256sum "$f" | cut -c1-16) $(basename "$f")"; done
  echo "loadavg start: $(cat /proc/loadavg)"
} > "$OUT/$NAME-env.txt"
cd "$BENCH"
export BENCH_DIR="$BENCH" GOMAXPROCS=4
"$HERE/node.sh" start "$NAME-t" "$NODE_CPU" >> "$OUT/$NAME-env.txt"
nice -n 5 taskset -c "$DRV_CPU" npx tsx "$HERE/nc.ts" timing --node "$NAME-t" "${SRCS[@]}" --reps "$REPS" --out "$OUT/$NAME-timing.jsonl" 2> "$OUT/$NAME-timing.log" || echo "timing driver failed" >> "$OUT/$NAME-env.txt"
"$HERE/node.sh" stop "$NAME-t" >> "$OUT/$NAME-env.txt" || true
POLICY=1 "$HERE/node.sh" start "$NAME-p" "$NODE_CPU" >> "$OUT/$NAME-env.txt"
nice -n 5 taskset -c "$DRV_CPU" npx tsx "$HERE/nc.ts" policy --node "$NAME-p" "${SRCS[@]}" --out "$OUT/$NAME-policy.jsonl" 2> "$OUT/$NAME-policy.log" || echo "policy driver failed" >> "$OUT/$NAME-env.txt"
"$HERE/node.sh" stop "$NAME-p" >> "$OUT/$NAME-env.txt" || true
echo "loadavg end: $(cat /proc/loadavg)" >> "$OUT/$NAME-env.txt"
