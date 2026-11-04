#!/usr/bin/env bash
# Worst-case kernels on stock BCHN 29.1.0 (regtest, localhost only) via the node-check harness (node.sh) and Track 1's
# rig (rig-run.ts): a fresh timing node (block validation, BCHN's "Verify N txins" bench line, 11 reps) and a fresh
# POLICY=1 node (acceptnonstdtxn=0, testmempoolaccept) for the kernels meant to be standard. Both nodes are stopped.
#   run-bchn.sh NAME NODE_CPU DRIVER_CPU REPS      (DATA = generated nc-*.json, see gen.ts)
set -euo pipefail
NAME=${1:?name}; NODE_CPU=${2:-9}; DRV_CPU=${3:-7}; REPS=${4:-11}
HERE=$(cd "$(dirname "$0")" && pwd); BENCH=$(cd "$HERE/../.." && pwd); NC=$BENCH/research/node-check
export OPCOST_DIR=${OPCOST_DIR:-/home/mrzwets/BCH-projects/verifier.cash/work/worst-case-timing}
DATA=${DATA:-$OPCOST_DIR/data}; OUT=$HERE/raw; mkdir -p "$OUT"
VMB=${VMB_DIR:-/home/mrzwets/BCH-projects/verifier.cash/work/opcost-timing/ext/vmb_tests}
# references from the VM-limits benchmark vectors (Track 1): trxhzt baseline, l0fhm3 (packed 1-of-3 bare multisig, the
# CHIP's worst case), ap38fd (max OP_ROLL), w57j6w (OP_RIPEMD160 of 10,000 B, nonstandard)
REFS=(--src "vmb:$VMB/bch_2026_standard/core.benchmarks.baseline.vmb_tests.json@accept" --src "vmb:$VMB/bch_2026_standard/core.benchmarks.signature-checking.bms-ecdsa.vmb_tests.json@accept"
      --src "vmb:$VMB/bch_2026_standard/core.benchmarks.roll.vmb_tests.json@accept" --src "vmb:$VMB/bch_2026_nonstandard/core.benchmarks.hashing.vmb_tests.json@accept")
FILTER=${FILTER:-'@|^(trxhzt|l0fhm3|ap38fd|w57j6w)$'}
TIMING=(--src "json:$DATA/rig-today-std.json" --src "json:$DATA/rig-today-cons.json" --src "json:$DATA/rig-today-tx-std.json" --src "json:$DATA/rig-today-tx-cons.json" --src "json:$DATA/rig-today-sweep.json" "${REFS[@]}")
POLICY=(--src "json:$DATA/rig-today-std.json" --src "json:$DATA/rig-today-tx-std.json" --src "json:$DATA/rig-today-cons.json")
{
  echo "date: $(date -Is)"; echo "host: $(uname -srm)"; lscpu | grep -E "Model name"
  echo "governor(cpu$NODE_CPU): $(cat /sys/devices/system/cpu/cpu$NODE_CPU/cpufreq/scaling_governor) epp: $(cat /sys/devices/system/cpu/cpu$NODE_CPU/cpufreq/energy_performance_preference 2>/dev/null)"
  echo "bchn: $($HOME/BCH-infra/bitcoin-cash-node-29.1.0/bin/bitcoind -version | head -1)"
  echo "bench: $(git -C "$BENCH" rev-parse --short HEAD)  node cpu: $NODE_CPU driver cpu: $DRV_CPU reps: $REPS"
  echo "workload files:"; for f in "$DATA"/rig-*.json; do echo "  $(sha256sum "$f" | cut -c1-16) $(basename "$f")"; done
  echo "loadavg start: $(cat /proc/loadavg)"
} > "$OUT/$NAME-env.txt"
cd "$BENCH"
nice -n 19 "$NC/node.sh" start "$NAME-t" "$NODE_CPU" >> "$OUT/$NAME-env.txt"
nice -n 19 taskset -c "$DRV_CPU" npx tsx "$HERE/rig-run.ts" timing --node "$NAME-t" "${TIMING[@]}" --filter "$FILTER" --reps "$REPS" --out "$OUT/$NAME-timing.jsonl" 2> "$OUT/$NAME-timing.log" || echo "timing driver failed" >> "$OUT/$NAME-env.txt"
"$NC/node.sh" stop "$NAME-t" >> "$OUT/$NAME-env.txt" || true
echo "loadavg after timing: $(cat /proc/loadavg)" >> "$OUT/$NAME-env.txt"
if [ "${SKIP_POLICY:-0}" != 1 ]; then
  POLICY=1 nice -n 19 "$NC/node.sh" start "$NAME-p" "$NODE_CPU" >> "$OUT/$NAME-env.txt"
  nice -n 19 taskset -c "$DRV_CPU" npx tsx "$HERE/rig-run.ts" policy --node "$NAME-p" "${POLICY[@]}" --out "$OUT/$NAME-policy.jsonl" 2> "$OUT/$NAME-policy.log" || echo "policy driver failed" >> "$OUT/$NAME-env.txt"
  "$NC/node.sh" stop "$NAME-p" >> "$OUT/$NAME-env.txt" || true
fi
echo "loadavg end: $(cat /proc/loadavg)" >> "$OUT/$NAME-env.txt"
