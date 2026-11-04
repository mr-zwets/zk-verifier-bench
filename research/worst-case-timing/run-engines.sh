#!/usr/bin/env bash
# Raised-limit timing on the two engines that can run them: bchd-fork's opcostbench (Go, BCH 2026 VM with raisable
# limits; branch wip/worst-case-timing adds the txv5-100k/150k[+num] modes, patch in bchd-raised-modes.patch) and libauth
# (libauth-time.ts). Steady state (no forced GC), 7 batches of >= 300 ms; every evaluation's verdict and op-cost are
# checked against the unit (libauth consensus op-cost). One job at a time, nice 19, one pinned core each.
#   run-engines.sh NAME CPU      (UNITS dir = generated units-*.json)
set -euo pipefail
NAME=${1:?name}; CPU=${2:-9}
HERE=$(cd "$(dirname "$0")" && pwd); BENCH=$(cd "$HERE/../.." && pwd)
UNITS=${UNITS:-/home/mrzwets/BCH-projects/verifier.cash/work/worst-case-timing/data}
BCHD=${BCHD:-/home/mrzwets/BCH-projects/verifier.cash/work/worst-case-timing/bchd}
OUT=$HERE/raw; mkdir -p "$OUT"
FILES=(units-today.json units-txv5-100k.json units-txv5-150k.json units-txv5-100k-num.json units-txv5-150k-num.json)
{
  echo "date: $(date -Is)"; echo "host: $(uname -srm)"; lscpu | grep -E "Model name"
  echo "governor(cpu$CPU): $(cat /sys/devices/system/cpu/cpu$CPU/cpufreq/scaling_governor) epp: $(cat /sys/devices/system/cpu/cpu$CPU/cpufreq/energy_performance_preference 2>/dev/null)"
  echo "bchd-fork: $(git -C "$BCHD" rev-parse --short HEAD) $(git -C "$BCHD" status --short | wc -l) uncommitted; $(go version)"
  echo "node: $(node --version); libauth: $(node -p "require('$BENCH/node_modules/@bitauth/libauth/package.json').version")"
  echo "cpu: $CPU"; echo "unit files:"; for f in "${FILES[@]}"; do echo "  $(sha256sum "$UNITS/$f" | cut -c1-16) $f"; done
  echo "loadavg start: $(cat /proc/loadavg)"
} > "$OUT/$NAME-env.txt"
for f in "${FILES[@]}"; do
  b=${f%.json}
  GOMAXPROCS=1 nice -n 19 taskset -c "$CPU" "$BCHD/opcostbench" -in "$UNITS/$f" -out "$OUT/$NAME-bchd-$b.json" -steady 2> "$OUT/$NAME-bchd-$b.log" || echo "bchd $f failed" >> "$OUT/$NAME-env.txt"
  echo "loadavg after bchd $f: $(cat /proc/loadavg)" >> "$OUT/$NAME-env.txt"
done
cd "$BENCH"
for f in "${FILES[@]}"; do
  b=${f%.json}
  nice -n 19 taskset -c "$CPU" node --max-old-space-size=4096 --import tsx "$HERE/libauth-time.ts" "$UNITS/$f" "$OUT/$NAME-libauth-$b.json" 2> "$OUT/$NAME-libauth-$b.log" || echo "libauth $f failed" >> "$OUT/$NAME-env.txt"
  echo "loadavg after libauth $f: $(cat /proc/loadavg)" >> "$OUT/$NAME-env.txt"
done
echo "loadavg end: $(cat /proc/loadavg)" >> "$OUT/$NAME-env.txt"
