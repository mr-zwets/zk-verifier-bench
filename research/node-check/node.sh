#!/usr/bin/env bash
# node-check copy of research/opcost-timing/bchn/node.sh (BCHN v29.1.0 regtest, stock binaries), plus POLICY=1:
# acceptnonstdtxn=0 (default relay policy otherwise) for the testmempoolaccept policy mode. Usage:
#   node.sh start [NAME] [CPU]   start fresh node (datadir $OPCOST_DIR/bchn-NAME), pinned to CPU
#   node.sh stop  [NAME]
#   node.sh cli   [NAME] <rpc args...>
# Ports are derived from NAME so several rigs can coexist; nothing touches ~/BCH-infra/regtest.
set -euo pipefail
BIN=${BCHN_BIN:-$HOME/BCH-infra/bitcoin-cash-node-29.1.0/bin}
OPCOST_DIR=${OPCOST_DIR:-/home/mrzwets/BCH-projects/verifier.cash/work/node-check}
cmd=${1:?start|stop|cli}; NAME=${2:-a}; shift 2 || true
DATA=$OPCOST_DIR/bchn-$NAME
off=$(( $(printf '%s' "$NAME" | cksum | cut -d' ' -f1) % 500 ))
RPCPORT=$((39300 + off*2)); P2PPORT=$((RPCPORT + 1))
CLI=("$BIN/bitcoin-cli" -regtest -datadir="$DATA" -rpcport=$RPCPORT)
case $cmd in
  start)
    CPU=${1:-9}
    ACCEPTNONSTD=1; if [ "${POLICY:-0}" = 1 ]; then ACCEPTNONSTD=0; fi
    if [ -e "$DATA" ]; then echo "datadir $DATA exists; remove it for a fresh run" >&2; exit 1; fi
    mkdir -p "$DATA"
    cat > "$DATA/bitcoin.conf" <<CONF
regtest=1
[regtest]
rpcport=$RPCPORT
port=$P2PPORT
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
listen=0
dnsseed=0
connect=0
disablewallet=1
server=1
upgrade12activationheight=0
acceptnonstdtxn=$ACCEPTNONSTD
maxscriptcachesize=0
maxsigcachesize=0
par=1
debug=bench
logtimemicros=1
printtoconsole=0
persistmempool=0
rpcworkqueue=64
rpcservertimeout=3600
CONF
    # optional extra settings, e.g. EXTRA_CONF='minrelaytxfee=0' so testmempoolaccept reaches script checks
    if [ -n "${EXTRA_CONF:-}" ]; then printf '%s\n' $EXTRA_CONF >> "$DATA/bitcoin.conf"; fi
    taskset -c "$CPU" "$BIN/bitcoind" -datadir="$DATA" -daemon
    for i in $(seq 1 100); do "${CLI[@]}" getblockcount >/dev/null 2>&1 && break; sleep 0.2; done
    echo "{\"datadir\":\"$DATA\",\"rpcport\":$RPCPORT,\"cpu\":\"$CPU\",\"pid\":$(cat "$DATA/regtest/bitcoind.pid")}"
    ;;
  stop) "${CLI[@]}" stop; ;;
  cli) "${CLI[@]}" "$@"; ;;
  *) echo "unknown $cmd" >&2; exit 2;;
esac
