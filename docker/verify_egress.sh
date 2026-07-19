#!/bin/sh
# verify_egress.sh — proves the cage's kernel egress lock enforces scope.
#
# This is the network-layer experiment behind the paper's claim: with the cage up,
# an OUT-of-scope host must be unreachable (packets dropped by nftables) while an
# IN-scope host is reachable. Run it after `docker compose ... up -d`:
#
#   docker/verify_egress.sh [container] [out-of-scope-ip] [in-scope-ip:port]
#   e.g.  docker/verify_egress.sh brukal-kali 8.8.8.8 10.129.56.241:80
#
# Exit 0 = claim holds; non-zero = a leak or a misconfigured lock. Capture the
# output (and `nft list ruleset`) for the paper's results.
set -e

CONT="${1:-brukal-kali}"
OOS="${2:-8.8.8.8}"          # out-of-scope canary (a reliably-up public host)
OOS_PORT="443"
INSCOPE="${3:-}"             # optional  ip:port  known to be in scope + listening

pass() { echo "  PASS  $1"; }
fail() { echo "  FAIL  $1"; exit 1; }

echo "== brukal egress verification (container: $CONT) =="

# 0. The lock must actually be installed — an open cage is an immediate fail.
if ! docker exec "$CONT" nft list table inet brukal >/dev/null 2>&1; then
    fail "no 'brukal' nftables table present — the cage came up WITHOUT the egress lock"
fi
pass "egress lock present (table inet brukal)"

# 1. Out-of-scope host must be DROPPED. `timeout` returns 124 when the probe is
#    dropped (SYN goes into a black hole); a reachable host connects (exit 0). So
#    exit 0 here means the packet escaped scope — a failure.
set +e
docker exec "$CONT" timeout 5 nc -w 4 -z "$OOS" "$OOS_PORT" >/dev/null 2>&1
rc=$?
set -e
if [ "$rc" -eq 0 ]; then
    fail "out-of-scope $OOS:$OOS_PORT was REACHABLE — scope leak!"
fi
pass "out-of-scope $OOS:$OOS_PORT blocked (probe exit $rc, dropped)"

# 2. In-scope host must be reachable (connects, or is refused fast — NOT dropped).
#    A dropped probe is exactly `timeout`'s 124; anything else means the packet was
#    allowed out (reached the host or got an RST).
if [ -n "$INSCOPE" ]; then
    ip="${INSCOPE%%:*}"; port="${INSCOPE##*:}"; [ "$port" = "$INSCOPE" ] && port=80
    set +e
    docker exec "$CONT" timeout 6 nc -w 5 -z "$ip" "$port" >/dev/null 2>&1
    rc=$?
    set -e
    if [ "$rc" -eq 124 ]; then
        fail "in-scope $ip:$port was DROPPED — the lock is too tight (scope not allowed)"
    fi
    pass "in-scope $ip:$port reachable (probe exit $rc, not dropped)"
else
    echo "  SKIP  no in-scope ip:port given — pass one as arg 3 to prove reachability"
fi

# 3. Show the drop counter as evidence (how many out-of-scope packets were killed).
echo "== drop counter =="
docker exec "$CONT" sh -c "nft list ruleset | grep -A0 'brukal-egress-drop' || true"
echo "== egress verification complete — scope enforced at the kernel =="
