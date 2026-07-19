#!/bin/sh
# Cage entrypoint. Order matters:
#   1. bring the VPN up (needs open egress to reach the VPN server),
#   2. resolve the authorised vhosts ONCE (scope-time pin, never at runtime),
#   3. lock egress to scope with nftables (kernel-enforced default-drop),
#   4. idle so the executor can `docker exec` approved commands in.
#
# The nftables lock is the STRUCTURAL guarantee behind the paper's claim: even a
# command that slips past the Python text-gate cannot send a packet to a host
# outside scope, because the kernel drops it. Fail-closed: a missing/unparseable
# scope installs a drop-all ruleset and the container exits non-zero, so the cage
# never comes up "open". Set BRUKAL_EGRESS_LOCK=0 only on a kernel without
# nftables support (you then lose the structural guarantee — software gate only).
set -e

SCOPE_FILE="${BRUKAL_SCOPE:-/scope.json}"
LOCKDOWN="${BRUKAL_EGRESS_LOCK:-1}"
# DNS resolver to permit (only this one) — defaults to the container's configured
# nameserver (Docker's embedded DNS, usually 127.0.0.11). Lookups work; arbitrary
# DNS-tunnel egress to any other resolver is dropped.
RESOLVER="${BRUKAL_DNS:-$(awk '/^nameserver/{print $2; exit}' /etc/resolv.conf 2>/dev/null)}"
RESOLVER="${RESOLVER:-127.0.0.11}"

_family() {   # echo "ip" or "ip6" for an address/CIDR
    case "$1" in *:*) echo ip6 ;; *) echo ip ;; esac
}

lock_drop_all() {
    # Fail-closed ruleset: drop ALL egress except loopback.
    nft flush ruleset 2>/dev/null || true
    nft -f - <<'NFT'
table inet brukal {
  chain output {
    type filter hook output priority 0; policy drop;
    oif "lo" accept
    log prefix "brukal-egress-drop " counter drop
  }
}
NFT
}

apply_egress_lock() {
    if ! command -v nft >/dev/null 2>&1; then
        echo "[cage] FATAL: nftables (nft) not installed."; return 1
    fi
    if [ ! -f "$SCOPE_FILE" ]; then
        echo "[cage] FATAL: scope file $SCOPE_FILE not found — installing drop-all egress."
        lock_drop_all; return 1
    fi

    # Extract authorised CIDRs + hosts with python3 (present in the image). Emits
    # shell-safe assignments, or ERROR= on a malformed policy.
    PARSED="$(python3 - "$SCOPE_FILE" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    cidrs = [str(c).strip() for c in d.get("authorized_cidrs", []) if str(c).strip()]
    hosts = [str(h).strip() for h in d.get("authorized_hosts", []) if str(h).strip()]
    # basic sanity: allow only chars we expect in CIDRs / hostnames
    ok = lambda s, extra: all(c.isalnum() or c in extra for c in s)
    if not all(ok(c, ".:/") for c in cidrs) or not all(ok(h, ".-") for h in hosts):
        raise ValueError("unexpected characters in scope")
    print("CIDRS='" + " ".join(cidrs) + "'")
    print("HOSTS='" + " ".join(hosts) + "'")
except Exception as e:
    print("ERROR='" + str(e).replace("'", "") + "'")
PY
)"
    case "$PARSED" in
        *ERROR=*) echo "[cage] FATAL: scope unparseable: $PARSED"; lock_drop_all; return 1 ;;
    esac
    eval "$PARSED"

    # Resolve each authorised vhost ONCE, now, while egress is still open — pin the
    # result as a /32 (or /128) allow rule. This is scope-TIME resolution: a hostile
    # DNS answer later cannot widen the pinned set (the ruleset is fixed until the
    # cage is restarted). Matches Brukal's "resolve at scope-time, never at runtime".
    PINNED=""
    for h in $HOSTS; do
        got=""
        for ip in $(getent ahosts "$h" 2>/dev/null | awk '{print $1}' | sort -u); do
            PINNED="$PINNED $ip"; got="$got $ip"
        done
        if [ -n "$got" ]; then
            echo "[cage] pinned vhost $h ->$got"
        else
            echo "[cage] WARNING: could not resolve vhost $h (no pin added)."
        fi
    done

    # Build the ruleset. Default-drop output; allow loopback, established flows, DNS
    # to the one resolver, the authorised CIDRs, and the pinned host IPs; log+drop
    # the rest.
    rf="$(_family "$RESOLVER")"
    RULES="table inet brukal {
  chain output {
    type filter hook output priority 0; policy drop;
    oif \"lo\" accept
    ct state established,related accept
    $rf daddr $RESOLVER udp dport 53 accept
    $rf daddr $RESOLVER tcp dport 53 accept
"
    for cidr in $CIDRS; do
        RULES="$RULES    $(_family "$cidr") daddr $cidr accept
"
    done
    for ip in $PINNED; do
        RULES="$RULES    $(_family "$ip") daddr $ip accept
"
    done
    RULES="$RULES    log prefix \"brukal-egress-drop \" counter drop
  }
}
"
    nft flush ruleset 2>/dev/null || true
    printf '%s' "$RULES" | nft -f -
    echo "[cage] egress locked to scope. Ruleset:"
    nft list ruleset
}

# --- 1. VPN (open egress needed to reach the VPN server) ---------------------
CFG="${VPN_CONFIG:-/vpn/config.ovpn}"
if [ -f "$CFG" ]; then
    echo "[cage] starting OpenVPN from $CFG ..."
    openvpn --config "$CFG" --daemon --log /var/log/openvpn.log
    i=0
    while [ "$i" -lt 30 ]; do
        if ip addr show tun0 >/dev/null 2>&1; then
            echo "[cage] VPN up (tun0):"; ip -brief addr show tun0; break
        fi
        i=$((i + 1)); sleep 1
    done
    ip addr show tun0 >/dev/null 2>&1 || \
        echo "[cage] WARNING: tun0 not up — see /var/log/openvpn.log"
else
    echo "[cage] no VPN config at $CFG — local mode (drop an .ovpn in docker/vpn/config.ovpn for HTB)."
fi

# --- 2+3. Egress lock (fail-closed) -----------------------------------------
if [ "$LOCKDOWN" = "1" ]; then
    if ! apply_egress_lock; then
        echo "[cage] FATAL: could not apply the scope egress lock — refusing to run open."
        echo "[cage] (on a kernel without nftables support, set BRUKAL_EGRESS_LOCK=0 to run"
        echo "[cage]  software-gate-only; you then lose the kernel-enforced scope guarantee.)"
        exit 1
    fi
else
    echo "[cage] WARNING: BRUKAL_EGRESS_LOCK=0 — egress NOT locked (software gate only)."
fi

# --- 4. Idle so the executor can exec approved commands in -------------------
exec sleep infinity
