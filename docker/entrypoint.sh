#!/bin/sh
# Bring up the VPN if an OpenVPN config is present, then idle so the executor can
# `docker exec` approved commands in. No config -> plain local mode.
set -e

CFG="${VPN_CONFIG:-/vpn/config.ovpn}"
if [ -f "$CFG" ]; then
    echo "[cage] starting OpenVPN from $CFG ..."
    openvpn --config "$CFG" --daemon --log /var/log/openvpn.log
    i=0
    while [ "$i" -lt 30 ]; do
        if ip addr show tun0 >/dev/null 2>&1; then
            echo "[cage] VPN up (tun0):"
            ip -brief addr show tun0
            break
        fi
        i=$((i + 1)); sleep 1
    done
    ip addr show tun0 >/dev/null 2>&1 || \
        echo "[cage] WARNING: tun0 not up — see /var/log/openvpn.log"
else
    echo "[cage] no VPN config at $CFG — local mode (drop an .ovpn in docker/vpn/config.ovpn for HTB)."
fi

exec sleep infinity
