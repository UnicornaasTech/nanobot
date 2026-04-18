#!/bin/bash
set -euo pipefail  # Exit on error, undefined vars, and pipeline failures
IFS=$'\n\t'       # Stricter word splitting

# 1. Extract Docker DNS info BEFORE any flushing
DOCKER_DNS_RULES=$(iptables-save -t nat | grep "127\.0\.0\.11" || true)

# Flush existing rules and delete existing ipsets (legacy allowlist)
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
ipset destroy allowed-domains 2>/dev/null || true

# IPv6: lock down completely. We only authorize IPv4 traffic, so any IPv6
# path would otherwise be an unintended bypass.
if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -F
    ip6tables -X
    ip6tables -t mangle -F 2>/dev/null || true
    ip6tables -t mangle -X 2>/dev/null || true
    ip6tables -t nat -F 2>/dev/null || true
    ip6tables -t nat -X 2>/dev/null || true
    ip6tables -P INPUT DROP
    ip6tables -P FORWARD DROP
    ip6tables -P OUTPUT DROP
    ip6tables -A INPUT -i lo -j ACCEPT
    ip6tables -A OUTPUT -o lo -j ACCEPT
    echo "IPv6 locked down (loopback only)"
else
    echo "ip6tables not available; skipping (IPv6 must be disabled in the kernel/container)"
fi

# 2. Selectively restore ONLY internal Docker DNS resolution
if [ -n "$DOCKER_DNS_RULES" ]; then
    echo "Restoring Docker DNS rules..."
    iptables -t nat -N DOCKER_OUTPUT 2>/dev/null || true
    iptables -t nat -N DOCKER_POSTROUTING 2>/dev/null || true
    echo "$DOCKER_DNS_RULES" | xargs -L 1 iptables -t nat
else
    echo "No Docker DNS rules to restore"
fi

# Resolve host.docker.internal via nsswitch (no `dig` dependency).
# The HDI rules are the only thing constraining access to the host on the
# bridge network, so a resolution failure must be fatal -- otherwise the
# container would silently lose its sole guard against reaching the host.
HOST_DOCKER_INTERNAL_IP=$(getent hosts host.docker.internal | awk '{print $1}' | head -n 1 || true)
if [ -z "$HOST_DOCKER_INTERNAL_IP" ]; then
    echo "ERROR: host.docker.internal did not resolve. On Linux, add" >&2
    echo "       extra_hosts: [\"host.docker.internal:host-gateway\"] in compose." >&2
    exit 1
fi
echo "host.docker.internal -> $HOST_DOCKER_INTERNAL_IP (only TCP 8801-8810; all other traffic to that address blocked)"

# --- INPUT: local, return traffic, and the nanobot-api listener ---
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# Published services (host -> container; see docker-compose.yml)
iptables -A INPUT -p tcp -m multiport --dports 8900,18790 -j ACCEPT

# --- OUTPUT: essentials ---
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# DNS (any resolver)
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

# NTP
iptables -A OUTPUT -p udp --dport 123 -j ACCEPT

# ICMP (path MTU, ping, etc.)
iptables -A OUTPUT -p icmp -j ACCEPT

# host.docker.internal: TCP 8801-8810 only; block all other traffic to that address.
iptables -A OUTPUT -p tcp -d "$HOST_DOCKER_INTERNAL_IP" -m multiport --dports 8801:8810 -j ACCEPT
iptables -A OUTPUT -d "$HOST_DOCKER_INTERNAL_IP" -j REJECT --reject-with icmp-admin-prohibited

# HTTP(S) to the public internet (and anywhere else except blocked destinations above)
iptables -A OUTPUT -p tcp -m multiport --dports 80,443 -j ACCEPT

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

iptables -A OUTPUT -j REJECT --reject-with icmp-admin-prohibited

echo "Firewall configuration complete"
echo "Verifying firewall rules..."
if curl --connect-timeout 5 http://portquiz.net:8080 >/dev/null 2>&1; then
    echo "ERROR: Firewall verification failed - was able to reach http://portquiz.net:8080"
    exit 1
else
    echo "Firewall verification passed - unable to reach http://portquiz.net:8080 as expected"
fi

if ! curl --connect-timeout 5 -fsS https://example.com >/dev/null; then
    echo "ERROR: Firewall verification failed - could not reach https://example.com"
    exit 1
fi
echo "Firewall verification passed - https://example.com reachable"
