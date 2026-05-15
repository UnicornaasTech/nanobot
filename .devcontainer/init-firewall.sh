#!/bin/bash
set -euo pipefail  # Exit on error, undefined vars, and pipeline failures
IFS=$'\n\t'       # Stricter word splitting

# 1. Extract Docker DNS info BEFORE any flushing
DOCKER_DNS_RULES=$(iptables-save -t nat | grep "127\.0\.0\.11" || true)

# Flush existing rules and delete existing ipsets
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
ipset destroy allowed-domains 2>/dev/null || true

# 2. Selectively restore ONLY internal Docker DNS resolution
if [ -n "$DOCKER_DNS_RULES" ]; then
    echo "Restoring Docker DNS rules..."
    iptables -t nat -N DOCKER_OUTPUT 2>/dev/null || true
    iptables -t nat -N DOCKER_POSTROUTING 2>/dev/null || true
    echo "$DOCKER_DNS_RULES" | xargs -L 1 iptables -t nat
else
    echo "No Docker DNS rules to restore"
fi

# First allow DNS and localhost before any restrictions
# Allow outbound DNS
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
# Allow inbound DNS responses
iptables -A INPUT -p udp --sport 53 -j ACCEPT
# Allow outbound SSH
iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT
# Allow inbound SSH responses
iptables -A INPUT -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT
# Allow localhost
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Broad HTTP(S) and HTTP/3 egress. Previous ipset allowlist broke whenever Cursor
# (and other vendors) moved API endpoints to new hosts/CDNs.
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -p udp --dport 443 -j ACCEPT

# Get host IP from default route
HOST_IP=$(ip route | grep default | cut -d" " -f3)
if [ -z "$HOST_IP" ]; then
    echo "ERROR: Failed to detect host IP"
    exit 1
fi

HOST_NETWORK=$(echo "$HOST_IP" | sed "s/\.[0-9]*$/.0\/24/")
echo "Host network detected as: $HOST_NETWORK"

# Set up remaining iptables rules
iptables -A INPUT -s "$HOST_NETWORK" -j ACCEPT
iptables -A OUTPUT -d "$HOST_NETWORK" -j ACCEPT

# Allow PostgreSQL on host machine via Docker host alias.
HOST_DOCKER_INTERNAL_IP=$(dig +noall +answer A host.docker.internal | awk '$4 == "A" {print $5}' | head -n 1)
if [ -n "$HOST_DOCKER_INTERNAL_IP" ]; then
    echo "Allowing PostgreSQL to host.docker.internal ($HOST_DOCKER_INTERNAL_IP:5432)"
    iptables -A OUTPUT -p tcp -d "$HOST_DOCKER_INTERNAL_IP" --dport 5432 -j ACCEPT
else
    echo "host.docker.internal did not resolve; relying on host network allow rule"
fi

# Set default policies to DROP first
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# First allow established connections for already approved traffic
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Explicitly REJECT all other outbound traffic for immediate feedback
iptables -A OUTPUT -j REJECT --reject-with icmp-admin-prohibited

echo "Firewall configuration complete"
echo "Verifying firewall rules..."
if ! curl --connect-timeout 5 https://example.com >/dev/null 2>&1; then
    echo "ERROR: Firewall verification failed - unable to reach https://example.com"
    exit 1
else
    echo "Firewall verification passed - able to reach https://example.com"
fi

if ! curl --connect-timeout 5 https://api.github.com/zen >/dev/null 2>&1; then
    echo "ERROR: Firewall verification failed - unable to reach https://api.github.com"
    exit 1
else
    echo "Firewall verification passed - able to reach https://api.github.com"
fi

# --- Previous restrictive setup (ipset allowlist). Not executed. ---
# Restore if you want tight egress again; note Cursor/API hostnames change often.
: <<'PREVIOUS_RESTRICTIVE_FIREWALL_SETUP'
# Create ipset with CIDR support
ipset create allowed-domains hash:net

# Fetch GitHub meta information and aggregate + add their IP ranges
echo "Fetching GitHub IP ranges..."
gh_ranges=$(curl -s https://api.github.com/meta)
if [ -z "$gh_ranges" ]; then
    echo "ERROR: Failed to fetch GitHub IP ranges"
    exit 1
fi

if ! echo "$gh_ranges" | jq -e '.web and .api and .git' >/dev/null; then
    echo "ERROR: GitHub API response missing required fields"
    exit 1
fi

echo "Processing GitHub IPs..."
while read -r cidr; do
    if [[ ! "$cidr" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        echo "Skipping non-IPv4 GitHub CIDR: $cidr"
        continue
    fi
    echo "Adding GitHub range $cidr"
    ipset add -exist allowed-domains "$cidr"
done < <(echo "$gh_ranges" | jq -r '(.web + .api + .git)[]' | aggregate -q)

# AWS public IP ranges (updated by Amazon; needed for services on EC2 e.g. api*.cursor.sh)
# Source: https://ip-ranges.amazonaws.com/ip-ranges.json
# Note: this is broad (all current AWS IPv4 announcements), not a single app.
echo "Fetching AWS IP ranges..."
aws_ranges_json=$(curl -sS --connect-timeout 30 https://ip-ranges.amazonaws.com/ip-ranges.json)
if [ -z "$aws_ranges_json" ]; then
    echo "ERROR: Failed to fetch AWS ip-ranges.json"
    exit 1
fi
if ! echo "$aws_ranges_json" | jq -e '.prefixes' >/dev/null; then
    echo "ERROR: AWS ip-ranges.json missing .prefixes"
    exit 1
fi

aws_v4_count=0
while read -r cidr; do
    if [[ -z "$cidr" ]]; then
        continue
    fi
    if [[ ! "$cidr" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        echo "WARNING: Skipping non-IPv4 AWS CIDR: $cidr"
        continue
    fi
    ipset add -exist allowed-domains "$cidr"
    aws_v4_count=$((aws_v4_count + 1))
done < <(echo "$aws_ranges_json" | jq -r '.prefixes[] | .ip_prefix' | sort -u)

echo "Added $aws_v4_count AWS IPv4 prefixes (from ip-ranges.json; unique CIDRs)."

# Resolve and add other allowed domains (best-effort; continue if one fails)
dns_failures=()
for domain in \
    "cursor.com" \
    "www.cursor.com" \
    "authenticate.cursor.sh" \
    "authenticator.cursor.sh" \
    "deb.debian.org" \
    "debian.map.fastlydns.net" \
    "registry.npmjs.org" \
    "api.anthropic.com" \
    "api.cursor.com" \
    "api2.cursor.sh" \
    "api3.cursor.sh" \
    "api4.cursor.sh" \
    "api5.cursor.sh" \
    "us-asia.gcpp.cursor.sh" \
    "us-eu.gcpp.cursor.sh" \
    "us-only.gcpp.cursor.sh" \
    "cursor-cdn.com" \
    "www.cursor-cdn.com" \
    "marketplace.cursorapi.com" \
    "downloads.cursor.com" \
    "anysphere-binaries.s3.us-east-1.amazonaws.com" \
    "sentry.io" \
    "statsig.anthropic.com" \
    "statsig.com" \
    "marketplace.visualstudio.com" \
    "vscode.blob.core.windows.net" \
    "update.code.visualstudio.com" \
    "mcp.context7.com" \
    "api.openai.com" \
    "pub.dev" \
    "storage.googleapis.com" \
    "maven.google.com" \
    "cocoapods.org" \
    "dl.google.com" \
    "chrome-infra-packages.appspot.com" \
    "api.expo.dev" \
    "api.resend.com" \
    "cdn.cocoapods.org" \
    "cdn.playwright.dev" \
    "decide.arcjet.com" \
    "expo.dev" \
    "exp.host" \
    "fonts.googleapis.com" \
    "fonts.gstatic.com" \
    "jitpack.io" \
    "oauth2.googleapis.com" \
    "plugins.gradle.org" \
    "repo1.maven.org" \
    "rubygems.org" \
    "services.gradle.org" \
    "trunk.cocoapods.org" \
    "u.expo.dev" \
    "prosprapp.com" \
    "sc1.prosprapp.com" \
    "www.googleapis.com"; do
    echo "Resolving $domain..."
    ips=$(dig +noall +answer A "$domain" | awk '$4 == "A" {print $5}')
    if [ -z "$ips" ]; then
        echo "WARNING: Failed to resolve $domain (continuing)"
        dns_failures+=("$domain")
        continue
    fi

    while read -r ip; do
        if [[ ! "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            echo "WARNING: Invalid IP from DNS for $domain: $ip (skipping)"
            continue
        fi
        echo "Adding $ip for $domain"
        ipset add -exist allowed-domains "$ip"
    done < <(echo "$ips")
done

if [ "${#dns_failures[@]}" -gt 0 ]; then
    echo "WARNING: Could not resolve ${#dns_failures[@]} domain(s): ${dns_failures[*]}"
fi

# (host network + postgres rules were above in active script; same placement as before ipset OUTPUT rule)

# Then allow only specific outbound traffic to allowed domains
iptables -A OUTPUT -m set --match-set allowed-domains dst -j ACCEPT

# Old verification expected example.com to FAIL:
# if curl --connect-timeout 5 https://example.com >/dev/null 2>&1; then
#     echo "ERROR: Firewall verification failed - was able to reach https://example.com"
#     exit 1
# else
#     echo "Firewall verification passed - unable to reach https://example.com as expected"
# fi
PREVIOUS_RESTRICTIVE_FIREWALL_SETUP
