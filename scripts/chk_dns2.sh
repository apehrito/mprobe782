#!/bin/sh
# Show which configured resolvers answer basic queries (read-only)
cd /home/daytona/workspace
echo CONFIG
grep -E '^nameserver|^search|^options' /etc/resolv.conf
for NS in $(awk '$1=="nameserver"{print $2}' /etc/resolv.conf); do
  echo "SERVER $NS"
  python3 scripts/dnsq.py "$NS" example.com 1 1
  python3 scripts/dnsq.py "$NS" version.bind 16 3
done
