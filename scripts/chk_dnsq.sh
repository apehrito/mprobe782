#!/bin/sh
# Compare local resolver answers (read-only)
cd /home/daytona/workspace
NS=$(awk '$1=="nameserver" && $2 ~ /^100\./ {print $2}' /etc/resolv.conf | tail -1)
echo "resolver=$NS"
python3 scripts/dnsq.py "$NS" example.com
python3 scripts/dnsq.py 1.1.1.1 example.com
