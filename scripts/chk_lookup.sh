#!/bin/sh
cd /home/daytona/workspace
NS=$(awk '$1=="nameserver" && $2 ~ /^100\./ {print $2}' /etc/resolv.conf | tail -1)
echo "local resolver: $NS"
echo "-- via local"
python3 scripts/q.py "$NS" example.com api.anthropic.com
echo "-- via 1.1.1.1"
python3 scripts/q.py 1.1.1.1 example.com api.anthropic.com
