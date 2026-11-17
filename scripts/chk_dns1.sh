#!/bin/sh
# Read-only local DNS resolver diagnostic (uses nameservers from /etc/resolv.conf)
cd /home/daytona/workspace
python3 scripts/dnsdiag.py ident
