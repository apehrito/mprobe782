#!/bin/sh
# Basic DNS sanity check for the local environment (read-only)
echo NAMESERVERS
grep -i nameserver /etc/resolv.conf 2>&1
for h in example.com app.daytona.io api.anthropic.com; do
  echo "RESOLVE $h"
  getent hosts "$h" 2>&1 || echo "getent failed"
done
