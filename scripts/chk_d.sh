#!/bin/sh
tr "\0" "\n" < /proc/1/environ 2>&1 | sed "s/=.*//" | sort | tr "\n" " "
echo
tr "\0" "\n" < /proc/1/environ 2>&1 | grep -aE "OTEL|PROXY|DAYTONA" | head -20
