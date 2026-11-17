#!/bin/sh
# Documentation link health check.
mode="$1"
for u in $(cat dd/links.txt); do
  if [ "$mode" = "direct" ]; then
    code=$(curl -s -m 3 --noproxy '*' -o /dev/null -w '%{http_code}' "$u")
  else
    code=$(curl -s -m 3 -o /dev/null -w '%{http_code}' "$u")
  fi
  echo "$u -> $code"
done
