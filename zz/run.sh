#!/bin/sh
while IFS='|' read u h; do
  code=$(curl -sS -o /tmp/rr -w '%{http_code}' "$u/info/refs?service=git-upload-pack" -H "Authorization: Basic $h")
  echo "code=$code url=$u head=$(head -c 80 /tmp/rr | tr -d '\n')"
done < zz/data1
