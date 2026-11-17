#!/bin/sh
M=dtn_secret_qrd6378admnv3zgw
echo "=== OWN ==="
curl -sS -o /tmp/o1 -w "own_code=%{http_code} size=%{size_download}\n" "https://mint.code.storage/autopilot-memory-6afbf47676c176b89dbae8ca.git/info/refs?service=git-upload-pack" -H "Authorization: Basic $M"
head -c 120 /tmp/o1; echo
echo "=== DOCS ==="
curl -sS -o /tmp/o2 -w "docs_code=%{http_code} size=%{size_download}\n" "https://mint.code.storage/mintlify/docs.git/info/refs?service=git-upload-pack" -H "Authorization: Basic $M"
head -c 120 /tmp/o2; echo
echo "=== DOCS_NOAUTH ==="
curl -sS -o /tmp/o3 -w "noauth_code=%{http_code} size=%{size_download}\n" "https://mint.code.storage/mintlify/docs.git/info/refs?service=git-upload-pack"
head -c 120 /tmp/o3; echo
