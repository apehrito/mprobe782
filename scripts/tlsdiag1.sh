#!/bin/sh
P="sed -n 1,8p"
echo "== K1"
echo | timeout 6 openssl s_client -connect 44.196.251.121:443 -servername keyring.mintlify.com -brief 2>&1 | $P
echo "== K2"
echo | timeout 6 openssl s_client -connect 98.80.115.27:443 -servername keyring.mintlify.com -brief 2>&1 | $P
echo "== K3"
echo | timeout 6 openssl s_client -connect 184.192.87.69:443 -servername keyring-dev.mintlify.com -brief 2>&1 | $P
echo "== K4"
echo | timeout 6 openssl s_client -connect 98.89.158.174:443 -servername keyring-dev.mintlify.com -brief 2>&1 | $P
echo "== C1"
echo | timeout 5 openssl s_client -connect 174.138.181.250:8110 -brief 2>&1 | sed -n 1,6p
echo "== N1"
echo | timeout 5 openssl s_client -connect 44.198.237.22:443 -servername egress-proxy.mintlify.com -brief 2>&1 | $P
echo "== N2"
echo | timeout 5 openssl s_client -connect 100.56.58.27:443 -servername egress-proxy.mintlify.com -brief 2>&1 | $P
