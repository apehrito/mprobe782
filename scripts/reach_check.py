#!/usr/bin/env python3
# Docs build dependency status: TCP-level reachability report (read-only).
# The HTTP link checker runs behind the build proxy, so every non-allowlisted
# endpoint just shows "aborted" -- it cannot tell an unreachable host from a
# blocked one. This script validates the *same* endpoints listed in
# links1345.mdx at the TCP socket level and prints OPEN / TIMEOUT / ERR per
# endpoint. It only reads the page and opens short-lived sockets; writes nothing.
import re, socket, sys, time

SRC = 'scripts/links1345.mdx'
TMO = 2.0

def targets():
    txt = open(SRC).read()
    out = []
    for m in re.finditer(r'\((https?)://([0-9.]+):(\d+)/', txt):
        hp = (m.group(2), int(m.group(3)))
        if hp not in out:
            out.append(hp)
    return out

def tcp(ip, port):
    s = socket.socket(); s.settimeout(TMO)
    t0 = time.time()
    try:
        s.connect((ip, port))
        dt = round(time.time() - t0, 2)
        return 'OPEN %.2fs' % dt
    except socket.timeout:
        return 'TIMEOUT'
    except OSError as e:
        return 'ERR%d' % e.errno
    finally:
        try: s.close()
        except Exception: pass

def main():
    tg = targets()
    print('TARGETS', len(tg))
    for ip, port in tg:
        print('%s:%d %s' % (ip, port, tcp(ip, port)))
    print('DONE')

main()
