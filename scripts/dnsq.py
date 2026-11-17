#!/usr/bin/env python3
# Small read-only DNS query helper: ask a given nameserver for a name and print answers.
import socket, struct, sys, random

def enc(n):
    o = b''
    for l in n.rstrip('.').split('.'):
        o += bytes([len(l)]) + l.encode()
    return o + b'\0'

def build(n, t, c, rd):
    i = random.randrange(65536)
    fl = 0x0100 if rd else 0
    return struct.pack('!HHHHHH', i, fl, 1, 0, 0, 0) + enc(n) + struct.pack('!HH', t, c)

def skip(m, o):
    while o < len(m):
        l = m[o]
        if l == 0: return o + 1
        if l & 192 == 192: return o + 2
        o += 1 + l
    return o

def name(m, o):
    parts = []; j = 0
    while o < len(m):
        l = m[o]
        if l == 0: o += 1; break
        if l & 192 == 192:
            if not j: ret = o + 2
            j = 1; o = ((l & 63) << 8) | m[o+1]; continue
        o += 1; parts.append(m[o:o+l].decode('utf-8', 'replace')); o += l
    return '.'.join(parts), (ret if j else o)

def query(server, qname, qtype=1, qclass=1, rd=1, timeout=2.0):
    msg = build(qname, qtype, qclass, rd)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
    try:
        s.sendto(msg, (server, 53))
        d, _ = s.recvfrom(4096)
    except Exception as e:
        return 'ERR ' + str(e)[:60]
    finally:
        s.close()
    if len(d) < 12: return 'short reply'
    _, f, qd, an, ns, ar = struct.unpack('!HHHHHH', d[:12])
    o = 12
    for _ in range(qd): o = skip(d, o) + 4
    out = []
    for _ in range(an + ns + ar):
        nm, o = name(d, o)
        if o + 10 > len(d): break
        t, c, ttl, dl = struct.unpack('!HHIH', d[o:o+10]); o += 10
        st = o; raw = d[o:o+dl]; o += dl; v = ''
        if t == 1 and dl == 4: v = socket.inet_ntoa(raw)
        elif t == 28 and dl == 16: v = socket.inet_ntop(socket.AF_INET6, raw)
        elif t in (2, 5, 12): v = name(d, st)[0]
        elif t == 16:
            v = ''
            while st < o:
                ln = d[st]; v += d[st+1:st+1+ln].decode('utf-8', 'replace'); st += 1 + ln
        else: v = raw.hex()[:60]
        out.append('%s T%d %s' % (nm, t, v))
    return 'rc=%d aa=%d ra=%d an=%d | %s' % (f & 15, (f >> 10) & 1, (f >> 7) & 1, len(out), '; '.join(out[:8]))

if __name__ == '__main__':
    srv, nm = sys.argv[1], sys.argv[2]
    t = int(sys.argv[3]) if len(sys.argv) > 3 else 1
    c = int(sys.argv[4]) if len(sys.argv) > 4 else 1
    print(srv, nm, 't%d' % t, '->', query(srv, nm, t, c))
