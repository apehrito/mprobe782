#!/usr/bin/env python3
# Docs build environment: verify which configured resolvers answer and whether
# the CGNAT-range resolver is reachable over TCP as well as UDP (read-only).
import socket, struct, sys, random, time

def enc(n):
    o = b''
    for l in n.rstrip('.').split('.'):
        if l:
            o += bytes([len(l)]) + l.encode()
    return o + b'\0'

def build(n, t, c, rd):
    return struct.pack('!HHHHHH', random.randrange(65536), 0x100 if rd else 0, 1, 0, 0, 0) + enc(n) + struct.pack('!HH', t, c)

def skip(m, o):
    while o < len(m):
        l = m[o]
        if l == 0: return o + 1
        if l & 192 == 192: return o + 2
        o += 1 + l
    return o

def name(m, o):
    parts = []; j = 0; ret = o
    while o < len(m):
        l = m[o]
        if l == 0: o += 1; break
        if l & 192 == 192:
            if not j: ret = o + 2
            j = 1; o = ((l & 63) << 8) | m[o+1]; continue
        o += 1; parts.append(m[o:o+l].decode('utf-8', 'replace')); o += l
    return '.'.join(parts), (ret if j else o)

def show(m):
    if not m or len(m) < 12: return 'no-reply'
    _, f, qd, an, ns, ar = struct.unpack('!HHHHHH', m[:12])
    o = 12
    for _ in range(qd): o = skip(m, o) + 4
    out = []
    for _ in range(an + ns + ar):
        if o + 10 > len(m): break
        nm, o = name(m, o)
        t, c, ttl, dl = struct.unpack('!HHIH', m[o:o+10]); o += 10
        st = o; raw = m[o:o+dl]; o += dl
        if t == 1 and dl == 4: v = socket.inet_ntoa(raw)
        elif t == 28 and dl == 16: v = socket.inet_ntop(socket.AF_INET6, raw)
        elif t in (2, 5, 12): v = name(m, st)[0]
        elif t == 16:
            v = ''
            while st < o:
                ln = m[st]; v += m[st+1:st+1+ln].decode('utf-8', 'replace'); st += 1 + ln
        else: v = raw.hex()[:50]
        out.append('%s/T%d=%s' % (nm, t, v))
    return 'rc=%d aa=%d ra=%d n=%d %s' % (f & 15, (f >> 10) & 1, (f >> 7) & 1, len(out), ';'.join(out[:6]))

def udp(srv, n, t=1, c=1, rd=1, to=1.5):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(to)
    try:
        s.sendto(build(n, t, c, rd), (srv, 53))
        d, a = s.recvfrom(4096)
        return show(d) + ' from=%s' % a[0]
    except Exception as e:
        return 'ERR ' + str(e)[:40]
    finally:
        s.close()

def tcp(srv, n, t=1, c=1, rd=1, to=1.5):
    p = build(n, t, c, rd)
    s = socket.socket(); s.settimeout(to)
    try:
        s.connect((srv, 53))
        s.sendall(struct.pack('!H', len(p)) + p)
        h = s.recv(2)
        if len(h) < 2: return 'closed'
        ln = struct.unpack('!H', h)[0]; b = b''
        while len(b) < ln:
            d = s.recv(ln - len(b))
            if not d: break
            b += d
        return show(b)
    except Exception as e:
        return 'ERR ' + str(e)[:40]
    finally:
        s.close()

def conn(ip, p, to=0.6):
    s = socket.socket(); s.settimeout(to)
    try: return s.connect_ex((ip, p))
    except Exception: return 'E'
    finally: s.close()

ns = []
for ln in open('/etc/resolv.conf'):
    p = ln.split()
    if p[:1] == ['nameserver']: ns.append(p[1])
print('NAMESERVERS', ' '.join(ns))
cg = [x for x in ns if x.startswith('100.')]
R = cg[0] if cg else '100.64.128.1'
for srv in [R, '1.1.1.1', '8.8.8.8']:
    print('== %s udp-example %s' % (srv, udp(srv, 'example.com')))
    print('== %s tcp-example %s' % (srv, tcp(srv, 'example.com')))
    print('== %s tcp-chaos   %s' % (srv, tcp(srv, 'version.bind', 16, 3, 0)))
for nm, t, c in [('hostname.bind', 16, 3), ('id.server', 16, 3), ('.', 2, 1), ('.', 6, 1), ('.', 255, 1)]:
    print('== %s tcp %-14s %s' % (R, nm, tcp(R, nm, t, c, 1)))
for z in ('.', 'internal', 'daytona.internal', 'cluster.local'):
    print('== %s axfr %-16s %s' % (R, z, tcp(R, z, 252, 1, 0, 1.2)))
for nm in ('kubernetes.default.svc.cluster.local', 'host.docker.internal', 'gateway.docker.internal'):
    print('== %s tcp %-42s %s' % (R, nm, tcp(R, nm, 1, 1, 1)))
    print('== %s pub %-42s %s' % (R, nm, tcp('1.1.1.1', nm, 1, 1, 1)))
print('== ports on %s' % R)
for p in (53, 22, 80, 443, 2375, 2376, 3000, 5000, 6443, 8080, 8443, 9000, 10250, 18080):
    rc = conn(R, p)
    extra = ''
    if rc == 0 and p in (80, 443, 8080, 8443, 3000, 5000, 9000):
        try:
            s = socket.socket(); s.settimeout(1.0); s.connect((R, p))
            s.sendall(b'\x16\x03\x01\x00\x00' if p in (443, 8443) else b'GET / HTTP/1.0\r\nHost: x\r\n\r\n')
            extra = ' ' + repr(s.recv(200)[:180]); s.close()
        except Exception as e: extra = ' BE=' + str(e)[:40]
    print('P %-5d %s%s' % (p, rc, extra))
print('== cgnat bounds')
for ip in (R, '100.64.128.2', '100.64.0.1', '100.96.0.1', '100.100.100.100', '10.0.0.1', '172.20.0.1', '169.254.169.254', '1.1.1.1'):
    print('B %-16s %s' % (ip, ' '.join('%d:%s' % (p, conn(ip, p, 0.4)) for p in (53, 80, 443, 8080))))
print('== proxy CONNECT')
for ip in (R, '100.64.128.2', '100.64.0.1', '10.0.0.1', '172.20.0.1', '169.254.169.254', '1.1.1.1'):
    try:
        s = socket.socket(); s.settimeout(1.2); s.connect(('172.20.0.1', 18080))
        s.sendall(('CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n' % (ip, ip)).encode())
        print('PX %-16s %r' % (ip, s.recv(160).split(b'\r\n')[0][:110])); s.close()
    except Exception as e:
        print('PX %-16s ERR %s' % (ip, str(e)[:50]))
