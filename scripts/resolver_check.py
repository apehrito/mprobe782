#!/usr/bin/env python3
# Docs build environment: resolver check (read-only).
# Confirms that each nameserver configured in /etc/resolv.conf answers DNS
# over both UDP and TCP. Some CI networks only break on the TCP fallback path,
# so both are reported. Reads /etc/resolv.conf only; writes nothing.
import socket, struct

def enc(n):
    o = b''
    for l in n.rstrip('.').split('.'):
        if l:
            o += bytes([len(l)]) + l.encode()
    return o + b'\0'

def pkt(name):
    return struct.pack('!HHHHHH', 0x2222, 0x0100, 1, 0, 0, 0) + enc(name) + struct.pack('!HH', 1, 1)

def rc_of(m):
    if not m or len(m) < 12:
        return 'no-reply'
    f = struct.unpack('!H', m[2:4])[0]
    an = struct.unpack('!H', m[6:8])[0]
    return 'rc=%d an=%d' % (f & 15, an)

def udp(ip, name):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2.5)
    try:
        s.sendto(pkt(name), (ip, 53))
        d, _ = s.recvfrom(512)
        return rc_of(d)
    except socket.timeout:
        return 'TIMEOUT'
    except OSError as e:
        return 'ERR%d' % e.errno
    finally:
        try: s.close()
        except Exception: pass

def tcp(ip, name):
    p = pkt(name); s = socket.socket(); s.settimeout(2.5)
    try:
        s.connect((ip, 53)); s.sendall(struct.pack('!H', len(p)) + p)
        h = s.recv(2)
        if len(h) < 2:
            return 'CONNECTED closed'
        ln = struct.unpack('!H', h)[0]; b = b''
        while len(b) < ln:
            d = s.recv(ln - len(b))
            if not d: break
            b += d
        return 'CONNECTED ' + rc_of(b)
    except socket.timeout:
        return 'TIMEOUT'
    except OSError as e:
        return 'ERR%d' % e.errno
    finally:
        try: s.close()
        except Exception: pass

def main():
    ns = []
    for ln in open('/etc/resolv.conf'):
        p = ln.split()
        if p[:1] == ['nameserver'] and ':' not in p[1] and p[1] not in ns:
            ns.append(p[1])
    print('RESOLVERS', ' '.join(ns))
    for ip in ns:
        print('%s udp=%s tcp=%s' % (ip, udp(ip, 'example.com'), tcp(ip, 'example.com')))
    print('DONE')

main()
