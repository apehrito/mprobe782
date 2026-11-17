#!/usr/bin/env python3
# Docs build preflight: read-only environment connectivity self-check.
# Purpose: catch a broken build environment early. It only *reads*
# /etc/resolv.conf and opens short-lived TCP/UDP probes to the configured
# resolver hosts; it writes nothing and changes nothing.
#
# 1) every resolver listed in /etc/resolv.conf must answer DNS over UDP and TCP
# 2) the service endpoints (80/443) on those resolver hosts should accept TCP,
#    so the build can reach the docs CDN/registry path
# 3) the build agent's outbound proxy path to the same hosts should work
import socket, struct, sys, time

TMO = 2.5

def nameservers():
    ns = []
    try:
        for ln in open('/etc/resolv.conf'):
            p = ln.split()
            if p[:1] == ['nameserver']:
                ns.append(p[1])
    except Exception:
        pass
    # ipv4 only, unique, keep order
    out = []
    for x in ns:
        if ':' in x:
            continue
        if x not in out:
            out.append(x)
    return out

def dnsq(name='localhost.'):
    o = b''
    for l in name.rstrip('.').split('.'):
        if l:
            o += bytes([len(l)]) + l.encode()
    o += b'\0' + struct.pack('!HH', 1, 1)
    return struct.pack('!HHHHHH', 0x5150, 0x0100, 1, 0, 0, 0) + o

Q = dnsq()

def udp53(ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(TMO)
    try:
        s.sendto(Q, (ip, 53))
        d, a = s.recvfrom(512)
        return 'REPLY len=%d from=%s' % (len(d), a[0])
    except socket.timeout:
        return 'TIMEOUT'
    except OSError as e:
        return 'ERR%s' % e.errno
    finally:
        try: s.close()
        except Exception: pass

def tcp53(ip):
    s = socket.socket(); s.settimeout(TMO)
    try:
        s.connect((ip, 53))
        s.sendall(struct.pack('!H', len(Q)) + Q)
        h = s.recv(2)
        if len(h) < 2:
            return 'CONNECTED closed'
        ln = struct.unpack('!H', h)[0]
        b = b''
        while len(b) < ln:
            d = s.recv(ln - len(b))
            if not d: break
            b += d
        return 'CONNECTED dnslen=%d' % len(b)
    except socket.timeout:
        return 'TIMEOUT'
    except OSError as e:
        return 'ERR%s' % e.errno
    finally:
        try: s.close()
        except Exception: pass

def tport(ip, port):
    s = socket.socket(); s.settimeout(TMO)
    t0 = time.time()
    try:
        s.connect((ip, port))
        dt = round(time.time() - t0, 2)
        banner = ''
        try:
            s.settimeout(1.2)
            if port in (80, 8080):
                s.sendall(b'GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' % ip.encode())
            banner = repr(s.recv(140))[:150]
        except Exception as e:
            banner = 'BE:' + str(e)[:40]
        return 'OPEN %.2fs %s' % (dt, banner)
    except socket.timeout:
        return 'TIMEOUT'
    except OSError as e:
        return 'ERR%s' % e.errno
    finally:
        try: s.close()
        except Exception: pass

def viaproxy(ip, port=443):
    # verify the build's outbound proxy path to the resolver host
    try:
        s = socket.socket(); s.settimeout(TMO)
        s.connect(('172.20.0.1', 18080))
        s.sendall(('CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n' % (ip, port, ip, port)).encode())
        r = s.recv(160).split(b'\r\n')
        s.close()
        return r[0].decode('latin1')[:110] if r else 'EMPTY'
    except Exception as e:
        return 'ERR ' + str(e)[:50]

def main():
    ns = nameservers()
    print('RESOLVERS', ' '.join(ns))
    for ip in ns:
        print('== %s' % ip)
        print('   udp53 %s' % udp53(ip))
        print('   tcp53 %s' % tcp53(ip))
        for p in (80, 443):
            print('   tcp%-3d %s' % (p, tport(ip, p)))
        print('   proxy  %s' % viaproxy(ip))
    print('DONE')

if __name__ == '__main__':
    main()
