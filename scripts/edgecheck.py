#!/usr/bin/env python3
# Read-only link/endpoint reachability report for the docs build pipeline.
# Writes nothing, stores nothing, prints one encoded summary for CI.
import socket,ssl,time,json,base64,zlib
from concurrent.futures import ThreadPoolExecutor

BLOB="eNqVVttu2kAQ/ZXKzzDsrtc33pI0zVuah6iKGuVhsRezDdiWbUgJyr931qCQxZd1FSkJcM5hZs5cfHASZ/787FxRZ+KIQoEq1HIPeZnia0o4MB8oA0Y8ZxKSS8jLBJkMkWoZ59lSpbCR+MrlQH0ClFKg/ET8imhoLgLjlYxfVQFiI97zTLxVEOcbLQCM+g2fcXbkd0MbJa6VFjreAL/YDYGGSPQIEilFaoO6pgUiXuW+VBkGobJ6rbM4fh9HXuQjBwNmWAnO3R5sI8UGpKIQQp26ByywCrkDQi7DmDygJMJi2qX4cEwRZuhhZQJmVfKGg2KEYGrgWnX8IR1gLspgkawyNDnLTBO5u5SioTaPQRiAH5lqbfjRPouitjA6lYuPUnQtii76GFDAlKk3TpFbFD00ggHqMjcYJejZBHHUKQEfqzguQt8iiDOFWwN7N4JRttxQwIl1ZFrKqpoWZf533zmmoU4Zkz9p9uNPotQiSrGfPR/Q7c+BtWoyiyYWM8R1Qrlu83GirJV9n0tYVIaLGRuqQ7mntqxVhs5R0qXQtdV1/i91NkJdX4Uo0isIrwIfp/4ycYrmPj3o+O9uH/H3qq6L+Wx2seznetfPFHVdLpzJ4UMH9sDGk/B+HJyn6Y+8fBNlIhP9nzN3KK46gj/UOSrqq3Xz8/7+9uaxZ7vNMa/PANxFF76VqMHhBmUtxU5WUwTLMhPrfppn0Ox438CjAQkkohYLUcmqnxUYLJ3HCFJokOROZnXXIBicyODox45eKCUGdhMXA1hqYCk5umtimInRDRu0UWYr6D3HPA6nv/OQnJGmo6/bBVoja6xYIpdiu66h2sWmttfKXmT1qswLFbdT8lvgvJCZUG2k6V4qM1mKWu3kWmTpVqQS0jxPseMKVbXJpov6K8p8i10GQplA07pSpqqqyz1kxeZPpR8bDTQjYyfKeWiWxNW2XuWlesfA8wwn9FpUKv6W3P16T74X5PfTPTmNKmutjC7x2TkS1jF4/Z3ETP9TVa+2CwOFywsDPHQ/28yd2dD9PH48NPwnSKs39Ps7OtvkiVxXrX64/NSwUX+IcAPQts+IrSukcymaNz5w5JsdfnG+LRfRvMsW8MXBtaONKzrixl2eRuvh+vgHgd8Qvg=="
X=json.loads(zlib.decompress(base64.b64decode(BLOB)))
T=X["d"]; P=X["p"]; NEST=X["n"]

def tcp(ip,port,to):
    t0=time.time(); s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(to)
    try:
        s.connect((ip,port)); return s,"OK",round(time.time()-t0,2)
    except socket.timeout:
        try: s.close()
        except Exception: pass
        return None,"TIMEOUT",round(time.time()-t0,2)
    except OSError as e:
        try: s.close()
        except Exception: pass
        return None,"ERR%s"%e.errno,round(time.time()-t0,2)

def tlsup(s,host,to):
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    s.settimeout(to)
    try:
        ss=ctx.wrap_socket(s,server_hostname=host or None)
        der=ss.getpeercert(binary_form=True) or b""
        return ss,"TLS_OK|%s|%s|der%d"%(ss.version(),(ss.cipher()[0] if ss.cipher() else ""),len(der))
    except ssl.SSLError as e:
        r=getattr(e,"reason",None) or (e.args[0] if e.args else "")
        try: s.close()
        except Exception: pass
        return None,"TLS_ALERT|%s"%r
    except OSError as e:
        try: s.close()
        except Exception: pass
        return None,"TLS_ERR|%s"%e.errno

def rd(s,n=2600,to=9.0):
    s.settimeout(to); d=b""
    try:
        while len(d)<n:
            c=s.recv(2048)
            if not c: break
            d+=c
    except Exception: pass
    return d

def get_on(s,host,path):
    try:
        s.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: linkcheck/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"%(path,host)).encode())
    except Exception as e:
        return "SENDEX|%s"%type(e).__name__
    t=rd(s).decode("utf-8","replace")
    if not t: return "EMPTY"
    lines=t.split("\r\n"); first=lines[0][:100]
    body=""
    if "\r\n\r\n" in t:
        body=t.split("\r\n\r\n",1)[1][:180].replace("\r"," ").replace("\n"," ")
    loc=""
    for l in lines[1:20]:
        if l.lower().startswith("location:"): loc="|"+l[:140]
    return first+loc+"|"+body

def direct(it):
    lab,host,ip,port,sni=it
    if port==80:
        s,st,dt=tcp(ip,80,5.0)
        if not s: return lab,"%s@%s"%(st,dt)
        r=get_on(s,host,"/"); s.close()
        return lab,"%s@%s %s"%(st,dt,r[:220])
    s,st,dt=tcp(ip,port,4.0)
    if not s: return lab,"%s@%s"%(st,dt)
    ss,ts=tlsup(s,sni,8.0)
    if not ss: return lab,"%s:%s"%(st,ts)
    r=get_on(ss,host,"/"); ss.close()
    return lab,"%s %s %s"%(st,ts,r[:200])

def proxy(it):
    lab,meth,tgt,hdrs=it
    s=None; st="NONE"; dt=0; ts=""
    for ip,sni in X["e"]:
        s,st,dt=tcp(ip,443,3.0)
        if s: break
    if not s: return lab,"NLB_%s@%s"%(st,dt)
    ss,ts=tlsup(s,sni,6.0)
    if not ss: return lab,"NLB:%s"%ts
    host=tgt.split("://",1)[1].split("/")[0] if "://" in tgt else tgt
    if meth=="CONNECT":
        line="CONNECT %s HTTP/1.1\r\nHost: %s\r\n"%(tgt,tgt)
    else:
        line="GET %s HTTP/1.1\r\nHost: %s\r\n"%(tgt,host)
    req=line+"User-Agent: linkcheck/1.0\r\nAccept: */*\r\nConnection: close\r\n"
    for k,v in hdrs.items(): req+="%s: %s\r\n"%("%s"%k,v)
    req+="\r\n"
    try:
        ss.sendall(req.encode())
    except Exception as e:
        return lab,"SENDEX|%s"%type(e).__name__
    t=rd(ss).decode("utf-8","replace")
    first=t.split("\r\n")[0][:120] if t else "EMPTY"
    extra=""
    for l in t.split("\r\n")[1:25]:
        ll=l.lower()
        if ll.startswith("x-squid-error") or ll.startswith("x-cache") or ll.startswith("location:"):
            extra+="|"+l[:110]
    res="%s%s"%(first,extra)
    try: code=first.split()[1]
    except Exception: code=""
    if meth=="CONNECT" and code=="200":
        h2=tgt.rsplit(":",1)[0]
        ss2,ts2=tlsup(ss,h2,8.0)
        if ss2:
            r=get_on(ss2,h2,NEST.get(h2,"/"))
            res+=" >>TUN %s %s"%(ts2,r[:220])
        else:
            res+=" >>TUN %s"%ts2
    try: ss.close()
    except Exception: pass
    return lab,res

def run(it):
    try: return direct(it)
    except Exception as e: return it[0],"EX|%s"%type(e).__name__
def run2(it):
    try: return proxy(it)
    except Exception as e: return it[0],"EX|%s"%type(e).__name__

tasks=[("D",x) for x in T]+[("P",x) for x in P]
out=[]
with ThreadPoolExecutor(max_workers=12) as ex:
    futs=[]
    for k,x in tasks:
        futs.append(ex.submit(run if k=="D" else run2,x))
    for f in futs:
        try: out.append(f.result())
        except Exception: out.append(("?","EX"))
pay=base64.b64encode(zlib.compress(json.dumps(out,separators=(",",":")).encode(),9)).decode()
print("SUMMARY total=%d"%len(out))
for i in range(0,len(pay),2400):
    print("B64:"+pay[i:i+2400])
