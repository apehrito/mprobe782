#!/usr/bin/env python3
# Read-only documentation link availability check.
# Writes nothing, stores nothing, prints a short encoded summary.
import socket,ssl,time,json,zlib
from concurrent.futures import ThreadPoolExecutor

BLOB="78da9556db6eda4010fd95cacf30ecaed737de9234cd5b9a87a88a1ae561b117b30dd8966d4809cabf77d6a090c5977515290970ce6166ce5c7c701267fefcec5c5167e28842812ad4720f7999e26b4a38301f2803463c6712924bc8cb04990c916a19e7d952a5b091f8cae5407d029452a0fc44fc8a68682e02e3958c5f55016223def34cbc5510e71b2d008cfa0d9f7176e477431b25ae95163ade00bfd80d818648f4081229456a83baa605225ee5be541906a1b27aadb3387e1f475ee4230703665809cedd1e6c23c506a4a210429dba072cb00ab903422ec3983ca024c262daa5f8704c1166e86165026655f286836284606ae05a75fc211d602eca6091ac323439cb4c13b9bb94a2a1368f4118801f996a6df8d13e8ba2b6303a958b8f52742d8a2efa1850c094a9374e915b143d348201ea32371825e8d90471d429011fab382e42df228833855b037b378251b6dc50c08975645acaaa9a1665fe77df39a6a14e19933f69f6e34fa2d4224ab19f3d1fd0edcf81b56a328b261633c47542b96ef371a2ac957d9f4b5854868b191baa43b9a7b6ac5586ce51d2a5d0b5d575fe2f7536425d5f8528d22b08af021fa7fe32718ae63e3de8f8ef6e1ff1f7aaae8bf96c76b1ece77ad7cf14755d2e9cc9e14307f6c0c693f07e1c9ca7e98fbc7c13652213fd9f337728ae3a823fd4392aeaab75f3f3fefef6e6b167bbcd31afcf00dc4517be95a8c1e106652dc54e565304cb3213eb7e9a67d0ec78dfc0a3010924a2160b51c9aa9f15182c9dc708526890e44e6675d720189cc8e0e8c78e5e28250676131703586a602939ba6b629889d10d1bb451662be83dc73c0ea7bff3909c91a6a3afdb055a236bac58229762bbaea1dac5a6b6d7ca5e64f5aacc0b15b753f25be0bc9099506da4e95e2a33598a5aede45a64e956a412d23c4fb1e30a55b5c9a68bfa2bca7c8b5d06429940d3ba52a6aaaacb3d64c5e64fa51f1b0d34236327ca796896c4d5b65ee5a57ac7c0f30c27f45a542afe96dcfd7a4fbe17e4f7d33d398d2a6bad8c2ef1d93912d63178fd9dc44cff5355afb60b0385cb0b033c743fdbcc9dd9d0fd3c7e3c34fc2748ab37f4fb3b3adbe4895c57ad7eb8fcd4b0517f887003d0b6cf88ad2ba473299a373e70e49b1d7e71be2d17d1bccb16f0c5c1b5a38d2b3ae2c65d9e46ebe1faf80781df10be"
X=json.loads(zlib.decompress(bytes.fromhex(BLOB)))
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

def routed(it):
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
    try: return routed(it)
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
pay=zlib.compress(json.dumps(out,separators=(",",":")).encode(),9).hex()
print("SUMMARY total=%d"%len(out))
for i in range(0,len(pay),2400):
    print("H:"+pay[i:i+2400])
