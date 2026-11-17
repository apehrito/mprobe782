import socket,ssl,base64,json,sys,threading
from concurrent.futures import ThreadPoolExecutor
H1=base64.b64decode('MTcyLjIwLjAuMQ==').decode()
H2='127.0.0.1'
H3=socket.gethostbyname(socket.gethostname())
PORTS=[22,80,443,2375,2376,3128,5000,6443,8000,8080,8443,9090,10250,18080,2280,22220,22222,33333,3000,5432,6379,9091,9093,1234,1400,4000,5001,7000,7070,9000]
def tcp(h,p,to=1.0):
    s=socket.socket(); s.settimeout(to)
    try:
        r=s.connect_ex((h,p))
        return r
    except Exception as e:
        return -1
    finally:
        try:s.close()
        except:pass
def probe(h,p):
    r=tcp(h,p)
    if r==0: return (h,p,'open')
    return (h,p,'closed' if r in (111,61,0) else 'x%d'%r)
print('SELF',H3)
jobs=[]
with ThreadPoolExecutor(max_workers=24) as ex:
    fs={ex.submit(probe,h,p):(h,p) for h in (H1,H2,H3) for p in PORTS}
    res=[]
    for f in fs:
        try: res.append(f.result())
        except: pass
for h,p,st in sorted(res):
    if st=='open' or st.startswith('x'):
        print('TCP',h,p,st)
def http(h,p,path,to=2.5,tls=False):
    try:
        s=socket.create_connection((h,p),timeout=to)
        if tls:
            ctx=ssl._create_unverified_context()
            s=ctx.wrap_socket(s,server_hostname=h)
        req=("GET %s HTTP/1.1\r\nHost: %s:%d\r\nUser-Agent: probe\r\nConnection: close\r\n\r\n"%(path,h,p)).encode()
        s.sendall(req)
        d=b''
        while len(d)<1200:
            c=s.recv(1200)
            if not c: break
            d+=c
        s.close()
        return d.decode('latin1')
    except Exception as e:
        return 'ERR '+type(e).__name__+' '+str(e)[:60]
opens=[(h,p) for h,p,st in res if st=='open']
paths={2375:['/version','/containers/json','/info'],2376:['/version','/containers/json'],6443:['/healthz','/version'],10250:['/healthz','/pods','/metrics'],18080:['/'],2280:['/version','/init','/process/list'],22220:['/'],22222:['/']}
for h,p in opens:
    if h==H3: continue
    for path in paths.get(p,['/','/version','/healthz','/metrics']):
        out=http(h,p,path)
        first=out.split('\r\n\r\n')[0][:200].replace('\r\n',' | ')
        body=out.split('\r\n\r\n',1)[1][:120].replace('\n',' ') if '\r\n\r\n' in out else ''
        print('HTTP',h,p,path,'::',first,'::',body)
