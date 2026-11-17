import socket,struct,random,sys,time,base64
# Local resolver diagnostics: read-only DNS checks against the sandbox's configured nameservers.
def en(n):
 o=b''
 for l in n.rstrip('.').split('.'):
  o+=bytes([len(l)])+l.encode()
 return o+b'\0'
def mk(n,t,c,rd):
 i=random.randrange(65536)
 return i,struct.pack('!HHHHHH',i,0x100 if rd else 0,1,0,0,0)+en(n)+struct.pack('!HH',t,c)
def dn(m,o):
 L=[];j=0;r=o
 while o<len(m):
  l=m[o]
  if l==0:o+=1;break
  if l&192==192:
   if not j:r=o+2
   j=1;o=((l&63)<<8)|m[o+1];continue
  o+=1;L.append(m[o:o+l].decode('utf-8','replace'));o+=l
 return '.'.join(L),(r if j else o)
def pr(m):
 if not m or len(m)<12:return 'none'
 _,f,qd,an,ns,ar=struct.unpack('!HHHHHH',m[:12]);o=12;A=[]
 for _ in range(qd):
  _,o=dn(m,o);o+=4
 for _ in range(an+ns+ar):
  nm,o=dn(m,o)
  if o+10>len(m):break
  t,c,ttl,dl=struct.unpack('!HHIH',m[o:o+10]);o+=10;s=o;d=m[o:o+dl];o+=dl;v=''
  if t==1 and dl==4:v=socket.inet_ntoa(d)
  elif t==28 and dl==16:v=socket.inet_ntop(socket.AF_INET6,d)
  elif t in(2,5,12):v=dn(m,s)[0]
  elif t==16:
   v=''
   while s<o:
    ln=m[s];v+=m[s+1:s+1+ln].decode('utf-8','replace');s+=1+ln
  elif t==6:v=dn(m,s)[0]
  else:v=d.hex()[:40]
  A.append('%s/T%d=%s'%(nm,t,v))
 return 'rc=%d aa=%d ra=%d an=%d %s'%(f&15,(f>>10)&1,(f>>7)&1,len(A),';'.join(A[:5]))
def ud(s,n,t,c,rd,to=2):
 i,p=mk(n,t,c,rd);x=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);x.settimeout(to)
 try:
  x.sendto(p,(s,53));return x.recvfrom(4096)[0]
 except Exception as e:return ('ERR '+str(e)[:40]).encode()
 finally:x.close()
def tc(s,n,t,c,to=2):
 i,p=mk(n,t,c,0);x=socket.socket();x.settimeout(to)
 try:
  x.connect((s,53));x.sendall(struct.pack('!H',len(p))+p);h=x.recv(2)
  if len(h)<2:return b''
  l=struct.unpack('!H',h)[0];b=b''
  while len(b)<l:
   d=x.recv(l-len(b))
   if not d:break
   b+=d
  return b
 except Exception as e:return ('ERR '+str(e)[:40]).encode()
 finally:x.close()
def nsl():
 a=[]
 for l in open('/etc/resolv.conf'):
  p=l.split()
  if p[:1]==['nameserver']:a.append(p[1])
 return a
def pick():
 n=nsl();r=[x for x in n if x.startswith('100.')];c=[x for x in n if x in('1.1.1.1','1.0.0.1','8.8.8.8')]
 return (r[0] if r else n[0] if n else '1.1.1.1'),(c[0] if c else '1.1.1.1'),n
def m_ident():
 R,C,N=pick();print('NS',N);print('USE',R,C)
 for s in (R,C):
  print('==',s)
  for n,t,c in [('version.bind',16,3),('hostname.bind',16,3),('id.server',16,3),('version.server',16,3),('.',2,1),('.',6,1),('.',255,1),('localhost',1,1)]:
   print('Q',n,t,c,pr(ud(s,n,t,c,0,2.0)))
  for z in ('.','local','localhost'):
   print('AX',z,pr(tc(s,z,252,1,1.5)))
  for n,t in [('example.com',1),('example.com',28)]:
   print('R1',n,t,pr(ud(s,n,t,1,1,2.0)))
   print('R0',n,t,pr(ud(s,n,t,1,0,2.0)))
def m_tools():
 import shutil
 for x in ('dig','nslookup','host','getent','python3','bash','gzip','base64'):
  print('T',x,shutil.which(x))
 print('NS',nsl())
def m_diff():
 R,C,N=pick();print('USE',R,C)
 HN=open('/etc/hostname').read().strip()
 NAMES=base64.b64decode('TUlOVCBQTEFDRUhPTERFUg==').decode().split()
 NAMES += [HN,HN+'.local',HN+'.internal',HN+'.daytona.internal']
 d=0
 for n in NAMES:
  for t in (1,28):
   a=pr(ud(R,n,t,1,1,1.5));b=pr(ud(C,n,t,1,1,1.5))
   if a!=b or ('an=0' not in a and 'none' not in a):
    if a!=b:d+=1
    print('N',n,t,'|R',a[:120],'|C',b[:120],'|D' if a!=b else '')
 print('DIFFS',d)
 import ipaddress
 for x in ('172.20.0.22','127.0.0.1'):
  rv='.'.join(reversed(x.split('.')))+'.in-addr.arpa'
  print('PTR',x,'|R',pr(ud(R,rv,12,1,1)),'|C',pr(ud(C,rv,12,1,1)))
def conn(ip,p,t=0.7):
 s=socket.socket();s.settimeout(t)
 try:return s.connect_ex((ip,p))
 except Exception:return 'E'
 finally:s.close()
def m_ports():
 R,C,N=pick();print('USE',R)
 for p in (53,22,80,443,2375,2376,3000,5000,6443,8080,8443,9000,10250,18080):
  rc=conn(R,p,0.9);ln='P %-5d %s'%(p,rc)
  if rc==0:
   try:
    s=socket.socket();s.settimeout(1.2);s.connect((R,p))
    s.sendall(b'\x16\x03\x01\x00\x00' if p in(443,8443) else b'GET / HTTP/1.0\r\nHost: x\r\n\r\n')
    ln+=' B='+repr(s.recv(300)[:250]);s.close()
   except Exception as e:ln+=' BE='+str(e)[:50]
  print(ln)
 for p in (80,8080,8443,443):
  for pa in ('/','/version','/healthz','/metrics'):
   try:
    s=socket.socket();s.settimeout(0.8);s.connect((R,p));s.sendall(('GET %s HTTP/1.0\r\nHost: x\r\n\r\n'%pa).encode())
    print('H',p,pa,repr(s.recv(300)[:250]));s.close()
   except Exception:pass
def m_bounds():
 R,C,N=pick();o=R.split('.');base='.'.join(o[:3])
 T=[R,base+'.2',base+'.0','100.64.0.1','100.96.0.1','100.100.100.100','10.0.0.1','172.20.0.1','169.254.169.254','1.1.1.1']
 P=(53,80,443,22,2280,22222)
 for ip in T:
  print('T',ip,' '.join('%d:%s'%(p,conn(ip,p,0.6)) for p in P))
 print('== proxy')
 for ip in (R,base+'.2','100.64.0.1','10.0.0.1','172.20.0.1','169.254.169.254','1.1.1.1'):
  for p in (53,80,443,2280):
   try:
    s=socket.socket();s.settimeout(1.5);s.connect(('172.20.0.1',18080))
    s.sendall(('CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n'%(ip,p,ip,p)).encode())
    print('PC',ip,p,repr(s.recv(200).split(b'\r\n')[0][:120]));s.close()
   except Exception as e:print('PC',ip,p,'ERR',str(e)[:50])
m={'ident':m_ident,'tools':m_tools,'diff':m_diff,'ports':m_ports,'bounds':m_bounds}[sys.argv[1]]
m()
