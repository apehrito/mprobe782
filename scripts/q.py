import socket,struct,random,sys
def q(s,name,t=1,c=1,rd=1):
 p=struct.pack('!HHHHHH',random.randrange(65535),0x100*rd,1,0,0,0)
 for l in name.split('.'):p+=bytes([len(l)])+l.encode()
 p+=b'\0'+struct.pack('!HH',t,c)
 s.sendto(p,(sys.argv[1],53));d=s.recv(2048)
 f=struct.unpack('!H',d[2:4])[0];an=struct.unpack('!H',d[6:8])[0]
 o=12
 while d[o]:o+=1+d[o]
 o+=5;r=[]
 for _ in range(an):
  while d[o]&192!=192 and d[o]:o+=1+d[o]
  o+=2 if d[o]&192==192 else 1
  ty,cl,ttl,dl=struct.unpack('!HHIH',d[o:o+10]);o+=10;v=d[o:o+dl];o+=dl
  if ty==1 and dl==4:v=socket.inet_ntoa(v)
  elif ty==5:v='cname'
  r.append('%d=%s'%(ty,v))
 return 'rc=%d n=%d %s'%(f&15,an,';'.join(r))
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2)
for n in sys.argv[2:]:
 try:print(n,q(s,n))
 except Exception as e:print(n,'ERR',e)
