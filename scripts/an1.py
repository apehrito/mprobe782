import sys, os
def hx(b):
    return b.hex()
def dump(path, depth=0):
    try:
        if os.path.isdir(path):
            print("### DIR", path)
            try:
                names = sorted(os.listdir(path))
            except Exception as e:
                print("  ERR list", e); return
            for name in names:
                p = os.path.join(path, name)
                try:
                    st = os.lstat(p)
                    print("  ", name, st.st_size, oct(st.st_mode))
                except Exception as e:
                    print("  ", name, "ERR", e)
            if depth < 1:
                for name in names:
                    p = os.path.join(path, name)
                    try:
                        if os.path.isfile(p) and os.path.getsize(p) <= 4096:
                            b = open(p, 'rb').read()
                            print("### SUBFILE", p, "len", len(b))
                            print(hx(b))
                    except Exception as e:
                        print("### SUBERR", p, e)
        else:
            b = open(path, 'rb').read()
            print("### FILE", path, "len", len(b))
            print(hx(b)[:12000])
    except Exception as e:
        print("### ERR", path, repr(e))
for a in sys.argv[1:]:
    dump(a)
