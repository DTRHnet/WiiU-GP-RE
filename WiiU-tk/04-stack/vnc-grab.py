#!/usr/bin/env python3
"""Minimal RFB (VNC) client: handshake, read one raw framebuffer update, save PPM.

Proves the display half of the pipeline - that the Kali desktop is capturable
over VNC at the size drcvncclient will consume - without needing a GamePad.
"""
import socket, struct, sys

host, port = sys.argv[1], int(sys.argv[2])
out = sys.argv[3]

s = socket.create_connection((host, port), timeout=10)
f = s.makefile("rb")

# --- handshake ---
ver = f.read(12)
print("  server version:", ver.decode().strip())
s.sendall(b"RFB 003.008\n")

n = f.read(1)[0]
types = list(f.read(n))
print("  security types offered:", types)
if 1 not in types:
    print("  no 'None' security - aborting"); sys.exit(1)
s.sendall(b"\x01")                      # choose None
res = struct.unpack("!I", f.read(4))[0]
print("  security result:", "OK" if res == 0 else f"FAILED({res})")
if res != 0:
    sys.exit(1)

s.sendall(b"\x01")                      # ClientInit, shared

# --- ServerInit ---
w, h = struct.unpack("!HH", f.read(4))
pf = f.read(16)
name = f.read(struct.unpack("!I", f.read(4))[0])
print(f"  framebuffer: {w}x{h}   name={name.decode(errors='replace')!r}")

# --- ask for 32bpp truecolour, raw encoding only ---
# bits_per_pixel=32 depth=24 bigendian=0 truecolor=1 rmax gmax bmax  rshift gshift bshift
fmt = struct.pack("!BBBBHHHBBB3x", 32, 24, 0, 1, 255, 255, 255, 16, 8, 0)
s.sendall(struct.pack("!B3x", 0) + fmt)                         # SetPixelFormat (20 bytes)
s.sendall(struct.pack("!BBH", 2, 0, 1) + struct.pack("!i", 0))  # SetEncodings: Raw
s.sendall(struct.pack("!BBHHHH", 3, 0, 0, 0, w, h))            # FramebufferUpdateRequest

# --- read messages until we get a framebuffer update ---
while True:
    mtype = f.read(1)[0]
    if mtype == 1:                                  # SetColourMapEntries
        f.read(3); ncol = struct.unpack("!H", f.read(2))[0]; f.read(6 * ncol)
        continue
    if mtype == 2:                                  # Bell
        continue
    if mtype != 0:                                  # 0 = FramebufferUpdate
        print("  unexpected message type", mtype); sys.exit(1)
    f.read(1)
    nrect = struct.unpack("!H", f.read(2))[0]
    canvas = bytearray(b"\x00" * (w * h * 3))
    for _ in range(nrect):
        x, y, rw, rh, enc = struct.unpack("!HHHHi", f.read(12))
        if enc != 0:
            print("  non-raw encoding", enc, "- aborting"); sys.exit(1)
        data = f.read(rw * rh * 4)
        for row in range(rh):
            src = row * rw * 4
            dst = ((y + row) * w + x) * 3
            for col in range(rw):
                b, g, r = data[src + col*4], data[src + col*4 + 1], data[src + col*4 + 2]
                canvas[dst + col*3]     = r
                canvas[dst + col*3 + 1] = g
                canvas[dst + col*3 + 2] = b
    break

with open(out, "wb") as fp:
    fp.write(b"P6\n%d %d\n255\n" % (w, h))
    fp.write(canvas)
print(f"  wrote {out} ({w}x{h}, {len(canvas)} bytes)")
