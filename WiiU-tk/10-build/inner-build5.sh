#!/bin/bash
# Round 5: build libx264 as a SHARED lib (proper PIC + DT_NEEDED), so libdrc
# carries a real dependency instead of relying on undefined symbols.
OUT=/work/out; LOG=$OUT/logs; mkdir -p "$LOG"
step(){ echo; echo "=============== $* ==============="; }

step "x264 shared+static"
( cd /work/pc2drc/drc-x264 && make clean > /dev/null 2>&1
  ./configure --prefix="$OUT/x264" --enable-shared --enable-static --disable-cli --enable-pic > "$LOG/x264-conf5.log" 2>&1 &&
  make -j"$(nproc)" > "$LOG/x264-make5.log" 2>&1 &&
  make install > "$LOG/x264-install5.log" 2>&1 )
echo "x264 exit=$?"; ls -1 "$OUT/x264/lib"/*.so* 2>/dev/null | head -3

step "libdrc relink against shared x264"
( cd /work/pc2drc/libdrc-vnc/libdrc-thefloppydriver && rm -f libdrc.so
  PKG_CONFIG_PATH="$OUT/x264/lib/pkgconfig" make -j"$(nproc)" > "$LOG/libdrc-make5.log" 2>&1 &&
  make install > "$LOG/libdrc-install5.log" 2>&1 )
echo "libdrc exit=$?"
echo "--- DT_NEEDED ---"; readelf -d "$OUT/libdrc/lib/libdrc.so" 2>/dev/null | grep NEEDED

step "drcvncclient"
( cd /work/pc2drc/libdrc-vnc/drcvncclient && make clean > /dev/null 2>&1
  PKG_CONFIG_PATH="$OUT/libdrc/lib/pkgconfig:$OUT/x264/lib/pkgconfig" \
  make -j"$(nproc)" LDFLAGS="-L$OUT/x264/lib -L$OUT/libdrc/lib -Wl,-rpath-link,$OUT/x264/lib" \
  > "$LOG/vncclient-make5.log" 2>&1 )
echo "drcvncclient exit=$?"
grep -E "error:|undefined reference" "$LOG/vncclient-make5.log" 2>/dev/null | head -5

step "artefacts"
for b in "$OUT/libdrc/lib/libdrc.so" "$OUT/bin/bin/drcvncclient"; do
  [ -f "$b" ] && echo "  BUILT  $b" || echo "  MISSING $b"
done
chown -R 1000:1000 /work/out 2>/dev/null
