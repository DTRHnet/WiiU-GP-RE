#!/bin/bash
# Round 4: relink libdrc with correct library order, then drcvncclient.
OUT=/work/out; LOG=$OUT/logs; mkdir -p "$LOG"
step(){ echo; echo "=============== $* ==============="; }

step "libdrc relink (libs after objects)"
( cd /work/pc2drc/libdrc-vnc/libdrc-thefloppydriver && rm -f libdrc.so && \
  PKG_CONFIG_PATH="$OUT/x264/lib/pkgconfig" make -j"$(nproc)" > "$LOG/libdrc-make4.log" 2>&1 && \
  make install > "$LOG/libdrc-install4.log" 2>&1 )
echo "libdrc exit=$?"
echo "--- DT_NEEDED on libdrc.so ---"
readelf -d "$OUT/libdrc/lib/libdrc.so" 2>/dev/null | grep NEEDED

step "drcvncclient link"
( cd /work/pc2drc/libdrc-vnc/drcvncclient && \
  PKG_CONFIG_PATH="$OUT/libdrc/lib/pkgconfig:$OUT/x264/lib/pkgconfig" \
  make -j"$(nproc)" > "$LOG/vncclient-make4.log" 2>&1 )
echo "drcvncclient exit=$?"
grep -E "error:|undefined reference" "$LOG/vncclient-make4.log" 2>/dev/null | head -5

step "artefacts"
for b in "$OUT/libdrc/lib/libdrc.so" "$OUT/bin/bin/drcvncclient"; do
  [ -f "$b" ] && { echo "  BUILT  $b"; file -b "$b" | cut -c1-70; } || echo "  MISSING $b"
done
chown -R 1000:1000 /work/out 2>/dev/null
