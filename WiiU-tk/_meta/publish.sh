#!/usr/bin/env bash
# publish.sh — the ONLY safe way to commit/push this repository.
#
# Why this exists:
#   WiiU-tk/ is a curated mirror of a live workspace. Another tool or agent may
#   regenerate it at any time from files that still contain the real console
#   credentials (e.g. SETUP.md, out/evidence/decrypt_h264.py). A .gitignore can
#   only exclude *paths*, so it cannot stop a regenerated file from reintroducing
#   a secret under an allowed path. Redaction therefore has to happen at the
#   publish boundary, every time, right before the commit.
#
# What it does, in order:
#   1. redact          replace credential material (BLOCK patterns) in text files
#   2. strip           remove binary diffs from patch files (compiled third-party code)
#   3. audit           run _meta/prepublish-audit.sh; abort on any FAIL
#   4. commit[/push]   only if the audit is clean
#
# Usage:
#   bash WiiU-tk/_meta/publish.sh                  # redact + audit + commit
#   bash WiiU-tk/_meta/publish.sh --push           # ...then push to origin
#   bash WiiU-tk/_meta/publish.sh --check          # redact + audit, no commit
set -uo pipefail

cd "$(dirname "$0")/../.." || exit 2
ROOT=$(pwd)
DENY="$ROOT/WiiU-tk/_meta/.private-deny-patterns"
DO_PUSH=0
CHECK_ONLY=0
for a in "$@"; do
  case "$a" in
    --push)  DO_PUSH=1 ;;
    --check) CHECK_ONLY=1 ;;
    *) echo "unknown arg: $a" >&2; exit 2 ;;
  esac
done

echo "== 1/4 redact credential material =="
if [ ! -f "$DENY" ]; then
  echo "  ERROR: $DENY missing — refusing to publish unredacted." >&2
  echo "  Create it with the BLOCK: patterns for your console's PSK." >&2
  exit 1
fi

python3 - "$DENY" <<'PY'
import sys, os, subprocess, re

deny = sys.argv[1]
block = [l.split(":", 1)[1].strip()
         for l in open(deny) if l.startswith("BLOCK:") and l.split(":", 1)[1].strip()]
block = [b for b in block if len(b) >= 16]
if not block:
    print("  no BLOCK patterns; nothing to redact")
    raise SystemExit(0)

tracked = subprocess.run(["git", "ls-files"], capture_output=True, text=True).stdout.split()
TEXT_EXT = {".md", ".sh", ".py", ".c", ".cpp", ".h", ".txt", ".tsv", ".json", ".yaml", ".yml", ".conf", ".patch", ".diff"}
changed = 0
for f in tracked:
    if not os.path.isfile(f):
        continue
    if os.path.splitext(f)[1] not in TEXT_EXT:
        continue
    try:
        data = open(f, "r", encoding="utf-8", errors="strict").read()
    except (UnicodeDecodeError, OSError):
        continue
    orig = data
    for b in block:
        if b in data:
            # A bare `PSK=<hex>` becomes `PSK=<redacted>`; a quoted hex literal in
            # code becomes a placeholder that still parses but fails closed.
            data = data.replace('"%s"' % b, '"<redacted-psk>"')
            data = data.replace("'%s'" % b, '"<redacted-psk>"')
            data = data.replace(b, "<redacted-psk>")
    if data != orig:
        open(f, "w", encoding="utf-8").write(data)
        print("  redacted: %s" % f)
        changed += 1
print("  %d file(s) redacted" % changed)
PY
RC=$?; [ $RC -ne 0 ] && { echo "redaction failed" >&2; exit $RC; }

echo
echo "== 2/4 strip binary diffs from patches =="
python3 - <<'PY'
import subprocess, os, re
tracked = [f for f in subprocess.run(["git", "ls-files"], capture_output=True, text=True).stdout.split()
           if f.endswith((".patch", ".diff"))]
for f in tracked:
    if not os.path.isfile(f):
        continue
    text = open(f, encoding="utf-8", errors="replace").read()
    if "GIT binary patch" not in text and "Binary files " not in text:
        continue
    # Split into per-file diff blocks and drop any block that carries binary data.
    blocks = re.split(r"(?m)^(?=diff --git )", text)
    kept, dropped = [], []
    for b in blocks:
        if "GIT binary patch" in b or re.search(r"(?m)^Binary files .* differ$", b):
            m = re.match(r"diff --git a/(\S+)", b)
            dropped.append(m.group(1) if m else "?")
        else:
            kept.append(b)
    open(f, "w", encoding="utf-8").write("".join(kept))
    print("  stripped %d binary diff block(s) from %s: %s" % (len(dropped), f, ", ".join(dropped)))
PY

echo
echo "== 3/4 audit =="
if ! bash "$ROOT/WiiU-tk/_meta/prepublish-audit.sh"; then
  echo >&2
  echo "ABORT: audit failed. Nothing committed. Fix the FAIL lines above." >&2
  exit 1
fi

[ "$CHECK_ONLY" -eq 1 ] && { echo; echo "check-only: audit clean, not committing."; exit 0; }

echo
echo "== 4/4 commit =="
git add -A
if git diff --cached --quiet; then
  echo "  nothing to commit"
else
  git commit -q -m "Publish WiiU-GP-RE: redacted and audited

Credential material redacted at the publish boundary and binary diff
hunks stripped before commit; prepublish-audit passed." || exit 1
  echo "  committed $(git log --oneline -1)"
fi

if [ "$DO_PUSH" -eq 1 ]; then
  git push -u origin HEAD || exit 1
  echo "  pushed"
fi
