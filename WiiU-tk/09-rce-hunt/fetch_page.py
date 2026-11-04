#!/usr/bin/env python3
"""Fetch a doku-wiki page and dump its plain text (read-only, no writes to repo).

Usage: dokuwiki_text.py <url> [maxchars]
"""
import html
import re
import subprocess
import sys

url = sys.argv[1]
maxc = int(sys.argv[2]) if len(sys.argv) > 2 else 20000
raw = subprocess.run(
    ["curl", "-sL", "-A", "Mozilla/5.0", url],
    capture_output=True, text=True, timeout=60).stdout
s = raw
s = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", "", s)
m = re.search(r'(?is)<div class="dokuwiki.*?>(.*?)<div class="docInfo"', s)
if not m:
    m = re.search(r'(?is)<div id="mw-content-text".*?>(.*?)<div class="printfooter"', s)
body = m.group(1) if m else s
body = re.sub(r"(?is)<br\s*/?>", "\n", body)
body = re.sub(r"(?is)</(p|div|li|tr|h[1-6]|pre|dt|dd)>", "\n", body)
body = re.sub(r"(?is)<(td|th)[^>]*>", " | ", body)
body = re.sub(r"(?is)<[^>]+>", "", body)
body = html.unescape(body)
body = re.sub(r"[ \t]+\n", "\n", body)
body = re.sub(r"\n{3,}", "\n\n", body)
print(body.strip()[:maxc])
