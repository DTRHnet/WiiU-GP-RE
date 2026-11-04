#!/usr/bin/env python3
"""generate-inventory.py - rebuild INVENTORY.md, MANIFEST.sha256 and
_meta/source-map.tsv for the WiiU-tk toolkit.

Every file in the toolkit is fingerprinted (sha256, size, lines) and matched back
to the workspace it was collected from, so the copy is auditable: re-run this and
diff the manifests to see whether the toolkit still matches its source tree.

Usage:
    ./generate-inventory.py [--workspace DIR] [--toolkit DIR]

Defaults: toolkit = the parent of this script's directory, workspace = /home/kali/Wiiu.
Read-only against the workspace; writes only inside the toolkit.
"""
import argparse
import ast
import hashlib
import os
import re
import sys

SKIP_DIRS = {
    ".git", "__pycache__", "hostap-2.12", "linux-source-7.1", "drc-hostap",
    "libdrc", "wozt-libdrc", "barista-ref", "deps", "extract", "kd", "ks",
}
TEXT_EXT = {
    ".md", ".txt", ".py", ".sh", ".c", ".cpp", ".h", ".patch", ".tsv", ".log",
    ".conf", ".env", ".service", ".yml", ".yaml", ".json", ".in", ".cfg",
}
INDEX_EXT = TEXT_EXT | {".bin"}  # .bin dumps are small enough to fingerprint
# Files that are derived (not copied) and therefore have no byte-identical source.
DERIVED = {
    "11-patches/pc2drc-local-work.patch":
        "generated: cd pc2drc && git diff (tracked+intent-to-add changes vs d979... upstream HEAD)",
    "11-patches/pc2drc-local-work.diffstat.txt":
        "generated: cd pc2drc && git diff --stat",
    "README.md": "authored for this toolkit (index of the collection; not a copy)",
    "MANIFEST.sha256": "generated: _meta/generate-inventory.py",
    "INVENTORY.md": "generated: _meta/generate-inventory.py",
}
MAX_HASH_BYTES = 2 * 1024 * 1024  # skip multi-MB captures when indexing sources


def sha256(path, limit=None):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def count_lines(path):
    try:
        with open(path, "rb") as f:
            return sum(1 for _ in f)
    except OSError:
        return 0


def first_sentence(text):
    """Normalise a header line without destroying hyphens or slashes in names."""
    text = re.sub(r"^[\s*/#!]+", "", text)
    text = re.sub(r"\s*\*/$", "", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def summary(path):
    ext = os.path.splitext(path)[1].lower()
    name = os.path.basename(path)
    if name == "Dockerfile" or ext == ".patch":
        ext = ext or ".patch"
    if ext not in TEXT_EXT and name != "Dockerfile":
        size = os.path.getsize(path)
        return "binary/asset, %d bytes" % size
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            head = f.read(6000)
    except OSError:
        return "(unreadable)"
    if ext == ".py":
        try:
            doc = ast.get_docstring(ast.parse(head))
            if doc:
                return first_sentence(doc.splitlines()[0])[:200]
        except SyntaxError:
            pass
    if ext in (".sh", ".py", ".c", ".cpp"):
        for line in head.splitlines()[1:40]:
            line = line.strip()
            if ext in (".c", ".cpp"):
                m = re.match(r"^(?://|/\*|\*)\s*(.+?)\s*(?:\*/)?$", line)
            elif ext == ".py":
                m = re.match(r"^#\s*(.+)$", line)
            else:
                m = re.match(r"^#\s*(.+)$", line)
            if not m:
                continue
            body = m.group(1).strip()
            if not body or re.match(r"^[-=*]{3,}$", body.lower()):
                continue
            if body.lower().startswith(("usage:", "usage ", "example", "set -", "sudo ")):
                continue
            return first_sentence(body)[:200]
    if ext == ".md":
        for line in head.splitlines():
            if line.startswith("# "):
                return line[2:].strip()[:200]
    if ext == ".patch":
        for line in head.splitlines():
            if line.startswith("Subject:"):
                return first_sentence(line[8:])[:200]
        touched = [l.split(" b/", 1)[-1] for l in head.splitlines()
                   if l.startswith("diff --git ")]
        if touched:
            return "git diff: %d file(s), first %s" % (len(touched), touched[0])
    if ext in (".txt", ".tsv", ".log"):
        for line in head.splitlines():
            line = line.strip()
            if line:
                return first_sentence(line)[:160]
    return ""


def index_workspace(workspace, toolkit):
    """sha256 -> [relative paths] for likely source files in the workspace."""
    index = {}
    tk_name = os.path.relpath(toolkit, workspace).split(os.sep)[0]
    for root, dirs, files in os.walk(workspace):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        rel_root = os.path.relpath(root, workspace)
        if rel_root.split(os.sep)[0] == tk_name:
            dirs[:] = []          # never index the toolkit itself
            continue
        for f in files:
            p = os.path.join(root, f)
            ext = os.path.splitext(f)[1].lower()
            if ext not in INDEX_EXT and f != "Dockerfile":
                continue
            try:
                if os.path.getsize(p) > MAX_HASH_BYTES:
                    continue
                digest = sha256(p)
            except OSError:
                continue
            index.setdefault(digest, []).append(os.path.relpath(p, workspace))
    return index


def walk_toolkit(toolkit):
    rows = []
    for root, dirs, files in os.walk(toolkit):
        dirs[:] = sorted(d for d in dirs if d not in {".git", "__pycache__"})
        for f in sorted(files):
            p = os.path.join(root, f)
            rel = os.path.relpath(p, toolkit)
            if rel in ("INVENTORY.md", "MANIFEST.sha256") or rel.startswith("_meta/"):
                continue
            rows.append(rel)
    return sorted(rows)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", default="/home/kali/Wiiu")
    ap.add_argument("--toolkit", default=os.path.dirname(here))
    args = ap.parse_args()

    toolkit = os.path.abspath(args.toolkit)
    workspace = os.path.abspath(args.workspace)

    index = index_workspace(workspace, toolkit) if os.path.isdir(workspace) else {}
    rows = walk_toolkit(toolkit)

    total_bytes = 0
    lines_out = []
    sha_lines = []

    for rel in rows:
        p = os.path.join(toolkit, rel)
        size = os.path.getsize(p)
        total_bytes += size
        digest = sha256(p)
        sha_lines.append("%s  %s" % (digest, rel))
        source = ""
        if index:
            matches = index.get(digest)
            if matches:
                source = matches[0]
                if len(matches) > 1:
                    source += " (+%d identical copies)" % (len(matches) - 1)
        purpose = DERIVED.get(rel) or summary(p)
        lines_out.append((rel, source, size, count_lines(p), purpose))

    with open(os.path.join(toolkit, "MANIFEST.sha256"), "w") as f:
        f.write("\n".join(sha_lines) + "\n")

    with open(os.path.join(here, "source-map.tsv"), "w") as f:
        f.write("# toolkit-relative path\tsource (workspace-relative)\tsha256\n")
        for rel, source, _size, _lines, _sum in lines_out:
            f.write("%s\t%s\t%s\n" % (rel, source, sha256(os.path.join(toolkit, rel))))

    with open(os.path.join(toolkit, "INVENTORY.md"), "w") as f:
        f.write("# WiiU-tk inventory\n\n")
        f.write("Generated by `_meta/generate-inventory.py` from this toolkit's own\n")
        f.write("contents; every row is matched back to the workspace it came from by\n")
        f.write("sha256, so this table is a provenance record, not a description.\n\n")
        f.write("- files: **%d**\n" % len(rows))
        f.write("- bytes: **%d**\n" % total_bytes)
        f.write("- workspace: `%s`\n\n" % workspace)
        f.write("Checksums: `MANIFEST.sha256` (`sha256sum -c MANIFEST.sha256`).\n")
        f.write("Machine-readable provenance: `_meta/source-map.tsv`.\n\n")
        current = None
        for rel, source, size, lines, summ in lines_out:
            parts = rel.split(os.sep)
            top = parts[0] if len(parts) > 1 else "toolkit root"
            if top != current:
                current = top
                f.write("\n## %s\n\n" % top)
                f.write("| file | lines | bytes | purpose | source |\n")
                f.write("|---|---|---|---|---|\n")
            leaf = parts[-1] if len(parts) == 1 else rel[len(top) + 1:]
            summ = (summ or "").replace("|", "\\|")
            if source:
                src = source.replace("|", "\\|")
            else:
                src = "*(generated here)*" if rel in DERIVED else "*unmatched*"
            f.write("| `%s` | %d | %d | %s | `%s` |\n" % (leaf, lines, size, summ, src))

    print("toolkit : %s" % toolkit)
    print("files   : %d" % len(rows))
    print("bytes   : %d" % total_bytes)
    print("workspace index: %d digests" % len(index))
    unmatched = [r for r, s, _z, _l, _m in lines_out if not s and r not in DERIVED]
    if unmatched:
        print("unmatched (no source copy found): %s" % ", ".join(unmatched))
    return 0


if __name__ == "__main__":
    sys.exit(main())
