#!/usr/bin/env python3
"""Tiny one-shot HTTP receiver: collects the Pi's self-test report.

The Pi's test script takes wlan0 over as a 5 GHz AP (which kills SSH), runs its
checks, restores networking and then POSTs the log here. This keeps the evidence
even though we cannot watch it happen.
"""
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

OUT = "/home/kali/Wiiu/pi-report.log"


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        data = self.rfile.read(n)
        with open(OUT, "ab") as f:
            f.write(f"\n########## POST {self.client_address[0]} {self.path}\n".encode())
            f.write(data)
        print(f"[receiver] got {n} bytes from {self.client_address[0]}", flush=True)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
    open(OUT, "wb").close()
    print(f"[receiver] listening on 0.0.0.0:{port} -> {OUT}", flush=True)
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()
