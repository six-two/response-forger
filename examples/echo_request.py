#!/usr/bin/env python3
"""Echo request details back as a JSON response.

Response Forger script-mode example. Receives the full HTTP request
as base64 on stdin, parses it, and returns a JSON response containing
the request method, path, and headers.

Usage:
    In Response Forger, set mode to Script and point to this file.
"""
import sys
import base64
import json

raw = base64.b64decode(sys.stdin.read()).decode("utf-8", errors="replace")
lines = raw.split("\r\n")

request_line = lines[0] if lines else ""
parts = request_line.split(" ", 2)
method = parts[0] if len(parts) > 0 else ""
path = parts[1] if len(parts) > 1 else ""

headers = {}
for line in lines[1:]:
    if not line:
        break
    if ":" in line:
        key, val = line.split(":", 1)
        headers[key.strip()] = val.strip()

body = json.dumps({
    "echo": True,
    "method": method,
    "path": path,
    "headers": headers,
}, indent=2)

sys.stdout.write(
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: %d\r\n"
    "\r\n"
    "%s" % (len(body), body)
)
