#!/usr/bin/env python3
"""Inject admin privileges into JSON responses.

Replaces the original server response with a JSON body containing
admin: true and role: superadmin. If the incoming request has a JSON
body, it is used as the base and modified. Otherwise a minimal admin
response is generated.

Use case: override frontend privilege/role checks during pentesting.

Usage:
    In Response Forger, set mode to Script and point to this file.
"""
import sys
import base64
import json

raw = base64.b64decode(sys.stdin.read()).decode("utf-8", errors="replace")

# Try to use request JSON body as base (e.g. POST with JSON payload)
data = {}
try:
    parts = raw.split("\r\n\r\n", 1)
    if len(parts) > 1 and parts[1].strip():
        parsed = json.loads(parts[1])
        if isinstance(parsed, dict):
            data = parsed
except ValueError:
    pass

data["admin"] = True
data["role"] = "superadmin"

body = json.dumps(data, indent=2)
sys.stdout.write(
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: %d\r\n"
    "Access-Control-Allow-Origin: *\r\n"
    "\r\n"
    "%s" % (len(body), body)
)
