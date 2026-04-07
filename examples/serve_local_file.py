#!/usr/bin/env python3
"""Serve a local file as an HTTP response.

Reads a file from disk and returns it with the correct Content-Type.
Use case: replace a remote JS/CSS file with a locally modified copy.

Usage in Response Forger script-path field:
    /path/to/serve_local_file.py /path/to/modified-app.js

The first argument after the script path is the file to serve.
"""
import sys
import os
import mimetypes

if len(sys.argv) < 2:
    sys.stderr.write("Usage: serve_local_file.py <file_path>\n")
    sys.exit(1)

file_path = sys.argv[1]
if not os.path.isfile(file_path):
    sys.stderr.write("File not found: %s\n" % file_path)
    sys.exit(1)

# Read stdin (required by Response Forger protocol) but discard it
sys.stdin.read()

with open(file_path, "rb") as f:
    content = f.read()

content_type = mimetypes.guess_type(file_path)[0] or "application/octet-stream"

header = (
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: %s\r\n"
    "Content-Length: %d\r\n"
    "\r\n"
) % (content_type, len(content))

sys.stdout.buffer.write(header.encode("utf-8") + content)
