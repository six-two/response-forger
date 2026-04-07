#!/usr/bin/env python3
"""Unit tests for Response Forger's response-building logic.

Run: python3 test_response_forger.py
Tests _normalize_crlf, _recalc_content_length, _update_date_header without Burp/Jython.
"""
import re
import sys
import time

# --- Copy the pure functions from response_forger.py ---

def _recalc_content_length(response_str):
    idx = response_str.find("\r\n\r\n")
    if idx >= 0:
        header_block = response_str[:idx]
        body = response_str[idx + 4:]
        sep = "\r\n"
    else:
        idx = response_str.find("\n\n")
        if idx >= 0:
            header_block = response_str[:idx]
            body = response_str[idx + 2:]
            sep = "\n"
        else:
            return response_str
    body_len = len(body)
    lines = header_block.split(sep)
    out = []
    found = False
    for line in lines:
        if line.lower().startswith("content-length:"):
            out.append("Content-Length: %d" % body_len)
            found = True
        else:
            out.append(line)
    if not found:
        out.append("Content-Length: %d" % body_len)
    return sep.join(out) + sep + sep + body


def _normalize_crlf(response_str):
    crlf_idx = response_str.find("\r\n\r\n")
    lf_idx = response_str.find("\n\n")

    if crlf_idx >= 0 and (lf_idx < 0 or crlf_idx <= lf_idx):
        headers = response_str[:crlf_idx]
        body = response_str[crlf_idx + 4:]
    elif lf_idx >= 0:
        headers = response_str[:lf_idx]
        body = response_str[lf_idx + 2:]
    else:
        return response_str.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")

    headers = headers.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")
    return headers + "\r\n\r\n" + body


def _update_date_header(response_str):
    idx = response_str.find("\r\n\r\n")
    if idx < 0:
        return response_str
    headers = response_str[:idx]
    body = response_str[idx + 4:]
    now = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
    lines = headers.split("\r\n")
    out = []
    for line in lines:
        if line.lower().startswith("date:"):
            out.append("Date: " + now)
        else:
            out.append(line)
    return "\r\n".join(out) + "\r\n\r\n" + body


# --- Simulate _build_static logic ---

STATUS_REASONS = {"200": "OK", "404": "Not Found"}

def _build_static(response_text, status_code="200"):
    resp = response_text
    if not resp:
        return None
    if not resp.startswith("HTTP/"):
        reason = STATUS_REASONS.get(status_code, "OK")
        resp = "HTTP/1.1 %s %s\r\n\r\n%s" % (status_code, reason, resp)
    else:
        resp = _normalize_crlf(resp)
    return _recalc_content_length(resp)


# --- Tests ---

passed = 0
failed = 0

def check(name, got, expected):
    global passed, failed
    if got == expected:
        passed += 1
        print("  PASS: %s" % name)
    else:
        failed += 1
        print("  FAIL: %s" % name)
        print("    expected: %r" % expected)
        print("    got:      %r" % got)

def check_match(name, got, pattern):
    global passed, failed
    if re.search(pattern, got):
        passed += 1
        print("  PASS: %s" % name)
    else:
        failed += 1
        print("  FAIL: %s" % name)
        print("    pattern: %r" % pattern)
        print("    got:     %r" % got)


print("=== Test _normalize_crlf ===")

# Response with LF only (as JTextArea would produce)
lf_resp = "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"admin\": true}"
normalized = _normalize_crlf(lf_resp)
check(
    "LF-only response gets CRLF headers",
    normalized,
    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"admin\": true}"
)

# Response already with CRLF (no change needed)
crlf_resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>hi</h1>"
check("CRLF response unchanged", _normalize_crlf(crlf_resp), crlf_resp)

# Mixed line endings
mixed_resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\nX-Custom: foo\r\n\r\n<body>"
normalized = _normalize_crlf(mixed_resp)
expected = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Custom: foo\r\n\r\n<body>"
check("Mixed CRLF/LF normalized to CRLF", normalized, expected)

# Body with LF should be preserved as-is
lf_body = "HTTP/1.1 200 OK\n\nline1\nline2\nline3"
normalized = _normalize_crlf(lf_body)
check(
    "Body LF preserved (not converted to CRLF)",
    normalized,
    "HTTP/1.1 200 OK\r\n\r\nline1\nline2\nline3"
)


print("\n=== Test _recalc_content_length ===")

# CRLF response - adds Content-Length
resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nhello"
result = _recalc_content_length(resp)
check(
    "Adds Content-Length for CRLF response",
    result,
    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nhello"
)

# LF response - also works
resp_lf = "HTTP/1.1 200 OK\nContent-Type: text/html\n\nhello"
result = _recalc_content_length(resp_lf)
check(
    "Adds Content-Length for LF response",
    result,
    "HTTP/1.1 200 OK\nContent-Type: text/html\nContent-Length: 5\n\nhello"
)

# Updates existing Content-Length
resp = "HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\nhi"
result = _recalc_content_length(resp)
check(
    "Updates wrong Content-Length",
    result,
    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
)


print("\n=== Test _update_date_header ===")

# Stale Date header gets updated to current time
stale = "HTTP/1.1 200 OK\r\nDate: Tue, 01 Jan 2019 00:00:00 GMT\r\nContent-Type: text/html\r\n\r\nhi"
result = _update_date_header(stale)
now_year = time.strftime("%Y", time.gmtime())
check_match(
    "Stale Date replaced with current year",
    result,
    r"Date: \w{3}, \d{2} \w{3} " + now_year
)
check(
    "Rest of response preserved after Date update",
    result.endswith("Content-Type: text/html\r\n\r\nhi"),
    True
)

# No Date header - response untouched
no_date = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nhi"
check("No Date header stays untouched", _update_date_header(no_date), no_date)

# No CRLF boundary - response untouched
no_boundary = "HTTP/1.1 200 OK"
check("No header boundary stays untouched", _update_date_header(no_boundary), no_boundary)


print("\n=== Test _build_static (full pipeline) ===")

# Body-only input (user pastes just the body)
result = _build_static('{"admin": true}')
check(
    "Body-only gets status line + Content-Length",
    result,
    'HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\n{"admin": true}'
)

# Full HTTP response with LF (JTextArea corruption scenario)
lf_full = "HTTP/1.1 200 OK\nContent-Type: application/json\nContent-Length: 999\n\n{\"forged\": true}"
result = _build_static(lf_full)
check(
    "LF full response -> CRLF headers + correct Content-Length",
    result,
    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 16\r\n\r\n{\"forged\": true}"
)

# Full HTTP response already correct
correct = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\ntest"
result = _build_static(correct)
check(
    "Correct CRLF response stays correct",
    result,
    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n\r\ntest"
)

# Empty response returns None
check("Empty response returns None", _build_static(""), None)

# 404 status code
result = _build_static("Not Found", "404")
check(
    "Custom status code applied",
    result,
    "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found"
)


print("\n=== Results ===")
print("%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
