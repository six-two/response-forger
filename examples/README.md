# Response Forger - Example Scripts

Sample Python 3 scripts for Response Forger's Script mode.

## Scripts

### echo_request.py

Echoes the incoming request details (method, path, headers) back as a JSON response. Useful for debugging what Response Forger sends to scripts and verifying the script-mode pipeline works.

### inject_admin.py

Returns a JSON response with `{"admin": true, "role": "superadmin"}`. If the original request has a JSON body, it is used as the base and the admin fields are injected into it. The most common use case - override frontend privilege/role checks during pentesting.

### serve_local_file.py

Serves a local file as an HTTP response with the correct Content-Type header. Use case: replace a remote JavaScript or CSS file with a locally modified copy.

In Response Forger's script-path field, add the file path as an argument:

```
/path/to/serve_local_file.py /path/to/modified-app.js
```

## How Script Mode Works

1. Response Forger matches a request URL (and optional method/header filters) to your rule
2. The extension runs your script: `python3 <script> [args...]`
3. The full HTTP request is sent to stdin as base64
4. Your script writes the full HTTP response to stdout
5. Response Forger uses your output as the forged response

Scripts must write a complete HTTP response including the status line:

```
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 42

{"result": "your response body here"}
```

If the script exits with a non-zero code or produces no output, the original server response passes through unchanged. Errors are logged to Burp's extension output.

Scripts are killed after 10 seconds to prevent hangs.
