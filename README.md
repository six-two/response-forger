# Response Forger

Burp Suite extension for overriding HTTP responses. Define URL patterns, provide replacement responses (static text or dynamic Python 3 scripts), and Burp swaps them in automatically.

## Changes in this fork

- When an request is intercepted, it does not get forwarded to upstream (and the answer gets ignored).
    Instead it is redirected to a local dummy web server.

Note: The changes are vibe coded, so maybe it is not the best approach.
But at least for my use case it worked pretty reliable.

## Features

- **Static response mode** - paste a response body, set a status code, done
- **Script mode** - run a Python 3 script that generates responses dynamically
- **Regex URL matching** - target specific endpoints with regular expressions
- **Conditional matching** - filter by HTTP method and request headers (regex)
- **Enable/disable rules** - toggle rules on/off without deleting them
- **Auto Content-Length** - header recalculated automatically for static responses
- **Auto Date header** - stale Date headers updated to current UTC time on every match
- **Duplicate dedup** - enabling a rule auto-disables other rules with the same URL pattern
- **Hit counter** - see how many times each rule fires
- **Import/Export** - share rule sets between engagements as JSON
- **Right-click integration** - send any request to Response Forger from HTTP history
- **Status code shortcut** - just paste the body and pick a status code
- **Sortable table** - click column headers to sort rules

## Installation

1. Download the [Jython standalone JAR](https://www.jython.org/download) (2.7.x)
2. In Burp Suite: Settings > Extensions > Python Environment > set the Jython JAR path
3. Extensions > Installed > Add > Extension Type: Python > select `response_forger.py`
4. A "Response Forger" tab appears in the main Burp window

## Usage

### Creating a Rule

1. Find a request in Burp's HTTP History
2. Right-click > **Send to Response Forger**
3. The URL pattern and response are pre-filled as a new rule
4. Edit the response body to what you want
5. Click **Save**

If your response body starts with `HTTP/`, it is used as a complete HTTP response (status code field is ignored). Otherwise the extension generates the status line for you.

Content-Length is recalculated automatically.

### Static Mode

Select a rule, edit the response body in the text area, set a status code, and click Save. The response is returned as-is for every matching request.

### Script Mode

1. Select a rule, switch mode to **Script (dangerous!)**
2. Enter the path to a Python 3 script (add arguments after the path, space-separated)
3. Click **Save**

When a matching request arrives, the extension runs the script and uses its stdout as the forged response. Script mode executes commands on the system - use with care.

**Script API:**

| Direction | Format |
|-----------|--------|
| **stdin** | Base64-encoded full HTTP request |
| **stdout** | Full HTTP response (status line + headers + `\r\n\r\n` + body) |
| **timeout** | 10 seconds (script is killed if it exceeds this) |
| **failure** | Non-zero exit code or empty stdout = original response passes through |

Use the **Test** button to run your script with a sample request and verify the output before enabling the rule. Use **Browse** to pick the script file.

**Example script path with arguments:**

```
/path/to/serve_local_file.py /path/to/modified-app.js
```

### Conditional Matching

Each rule can optionally filter on:

- **Method** - exact match (e.g. `GET`, `POST`). Leave blank to match all.
- **Header match** - regex applied to request headers. Leave blank to match all.

### Duplicate Rules

When you enable a rule and another rule with the same URL pattern is already enabled, the other rule is automatically disabled. This prevents ambiguity about which rule fires. Same applies when duplicating a rule or sending a new response from HTTP History.

### Import/Export

Click **Export** to save all rules as JSON. Click **Import** to load rules from a JSON file (duplicates by URL pattern are skipped).

## Sample Scripts

See the [`examples/`](examples/) folder:

| Script | Purpose |
|--------|---------|
| `echo_request.py` | Echoes request method, path, and headers as JSON |
| `inject_admin.py` | Returns `{"admin": true, "role": "superadmin"}` |
| `serve_local_file.py` | Serves a local file with correct Content-Type |

## Requirements

- Burp Suite Professional or Community Edition
- Jython standalone JAR configured in Burp's Python Environment
- Python 3 installed and on PATH (for Script mode only)

## Data Storage

Rules are stored in `burp_response_forger_data.json` next to the extension file. The format is backward-compatible with v1 data files.

## Credits

Built by [AFINE](https://afine.com) for internal penetration testing use.
