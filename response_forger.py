# -*- coding: utf-8 -*-
# =======================================================================
# Response Forger v2 - Burp Suite Extension
# AFINE (afine.com)
#
# Overrides HTTP responses in Burp Suite. Define URL patterns and
# replacement responses (static text or dynamic Python 3 scripts).
#
# --- Sample script for Script mode (save as .py, run with Python 3) ---
#
#   #!/usr/bin/env python3
#   """Receives base64-encoded HTTP request on stdin.
#   Writes full HTTP response to stdout."""
#   import sys, base64, json
#
#   request = base64.b64decode(sys.stdin.read()).decode("utf-8", errors="replace")
#   body = json.dumps({"status": "forged", "admin": True})
#   response = (
#       "HTTP/1.1 200 OK\r\n"
#       "Content-Type: application/json\r\n"
#       "Content-Length: {}\r\n"
#       "\r\n"
#       "{}"
#   ).format(len(body), body)
#   sys.stdout.write(response)
#
# =======================================================================

import re
import json
import os
import sys
import time
import base64
import threading
from subprocess import Popen, PIPE

from burp import IBurpExtender, ITab, IContextMenuFactory, IHttpListener, IProxyListener
from javax.swing import (
    JPanel, JTable, JButton, JTextArea, JScrollPane, JLabel,
    JOptionPane, JMenuItem, JSplitPane, JTextField,
    JRadioButton, ButtonGroup, JFileChooser, SwingUtilities,
    JPopupMenu, BorderFactory, BoxLayout,
)
from javax.swing.table import AbstractTableModel
from java.awt import BorderLayout, FlowLayout
from java.awt.event import MouseAdapter
from java.util import ArrayList
from java.lang import Boolean, String, Integer, Runnable


SCRIPT_TIMEOUT = 10  # seconds

STATUS_REASONS = {
    "200": "OK", "201": "Created", "204": "No Content",
    "301": "Moved Permanently", "302": "Found", "304": "Not Modified",
    "400": "Bad Request", "401": "Unauthorized", "403": "Forbidden",
    "404": "Not Found", "405": "Method Not Allowed",
    "500": "Internal Server Error", "502": "Bad Gateway",
    "503": "Service Unavailable",
}


def _make_default():
    return {
        "enabled": True, "url": "", "method": "", "header_match": "",
        "mode": "static", "status_code": "200", "response": "",
        "script_path": "", "hits": 0,
    }


def _migrate(entry):
    """Add missing fields to old-format rules for backward compatibility."""
    defaults = _make_default()
    for key in defaults:
        if key not in entry:
            entry[key] = defaults[key]
    return entry


def _recalc_content_length(response_str):
    """Recalculate Content-Length header to match actual body size."""
    # Handle both \r\n\r\n and \n\n as header/body boundary
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


def _safe_kill(proc):
    try:
        proc.kill()
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass


def _normalize_crlf(response_str):
    """Ensure HTTP headers use CRLF line endings.

    JTextArea silently converts \\r\\n to \\n, which breaks HTTP response
    parsing. This normalizes the header section to proper CRLF while
    leaving the body untouched.
    """
    # Find header/body boundary - try CRLF first, then LF
    crlf_idx = response_str.find("\r\n\r\n")
    lf_idx = response_str.find("\n\n")

    if crlf_idx >= 0 and (lf_idx < 0 or crlf_idx <= lf_idx):
        headers = response_str[:crlf_idx]
        body = response_str[crlf_idx + 4:]
    elif lf_idx >= 0:
        headers = response_str[:lf_idx]
        body = response_str[lf_idx + 2:]
    else:
        # No boundary - normalize everything (headers only, no body)
        return response_str.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")

    # Normalize header line endings to CRLF
    headers = headers.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")
    return headers + "\r\n\r\n" + body


def _update_date_header(response_str):
    """Replace existing Date header with the current UTC time."""
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


# --- Swing helpers ---

class _Runnable(Runnable):
    def __init__(self, fn):
        self._fn = fn

    def run(self):
        self._fn()


class _PopupListener(MouseAdapter):
    def __init__(self, ext):
        self._ext = ext

    def mousePressed(self, e):
        self._check(e)

    def mouseReleased(self, e):
        self._check(e)

    def _check(self, e):
        if e.isPopupTrigger():
            t = self._ext.table
            row = t.rowAtPoint(e.getPoint())
            if row >= 0:
                t.setRowSelectionInterval(row, row)
                self._ext._show_popup(e, row)


# =======================================================================
# Extension
# =======================================================================

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IHttpListener, IProxyListener):

    _ext_dir = (
        os.path.dirname(sys.argv[0]) if os.path.isfile(sys.argv[0]) else os.getcwd()
    )
    _data_path = os.path.join(_ext_dir, "burp_response_forger_data.json")
    # --- setup ---

    def registerExtenderCallbacks(self, callbacks):
        self._cb = callbacks
        self._hlp = callbacks.getHelpers()
        callbacks.setExtensionName("Response Forger")

        self.rules = self._load()
        self._sel = -1  # selected model-row index

        # -- Table --
        self._tmodel = RuleTableModel(self.rules, self)
        self.table = JTable(self._tmodel)
        self.table.setAutoCreateRowSorter(True)
        self.table.getSelectionModel().addListSelectionListener(self._on_select)
        self.table.addMouseListener(_PopupListener(self))
        cm = self.table.getColumnModel()
        cm.getColumn(0).setMinWidth(50);  cm.getColumn(0).setMaxWidth(55)
        cm.getColumn(2).setPreferredWidth(60);  cm.getColumn(2).setMaxWidth(80)
        cm.getColumn(3).setPreferredWidth(60);  cm.getColumn(3).setMaxWidth(80)
        cm.getColumn(4).setPreferredWidth(50);  cm.getColumn(4).setMaxWidth(60)
        cm.getColumn(5).setPreferredWidth(50);  cm.getColumn(5).setMaxWidth(60)

        # -- Editor --
        editor = JPanel(BorderLayout())
        editor.setBorder(BorderFactory.createTitledBorder("Rule Editor"))

        form = JPanel()
        form.setLayout(BoxLayout(form, BoxLayout.Y_AXIS))

        # URL row
        r = JPanel(BorderLayout())
        r.add(JLabel(" URL pattern (regex): "), BorderLayout.WEST)
        self._f_url = JTextArea(1, 50)
        r.add(JScrollPane(self._f_url), BorderLayout.CENTER)
        form.add(r)

        # Method + header-match row
        r = JPanel(FlowLayout(FlowLayout.LEFT))
        r.add(JLabel("Method (empty = any):"))
        self._f_method = JTextField(8)
        r.add(self._f_method)
        r.add(JLabel("  Header match (regex):"))
        self._f_header = JTextField(25)
        r.add(self._f_header)
        form.add(r)

        # Mode row
        r = JPanel(FlowLayout(FlowLayout.LEFT))
        r.add(JLabel("Mode:"))
        self._rb_static = JRadioButton("Static", True, actionPerformed=self._on_mode)
        self._rb_script = JRadioButton("Script (dangerous!)", False, actionPerformed=self._on_mode)
        bg = ButtonGroup()
        bg.add(self._rb_static)
        bg.add(self._rb_script)
        r.add(self._rb_static)
        r.add(self._rb_script)
        form.add(r)

        # Status-code row (static)
        self._row_status = JPanel(FlowLayout(FlowLayout.LEFT))
        self._row_status.add(JLabel("Status code:"))
        self._f_status = JTextField(5)
        self._f_status.setText("200")
        self._row_status.add(self._f_status)
        self._row_status.add(JLabel(" (leave blank if response has HTTP status line)"))
        form.add(self._row_status)

        # Script row (script)
        self._row_script = JPanel(FlowLayout(FlowLayout.LEFT))
        self._row_script.add(JLabel("Script:"))
        self._f_script = JTextField(30)
        self._row_script.add(self._f_script)
        self._btn_browse = JButton("Browse", actionPerformed=self._browse)
        self._row_script.add(self._btn_browse)
        self._btn_test = JButton("Test", actionPerformed=self._test_script)
        self._row_script.add(self._btn_test)
        self._row_script.setVisible(False)
        form.add(self._row_script)


        editor.add(form, BorderLayout.NORTH)

        # Response body text area (static - fills center)
        self._f_resp = JTextArea(8, 50)
        self._scroll_resp = JScrollPane(self._f_resp)
        editor.add(self._scroll_resp, BorderLayout.CENTER)

        # Button bar
        bar = JPanel(FlowLayout(FlowLayout.CENTER))
        for label, handler in [
            ("Save", self._save),
            ("Delete", self._delete), ("Duplicate", self._dup),
            ("Reset Hits", self._reset_hits),
            ("Import", self._import), ("Export", self._export),
        ]:
            bar.add(JButton(label, actionPerformed=handler))
        editor.add(bar, BorderLayout.SOUTH)
        self._editor = editor

        # Split pane
        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(self.table), editor)
        split.setResizeWeight(0.4)
        self.panel = JPanel(BorderLayout())
        self.panel.add(split, BorderLayout.CENTER)

        callbacks.registerHttpListener(self)
        callbacks.registerProxyListener(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)

    # --- ITab ---

    def getTabCaption(self):
        return "Response Forger"

    def getUiComponent(self):
        return self.panel

    # --- IContextMenuFactory ---

    def createMenuItems(self, invocation):
        items = ArrayList()
        items.add(JMenuItem(
            "Send to Response Forger",
            actionPerformed=lambda e: self._send_to_forger(invocation),
        ))
        return items

    def _send_to_forger(self, invocation):
        for msg in invocation.getSelectedMessages():
            url = str(self._hlp.analyzeRequest(msg).getUrl())
            resp_bytes = msg.getResponse()
            resp = self._hlp.bytesToString(resp_bytes) if resp_bytes else ""
            rule = _make_default()
            rule["url"] = re.escape(url)
            rule["response"] = resp
            self.rules.append(rule)
            self._dedup_rules(len(self.rules) - 1)
        self._tmodel.fireTableDataChanged()
        self._save_data()

    # --- IHttpListener ---

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return
        # Proxy traffic handled by processProxyMessage for reliable interception
        if toolFlag == self._cb.TOOL_PROXY:
            return
        self._process_response(messageInfo)

    # --- IProxyListener ---

    def processProxyMessage(self, messageIsRequest, message):
        if messageIsRequest:
            return
        self._process_response(message.getMessageInfo())

    # --- shared response forge logic ---

    def _process_response(self, messageInfo):
        req_info = self._hlp.analyzeRequest(messageInfo)
        req_url = str(req_info.getUrl())
        req_method = str(req_info.getMethod())
        req_headers = None  # lazy

        for i, rule in enumerate(self.rules):
            if not rule.get("enabled", True):
                continue
            if not rule.get("url", ""):
                continue  # skip rules with empty URL pattern
            try:
                if not re.search(rule["url"], req_url):
                    continue
            except re.error:
                continue
            if rule.get("method") and rule["method"].upper() != req_method.upper():
                continue
            hp = rule.get("header_match", "")
            if hp:
                if req_headers is None:
                    req_headers = "\r\n".join(
                        [str(h) for h in req_info.getHeaders()]
                    )
                try:
                    if not re.search(hp, req_headers):
                        continue
                except re.error:
                    continue

            # Matched - forge
            if rule.get("mode") == "script":
                forged = self._run_script(rule, messageInfo.getRequest())
            else:
                forged = self._build_static(rule)

            if forged is not None:
                forged = _update_date_header(forged)
                messageInfo.setResponse(self._hlp.stringToBytes(forged))
                rule["hits"] = rule.get("hits", 0) + 1
                self._cb.printOutput(
                    "[Response Forger] Forged %s %s (%d bytes)"
                    % (req_method, req_url, len(forged))
                )
                idx = i
                SwingUtilities.invokeLater(_Runnable(
                    lambda idx=idx: self._tmodel.fireTableRowsUpdated(idx, idx)
                ))
                break  # first match wins

    # --- response builders ---

    def _build_static(self, rule):
        resp = rule.get("response", "")
        if not resp:
            return None
        sc = rule.get("status_code", "")
        if not resp.startswith("HTTP/"):
            if not sc:
                sc = "200"
            reason = STATUS_REASONS.get(sc, "OK")
            resp = "HTTP/1.1 %s %s\r\n\r\n%s" % (sc, reason, resp)
        else:
            # Normalize CRLF - JTextArea converts \r\n to \n which breaks HTTP
            resp = _normalize_crlf(resp)
        return _recalc_content_length(resp)

    def _run_script(self, rule, request_bytes):
        raw_path = rule.get("script_path", "").strip()
        if not raw_path:
            self._cb.printError("Response Forger: no script path configured")
            return None
        parts = raw_path.split()
        script_file = parts[0]
        extra_args = parts[1:]
        if not os.path.isfile(script_file):
            self._cb.printError("Response Forger: script not found: " + script_file)
            return None
        try:
            req_b64 = base64.b64encode(str(self._hlp.bytesToString(request_bytes)))
            cmd = ["python3", script_file] + extra_args
            proc = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)
            killed = [False]
            def _kill():
                killed[0] = True
                _safe_kill(proc)
            timer = threading.Timer(SCRIPT_TIMEOUT, _kill)
            timer.start()
            try:
                stdout, stderr = proc.communicate(req_b64)
            finally:
                timer.cancel()
            if killed[0]:
                self._cb.printError(
                    "Response Forger: script timed out (%ds): %s" % (SCRIPT_TIMEOUT, script_file)
                )
                return None
            if proc.returncode == 0 and stdout:
                return _normalize_crlf(stdout)
            self._cb.printError(
                "Response Forger: script %s failed (rc=%d): %s" % (script_file, proc.returncode, stderr)
            )
            return None
        except Exception as e:
            self._cb.printError("Response Forger: script error: " + str(e))
            return None

    # --- table popup ---

    def _show_popup(self, event, view_row):
        model_row = self.table.convertRowIndexToModel(view_row)
        popup = JPopupMenu()
        enabled = self.rules[model_row].get("enabled", True)
        popup.add(JMenuItem(
            "Disable" if enabled else "Enable",
            actionPerformed=lambda e, r=model_row: self._toggle(r),
        ))
        popup.add(JMenuItem("Duplicate", actionPerformed=self._dup))
        popup.add(JMenuItem("Delete", actionPerformed=self._delete))
        popup.show(event.getComponent(), event.getX(), event.getY())

    def _toggle(self, model_row):
        if 0 <= model_row < len(self.rules):
            self.rules[model_row]["enabled"] = not self.rules[model_row].get("enabled", True)
            self._tmodel.fireTableRowsUpdated(model_row, model_row)
            if self.rules[model_row]["enabled"]:
                self._dedup_rules(model_row)
            self._save_data()

    def _dedup_rules(self, keep_row):
        """Disable other rules with the same URL pattern as keep_row."""
        url = self.rules[keep_row].get("url", "")
        if not url:
            return
        for i, rule in enumerate(self.rules):
            if i == keep_row:
                continue
            if rule.get("url") == url and rule.get("enabled", True):
                rule["enabled"] = False
                self._tmodel.fireTableRowsUpdated(i, i)

    # --- editor helpers ---

    def _model_row(self):
        """Return the model-row index for the currently selected table row, or -1."""
        vr = self.table.getSelectedRow()
        if vr < 0:
            return -1
        return self.table.convertRowIndexToModel(vr)

    def _on_select(self, event):
        if event.getValueIsAdjusting():
            return
        mr = self._model_row()
        if mr < 0 or mr == self._sel:
            return
        self._sel = mr
        rule = self.rules[mr]
        self._f_url.setText(rule.get("url", ""))
        self._f_method.setText(rule.get("method", ""))
        self._f_header.setText(rule.get("header_match", ""))
        self._f_status.setText(rule.get("status_code", "200"))
        self._f_resp.setText(rule.get("response", ""))
        self._f_script.setText(rule.get("script_path", ""))
        if rule.get("mode") == "script":
            self._rb_script.setSelected(True)
            self._set_script_mode()
        else:
            self._rb_static.setSelected(True)
            self._set_static_mode()

    def _on_mode(self, event):
        if self._rb_script.isSelected():
            self._set_script_mode()
        else:
            self._set_static_mode()

    def _set_static_mode(self):
        self._row_status.setVisible(True)
        self._scroll_resp.setVisible(True)
        self._row_script.setVisible(False)
        self._editor.revalidate()
        self._editor.repaint()

    def _set_script_mode(self):
        self._row_status.setVisible(False)
        self._scroll_resp.setVisible(False)
        self._row_script.setVisible(True)
        self._editor.revalidate()
        self._editor.repaint()

    def _browse(self, event):
        fc = JFileChooser()
        if fc.showOpenDialog(self.panel) == JFileChooser.APPROVE_OPTION:
            self._f_script.setText(fc.getSelectedFile().getAbsolutePath())

    def _test_script(self, event):
        raw_path = self._f_script.getText().strip()
        if not raw_path:
            JOptionPane.showMessageDialog(self.panel, "No script path set.")
            return
        parts = raw_path.split()
        script_file = parts[0]
        extra_args = parts[1:]
        if not os.path.isfile(script_file):
            JOptionPane.showMessageDialog(self.panel, "File not found: " + script_file)
            return
        sample = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        sample_b64 = base64.b64encode(sample)
        try:
            cmd = ["python3", script_file] + extra_args
            proc = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)
            timer = threading.Timer(SCRIPT_TIMEOUT, lambda: _safe_kill(proc))
            timer.start()
            try:
                stdout, stderr = proc.communicate(sample_b64)
            finally:
                timer.cancel()
            if proc.returncode == 0:
                JOptionPane.showMessageDialog(
                    self.panel, "Output (%d bytes):\n\n%s" % (len(stdout), stdout[:2000])
                )
            else:
                JOptionPane.showMessageDialog(
                    self.panel, "Failed (rc=%d):\n%s" % (proc.returncode, stderr[:1000])
                )
        except Exception as e:
            JOptionPane.showMessageDialog(self.panel, "Error: " + str(e))

    def _clear_editor(self):
        self._f_url.setText("")
        self._f_method.setText("")
        self._f_header.setText("")
        self._f_status.setText("200")
        self._f_resp.setText("")
        self._f_script.setText("")
        self._rb_static.setSelected(True)
        self._set_static_mode()

    # --- button handlers ---

    def _save(self, event):
        mr = self._model_row()
        if mr < 0:
            JOptionPane.showMessageDialog(self.panel, "No rule selected.")
            return
        url = self._f_url.getText().strip()
        if not url:
            JOptionPane.showMessageDialog(self.panel, "URL pattern cannot be empty.")
            return
        rule = self.rules[mr]
        rule["url"] = url
        rule["method"] = self._f_method.getText().strip()
        rule["header_match"] = self._f_header.getText().strip()
        if self._rb_script.isSelected():
            rule["mode"] = "script"
            rule["script_path"] = self._f_script.getText().strip()
        else:
            rule["mode"] = "static"
            rule["status_code"] = self._f_status.getText().strip()
            rule["response"] = self._f_resp.getText()
        self._tmodel.fireTableRowsUpdated(mr, mr)
        self._save_data()

    def _delete(self, event):
        mr = self._model_row()
        if mr < 0:
            JOptionPane.showMessageDialog(self.panel, "No rule selected.")
            return
        del self.rules[mr]
        self._sel = -1
        self._clear_editor()
        self._tmodel.fireTableDataChanged()
        self._save_data()

    def _dup(self, event):
        mr = self._model_row()
        if mr < 0:
            JOptionPane.showMessageDialog(self.panel, "No rule selected.")
            return
        new_rule = dict(self.rules[mr])
        new_rule["hits"] = 0
        self.rules.append(new_rule)
        new_mr = len(self.rules) - 1
        self._dedup_rules(new_mr)
        self._tmodel.fireTableDataChanged()
        self._save_data()
        try:
            vr = self.table.convertRowIndexToView(new_mr)
            self.table.setRowSelectionInterval(vr, vr)
        except Exception:
            pass

    def _reset_hits(self, event):
        mr = self._model_row()
        if mr < 0:
            JOptionPane.showMessageDialog(self.panel, "No rule selected.")
            return
        self.rules[mr]["hits"] = 0
        self._tmodel.fireTableRowsUpdated(mr, mr)
        self._save_data()

    def _import(self, event):
        fc = JFileChooser()
        if fc.showOpenDialog(self.panel) != JFileChooser.APPROVE_OPTION:
            return
        path = fc.getSelectedFile().getAbsolutePath()
        try:
            with open(path, "r") as f:
                data = json.load(f)
            if not isinstance(data, list):
                JOptionPane.showMessageDialog(self.panel, "Invalid format: expected JSON array.")
                return
            existing = set(r["url"] for r in self.rules)
            added = 0
            for entry in data:
                entry = _migrate(entry)
                if entry["url"] not in existing:
                    self.rules.append(entry)
                    existing.add(entry["url"])
                    added += 1
            self._tmodel.fireTableDataChanged()
            self._save_data()
            JOptionPane.showMessageDialog(
                self.panel,
                "Imported %d rules (%d skipped as duplicates)." % (added, len(data) - added),
            )
        except Exception as e:
            JOptionPane.showMessageDialog(self.panel, "Import error: " + str(e))

    def _export(self, event):
        fc = JFileChooser()
        if fc.showSaveDialog(self.panel) != JFileChooser.APPROVE_OPTION:
            return
        path = fc.getSelectedFile().getAbsolutePath()
        try:
            with open(path, "w") as f:
                json.dump(self.rules, f, indent=2)
            JOptionPane.showMessageDialog(
                self.panel, "Exported %d rules to %s" % (len(self.rules), path)
            )
        except Exception as e:
            JOptionPane.showMessageDialog(self.panel, "Export error: " + str(e))

    # --- persistence ---

    def _load(self):
        if os.path.exists(self._data_path):
            try:
                with open(self._data_path, "r") as f:
                    data = json.load(f)
                return [_migrate(e) for e in data]
            except (ValueError, IOError):
                return []
        return []

    def _save_data(self):
        try:
            with open(self._data_path, "w") as f:
                json.dump(self.rules, f)
        except IOError as e:
            self._cb.printError("Response Forger: save failed: " + str(e))


# =======================================================================
# Table model
# =======================================================================

class RuleTableModel(AbstractTableModel):

    COLS = ["Enabled", "URL Pattern", "Method", "Mode", "Status", "Hits"]

    def __init__(self, data, ext):
        self._data = data
        self._ext = ext

    def getColumnCount(self):
        return len(self.COLS)

    def getRowCount(self):
        return len(self._data)

    def getColumnName(self, col):
        return self.COLS[col]

    def getColumnClass(self, col):
        if col == 0:
            return Boolean
        if col == 5:
            return Integer
        return String

    def isCellEditable(self, row, col):
        return col == 0

    def getValueAt(self, row, col):
        r = self._data[row]
        if col == 0:
            return r.get("enabled", True)
        if col == 1:
            return r.get("url", "")
        if col == 2:
            return r.get("method", "")
        if col == 3:
            return r.get("mode", "static")
        if col == 4:
            return r.get("status_code", "")
        if col == 5:
            return r.get("hits", 0)
        return ""

    def setValueAt(self, value, row, col):
        if col == 0:
            self._data[row]["enabled"] = bool(value)
            self.fireTableCellUpdated(row, col)
            if self._data[row]["enabled"]:
                self._ext._dedup_rules(row)
            self._ext._save_data()
