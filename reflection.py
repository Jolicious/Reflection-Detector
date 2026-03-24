# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab, IHttpListener, IMessageEditorController
from java.lang import Thread, Runnable
from java.util.concurrent import LinkedBlockingQueue
from java.awt.event import ActionListener, KeyAdapter, MouseAdapter
from javax.swing import (
    JPanel, JScrollPane, JTextArea, JButton, JLabel, JCheckBox,
    JTable, JSplitPane, SwingUtilities, JComboBox, JTextField,
    ListSelectionModel
)
from javax.swing.table import DefaultTableModel
from javax.swing.event import ListSelectionListener
from java.awt import BorderLayout, FlowLayout, Dimension
import re
import json


PAYLOAD_NORMAL = '"><{-+(.;:)\'}>'
PAYLOAD_JSON = '"><{-+(.;:)\'}>'
WORKER_COUNT = 3


class NonEditableTableModel(DefaultTableModel):
    def __init__(self, columns, rows):
        DefaultTableModel.__init__(self, columns, rows)

    def isCellEditable(self, row, column):
        return False


class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Reflection Detector")

        self._queue = LinkedBlockingQueue()
        self._enabled = True
        self._running = True

        self._results = []
        self._displayed_results = []
        self._currentlyDisplayedItem = None

        self._domains = set(["All domains"])
        self._statuses = set(["All"])
        self._types = set(["All"])
        self._contexts = set(["All"])

        self._build_ui()

        self._callbacks.addSuiteTab(self)
        self._callbacks.registerHttpListener(self)

        self._workers = []
        for i in range(WORKER_COUNT):
            t = Thread(Worker(self, i + 1))
            t.start()
            self._workers.append(t)

        self.log("[+] Reflection Detector loaded")
        self.log("[+] Dedupe removed")
        self.log("[+] Search enabled")
        self.log("[+] Table editing disabled")
        self.log("[+] JSON reflections marked as Not Reflected")
        self.log("[+] Started %d worker threads" % WORKER_COUNT)

    # ---------------- UI ----------------

    def _build_ui(self):
        self._panel = JPanel(BorderLayout())

        top = JPanel(FlowLayout(FlowLayout.LEFT))

        self._status = JLabel("Status: Running")
        self._queue_label = JLabel("Queue: 0")
        self._proxy = JCheckBox("Proxy", True)
        self._repeater = JCheckBox("Repeater", True)
        self._only_in_scope = JCheckBox("Only in scope", False)
        self._show_only_reflected = JCheckBox("Show only reflected", False)
        self._toggle = JButton("Stop", actionPerformed=self.toggle)
        self._clear = JButton("Clear", actionPerformed=self.clear_all)

        self._domain_filter = JComboBox()
        self._domain_filter.addItem("All domains")
        self._domain_filter.setPreferredSize(Dimension(100, 25))
        self._domain_filter.addActionListener(GenericFilterListener(self))

        self._reflected_filter = JComboBox()
        self._reflected_filter.addItem("All")
        self._reflected_filter.addItem("Yes")
        self._reflected_filter.addItem("No")
        self._reflected_filter.setPreferredSize(Dimension(60, 25))
        self._reflected_filter.addActionListener(GenericFilterListener(self))

        self._status_filter = JComboBox()
        self._status_filter.addItem("All")
        self._status_filter.setPreferredSize(Dimension(60, 25))
        self._status_filter.addActionListener(GenericFilterListener(self))

        self._type_filter = JComboBox()
        self._type_filter.addItem("All")
        self._type_filter.setPreferredSize(Dimension(70, 25))
        self._type_filter.addActionListener(GenericFilterListener(self))

        self._context_filter = JComboBox()
        self._context_filter.addItem("All")
        self._context_filter.setPreferredSize(Dimension(70, 25))
        self._context_filter.addActionListener(GenericFilterListener(self))

        self._search_field = JTextField(20)
        self._search_field.setPreferredSize(Dimension(70, 25))
        self._search_field.addKeyListener(SearchKeyListener(self))

        self._show_only_reflected.addActionListener(GenericFilterListener(self))

        top.add(self._status)
        top.add(self._queue_label)
        top.add(self._proxy)
        top.add(self._repeater)
        top.add(self._only_in_scope)
        top.add(self._show_only_reflected)

        top.add(JLabel("Domain:"))
        top.add(self._domain_filter)

        top.add(JLabel("Reflected:"))
        top.add(self._reflected_filter)

        top.add(JLabel("Status:"))
        top.add(self._status_filter)

        top.add(JLabel("Type:"))
        top.add(self._type_filter)

        top.add(JLabel("Context:"))
        top.add(self._context_filter)

        top.add(JLabel("Search:"))
        top.add(self._search_field)

        top.add(self._toggle)
        top.add(self._clear)

        self._table_model = NonEditableTableModel(
            ["Method", "URL", "Param", "Type", "Status", "Reflected", "Context"],
            0
        )
        self._table = JTable(self._table_model)
        self._table.getSelectionModel().addListSelectionListener(TableSelectionListener(self))
        self._table.setRowSelectionAllowed(True)
        self._table.setColumnSelectionAllowed(False)
        table_scroll = JScrollPane(self._table)

        self._requestViewer = self._callbacks.createMessageEditor(self, False)
        self._responseViewer = self._callbacks.createMessageEditor(self, False)

        viewer_split = JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT,
            self._requestViewer.getComponent(),
            self._responseViewer.getComponent()
        )
        viewer_split.setResizeWeight(0.5)

        main_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, table_scroll, viewer_split)
        main_split.setResizeWeight(0.55)

        self._log = JTextArea()
        self._log.setEditable(False)
        log_scroll = JScrollPane(self._log)

        outer_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, main_split, log_scroll)
        outer_split.setResizeWeight(0.82)

        self._panel.add(top, BorderLayout.NORTH)
        self._panel.add(outer_split, BorderLayout.CENTER)

    def getTabCaption(self):
        return "Debug Reflection Detector"

    def getUiComponent(self):
        return self._panel

    # ---------------- Message viewers ----------------

    def getHttpService(self):
        if self._currentlyDisplayedItem is None:
            return None
        return self._currentlyDisplayedItem["httpService"]

    def getRequest(self):
        if self._currentlyDisplayedItem is None:
            return None
        return self._currentlyDisplayedItem["request"]

    def getResponse(self):
        if self._currentlyDisplayedItem is None:
            return None
        return self._currentlyDisplayedItem["response"]

    # ---------------- Controls ----------------

    def toggle(self, event):
        self._enabled = not self._enabled
        if self._enabled:
            self._status.setText("Status: Running")
            self._toggle.setText("Stop")
            self.log("[*] Testing resumed")
        else:
            self._status.setText("Status: Paused")
            self._toggle.setText("Start")
            self.log("[*] Testing paused")

    def clear_all(self, event):
        self._results = []
        self._displayed_results = []
        self._currentlyDisplayedItem = None
        self._table_model.setRowCount(0)
        self._log.setText("")
        self._requestViewer.setMessage(None, True)
        self._responseViewer.setMessage(None, False)

        self._domains = set(["All domains"])
        self._statuses = set(["All"])
        self._types = set(["All"])
        self._contexts = set(["All"])

        self.reset_combo(self._domain_filter, ["All domains"])
        self.reset_combo(self._reflected_filter, ["All", "Yes", "No"])
        self.reset_combo(self._status_filter, ["All"])
        self.reset_combo(self._type_filter, ["All"])
        self.reset_combo(self._context_filter, ["All"])
        self._search_field.setText("")
        self._show_only_reflected.setSelected(False)

        self.update_queue_label()

    def reset_combo(self, combo, items):
        combo.removeAllItems()
        for item in items:
            combo.addItem(item)

    def log(self, msg):
        def run():
            self._log.append(msg + "\n")
            self._log.setCaretPosition(self._log.getDocument().getLength())
        SwingUtilities.invokeLater(RunnableWrapper(run))

    def update_queue_label(self):
        def run():
            try:
                self._queue_label.setText("Queue: %d" % self._queue.size())
            except:
                pass
        SwingUtilities.invokeLater(RunnableWrapper(run))

    # ---------------- Helpers ----------------

    def is_static_url(self, url):
        lower = url.lower()
        static_exts = (
            ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
            ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map",
            ".mp4", ".mp3", ".webm", ".pdf", ".zip"
        )
        for ext in static_exts:
            if lower.endswith(ext):
                return True
        return False

    def get_payload_for_type(self, ptype):
        if ptype == 6:
            return PAYLOAD_JSON
        return PAYLOAD_NORMAL

    def add_combo_value(self, combo, backing_set, value):
        if value not in backing_set:
            backing_set.add(value)

            def run():
                combo.addItem(value)
            SwingUtilities.invokeLater(RunnableWrapper(run))

    def add_domain(self, host):
        self.add_combo_value(self._domain_filter, self._domains, host)

    def add_status(self, status):
        self.add_combo_value(self._status_filter, self._statuses, status)

    def add_type(self, type_name):
        self.add_combo_value(self._type_filter, self._types, type_name)

    def add_context(self, context):
        self.add_combo_value(self._context_filter, self._contexts, context)

    def get_selected_text(self, combo, default_value):
        try:
            selected = combo.getSelectedItem()
            if selected is None:
                return default_value
            return str(selected)
        except:
            return default_value

    def refresh_table(self):
        selected_domain = self.get_selected_text(self._domain_filter, "All domains")
        selected_reflected = self.get_selected_text(self._reflected_filter, "All")
        selected_status = self.get_selected_text(self._status_filter, "All")
        selected_type = self.get_selected_text(self._type_filter, "All")
        selected_context = self.get_selected_text(self._context_filter, "All")

        try:
            search_text = self._search_field.getText().strip().lower()
        except:
            search_text = ""

        show_only_reflected = self._show_only_reflected.isSelected()

        def run():
            self._table_model.setRowCount(0)
            self._displayed_results = []

            for item in self._results:
                if selected_domain != "All domains" and item.get("host") != selected_domain:
                    continue
                if selected_reflected != "All" and item.get("reflected") != selected_reflected:
                    continue
                if selected_status != "All" and item.get("status") != selected_status:
                    continue
                if selected_type != "All" and item.get("type") != selected_type:
                    continue
                if selected_context != "All" and item.get("context") != selected_context:
                    continue
                if show_only_reflected and item.get("reflected") != "Yes":
                    continue

                if search_text:
                    haystack = " ".join([
                        str(item.get("method", "")),
                        str(item.get("url", "")),
                        str(item.get("host", "")),
                        str(item.get("param", "")),
                        str(item.get("type", "")),
                        str(item.get("status", "")),
                        str(item.get("reflected", "")),
                        str(item.get("context", "")),
                    ]).lower()

                    if search_text not in haystack:
                        continue

                self._displayed_results.append(item)
                self._table_model.addRow([
                    item["method"],
                    item["url"],
                    item["param"],
                    item["type"],
                    item["status"],
                    item["reflected"],
                    item["context"],
                ])

        SwingUtilities.invokeLater(RunnableWrapper(run))

    # ---------------- HTTP listener ----------------

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        try:
            if not self._enabled or not messageIsRequest:
                return

            if toolFlag == self._callbacks.TOOL_PROXY:
                if not self._proxy.isSelected():
                    return
            elif toolFlag == self._callbacks.TOOL_REPEATER:
                if not self._repeater.isSelected():
                    return
            else:
                return

            analyzed = self._helpers.analyzeRequest(messageInfo)
            url_obj = analyzed.getUrl()
            url = str(url_obj)
            host = str(url_obj.getHost())

            self.add_domain(host)

            if self.is_static_url(url):
                return

            if self._only_in_scope.isSelected() and not self._callbacks.isInScope(url_obj):
                return

            params = analyzed.getParameters()
            headers = analyzed.getHeaders()

            has_testable = False
            for p in params:
                if p.getType() != p.PARAM_COOKIE:
                    has_testable = True
                    break

            if not has_testable:
                for h in headers:
                    if h.lower().startswith("content-type:") and "application/json" in h.lower():
                        has_testable = True
                        break

            if not has_testable:
                return

            self._queue.put(messageInfo)
            self.update_queue_label()

        except Exception as e:
            self.log("[-] Listener error: %s" % str(e))

    # ---------------- Scan logic ----------------

    def detect_context(self, resp_body, payload):
        try:
            idx = resp_body.find(payload)
            if idx == -1:
                return "NONE"

            stripped = resp_body.lstrip()
            if stripped.startswith("{") or stripped.startswith("["):
                return "JSON"

            lower_body = resp_body.lower()

            before = lower_body[:idx]
            open_script = before.rfind("<script")
            close_script = before.rfind("</script")
            if open_script != -1 and open_script > close_script:
                return "SCRIPT"

            lt = resp_body.rfind("<", 0, idx)
            gt = resp_body.rfind(">", 0, idx)
            if lt > gt:
                tag_chunk = resp_body[lt:min(len(resp_body), idx + len(payload) + 80)]

                if re.search(r'=\s*["\'][^"\']*$', tag_chunk[:max(0, idx - lt)]):
                    return "ATTRIBUTE"

                if re.search(r'=\s*[^\s>"\']*$', tag_chunk[:max(0, idx - lt)]):
                    return "ATTRIBUTE"

                return "HTML"

            if "<html" in lower_body or "<body" in lower_body or "<div" in lower_body or "<p" in lower_body:
                return "HTML"

            return "OTHER"
        except Exception:
            return "OTHER"

    def process_and_store(self, new_req, method, url, pname, ptype, payload, httpService, host):
        resp = self._callbacks.makeHttpRequest(httpService, new_req)
        if resp is None or resp.getResponse() is None:
            return

        resp_bytes = resp.getResponse()
        resp_info = self._helpers.analyzeResponse(resp_bytes)
        body_offset = resp_info.getBodyOffset()
        resp_str = self._helpers.bytesToString(resp_bytes)
        resp_body = resp_str[body_offset:]

        raw_reflected = payload in resp_body
        context = self.detect_context(resp_body, payload) if raw_reflected else "NONE"

        if raw_reflected and context != "JSON":
            is_reflected = True
        else:
            is_reflected = False

        reflected = "Yes" if is_reflected else "No"

        status = str(resp_info.getStatusCode())
        ptype_name = self.param_type_to_string(ptype)

        item = {
            "method": method,
            "url": url,
            "host": host,
            "param": pname,
            "type": ptype_name,
            "status": status,
            "reflected": reflected,
            "context": context,
            "request": new_req,
            "response": resp_bytes,
            "httpService": httpService,
        }

        self._results.append(item)
        self.add_status(status)
        self.add_type(ptype_name)
        self.add_context(context)
        self.refresh_table()

    def check_message(self, messageInfo):
        if messageInfo is None:
            return

        req = messageInfo.getRequest()
        if req is None:
            return

        analyzed = self._helpers.analyzeRequest(messageInfo)
        method = analyzed.getMethod()
        url_obj = analyzed.getUrl()
        url = str(url_obj)
        host = str(url_obj.getHost())
        httpService = messageInfo.getHttpService()
        headers = analyzed.getHeaders()
        body_offset = analyzed.getBodyOffset()
        req_str = self._helpers.bytesToString(req)
        body_str = req_str[body_offset:]

        for p in analyzed.getParameters():
            try:
                if p.getType() == p.PARAM_COOKIE:
                    continue

                if p.getType() == p.PARAM_JSON:
                    continue

                pname = p.getName()
                ptype = p.getType()
                payload = self.get_payload_for_type(ptype)

                new_param = self._helpers.buildParameter(pname, payload, ptype)
                new_req = self._helpers.updateParameter(req, new_param)

                self.process_and_store(new_req, method, url, pname, ptype, payload, httpService, host)

            except Exception as e:
                self.log("[-] Scan error: %s" % str(e))

        content_type = ""
        for h in headers:
            if h.lower().startswith("content-type:"):
                content_type = h.lower()
                break

        if "application/json" in content_type:
            try:
                data = json.loads(body_str)

                if isinstance(data, dict):
                    for key in data.keys():
                        try:
                            new_data = dict(data)
                            payload = PAYLOAD_JSON
                            new_data[key] = payload

                            new_body = json.dumps(new_data)
                            new_body_bytes = self._helpers.stringToBytes(new_body)
                            new_headers = list(headers)
                            new_req = self._helpers.buildHttpMessage(new_headers, new_body_bytes)

                            self.process_and_store(new_req, method, url, key, 6, payload, httpService, host)

                        except Exception as e:
                            self.log("[-] JSON key error (%s): %s" % (key, str(e)))

            except Exception as e:
                self.log("[-] JSON parse error: %s" % str(e))

    def param_type_to_string(self, ptype):
        if ptype == 0:
            return "URL"
        elif ptype == 1:
            return "BODY"
        elif ptype == 2:
            return "COOKIE"
        elif ptype == 3:
            return "XML"
        elif ptype == 4:
            return "XML_ATTR"
        elif ptype == 5:
            return "MULTIPART_ATTR"
        elif ptype == 6:
            return "JSON"
        return "OTHER"


class Worker(Runnable):
    def __init__(self, extender, worker_id):
        self.extender = extender
        self.worker_id = worker_id

    def run(self):
        while self.extender._running:
            try:
                item = self.extender._queue.take()
                self.extender.update_queue_label()

                if item is None:
                    continue

                self.extender.check_message(item)

            except Exception as e:
                self.extender.log("[-] Worker %d error: %s" % (self.worker_id, str(e)))
                try:
                    Thread.sleep(1000)
                except:
                    pass


class TableSelectionListener(ListSelectionListener):
    def __init__(self, extender):
        self.extender = extender

    def valueChanged(self, event):
        if event.getValueIsAdjusting():
            return

        row = self.extender._table.getSelectedRow()
        if row < 0 or row >= len(self.extender._displayed_results):
            return

        item = self.extender._displayed_results[row]
        self.extender._currentlyDisplayedItem = item
        self.extender._requestViewer.setMessage(item["request"], True)
        self.extender._responseViewer.setMessage(item["response"], False)


class GenericFilterListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, event):
        self.extender.refresh_table()


class SearchKeyListener(KeyAdapter):
    def __init__(self, extender):
        self.extender = extender

    def keyReleased(self, event):
        self.extender.refresh_table()


class RunnableWrapper(Runnable):
    def __init__(self, fn):
        self.fn = fn

    def run(self):
        self.fn()
