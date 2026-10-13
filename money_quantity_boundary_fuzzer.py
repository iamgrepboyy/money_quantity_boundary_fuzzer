"""Money and quantity boundary fuzzer for Burp's legacy Jython API."""

import json
import re
import threading

from burp import (
    IBurpExtender,
    ITab,
    IContextMenuFactory,
    IScannerCheck,
    IScannerInsertionPoint,
    IScannerInsertionPointProvider,
    IScanIssue,
    IHttpRequestResponse,
    IParameter,
)
from java.awt import BorderLayout, FlowLayout
from java.awt.event import ActionListener
from java.lang import System
from java.util import ArrayList
from javax.swing import (
    JButton,
    JCheckBox,
    JLabel,
    JMenuItem,
    JOptionPane,
    JPanel,
    JScrollPane,
    JSplitPane,
    ListSelectionModel,
    SwingWorker,
    JTable,
    JTextArea,
)
from javax.swing.table import DefaultTableModel
from javax.swing.event import ListSelectionListener
from jarray import array


_FIELD_PATTERNS = [
    ("currency", re.compile(r"(^|[^a-z])(currency|curr)([^a-z]|$)")),
    ("discount", re.compile(r"(^|[^a-z])(discount|markdown|reduction)([^a-z]|$)")),
    ("quantity", re.compile(r"(^|[^a-z])(quantity|qty|count|units)([^a-z]|$)")),
    (
        "amount",
        re.compile(r"(^|[^a-z])(price|amount|total|subtotal|cost|fee|tax|charge)([^a-z]|$)"),
    ),
]
_NUMERIC_VALUE = re.compile(r"^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$")
_REJECTION_TEXT = re.compile(
    r"(?i)invalid|not allowed|rejected|out of range|must be positive|"
    r"cannot be less|exceeds the maximum|validation failed"
)
_MAX_FIELDS = 30
_MAX_SELECTED_FIELDS = 12
_MAX_MANUAL_REQUESTS = 60
_SAFE_SCAN_METHODS = ("GET", "HEAD")
_STATE_CHANGING_METHODS = ("POST", "PUT", "PATCH", "DELETE")


class _Action(ActionListener):
    def __init__(self, callback):
        self.callback = callback

    def actionPerformed(self, event):
        self.callback()


class _SelectionListener(ListSelectionListener):
    def __init__(self, callback):
        self.callback = callback

    def valueChanged(self, event):
        self.callback(event)


class _ReadOnlyModel(DefaultTableModel):
    def isCellEditable(self, row, column):
        return False


def _field_family(name, value, parameter_type):
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(name)).lower()
    normalized = re.sub(r"[_-]+", " ", normalized)
    tokens = normalized.split()
    for family, pattern in _FIELD_PATTERNS:
        if pattern.search(normalized):
            value_text = str(value).strip().strip("\"'")
            if family == "discount" and ("code" in tokens or "coupon" in tokens):
                if not _NUMERIC_VALUE.match(value_text):
                    return None
            json_type = int(getattr(IParameter, "PARAM_JSON", -100))
            if parameter_type == json_type and value_text.lower() in (
                "true", "false", "null", "{}", "[]"
            ):
                return None
            return family
    return None


def _boundary_payloads(family, base_value=""):
    if family == "currency":
        return [
            value
            for value in ("USD", "EUR", "JPY", "XXX")
            if value.lower() != str(base_value).strip().lower()
        ]
    if family == "quantity":
        return ["-1", "0", "1.5", "9223372036854775808"]
    if family == "discount":
        return ["-1", "100.01", "101", "1000000"]
    return ["-0.01", "0.001", "1.005", "999999999999999999999999"]


def _is_accepted(helpers, response):
    if response is None:
        return False
    response_info = helpers.analyzeResponse(response)
    status = int(response_info.getStatusCode())
    if status < 200 or status >= 300:
        return False
    body = helpers.bytesToString(response[int(response_info.getBodyOffset()):])
    return _REJECTION_TEXT.search(body) is None


def _request_location(helpers, service, request):
    request_info = helpers.analyzeRequest(service, request)
    return str(request_info.getMethod()).upper(), request_info.getUrl()


def _scanner_method_allowed(method, allow_state_changes):
    method = str(method).upper()
    return method in _SAFE_SCAN_METHODS or (
        allow_state_changes and method in _STATE_CHANGING_METHODS
    )


class _BoundaryInsertionPoint(IScannerInsertionPoint):
    def __init__(self, extension, service, request, parameter, family, occurrence,
            total, duplicate=False):
        self.extension = extension
        self.service = service
        self.request = request
        self.parameter = parameter
        self.family = family
        self.occurrence = occurrence
        self.total = total
        self.duplicate = duplicate
        self.name = str(parameter.getName())
        self.parameter_type = int(parameter.getType())
        self.base_value = str(parameter.getValue())

    def getInsertionPointName(self):
        if self.duplicate:
            return "%s (duplicate parameter)" % self.name
        if self.total > 1:
            return "%s (%d/%d)" % (self.name, self.occurrence, self.total)
        return self.name

    def getBaseValue(self):
        return self.base_value

    def getInsertionPointType(self):
        return IScannerInsertionPoint.INS_EXTENSION_PROVIDED

    def getPayloadOffsets(self, payload):
        return None

    def buildRequest(self, payload):
        payload_text = self.extension.helpers.bytesToString(payload)
        if self.duplicate:
            parameter = self.extension.helpers.buildParameter(
                self.name, payload_text, self.parameter_type
            )
            return self.extension.helpers.addParameter(self.request, parameter)

        request_text = self.extension.helpers.bytesToString(self.request)
        start = int(self.parameter.getValueStart())
        end = int(self.parameter.getValueEnd())
        if start < 0 or end < start or end > len(request_text):
            return self.request

        replacement = self.extension._encode_parameter_value(
            request_text, start, end, self.parameter_type, payload_text
        )
        mutated_text = request_text[:start] + replacement + request_text[end:]
        mutated = self.extension.helpers.stringToBytes(mutated_text)
        updated_info = self.extension.helpers.analyzeRequest(self.service, mutated)
        headers = ArrayList()
        for header in updated_info.getHeaders():
            headers.add(str(header))
        body = mutated[int(updated_info.getBodyOffset()):]
        return self.extension.helpers.buildHttpMessage(headers, body)


class _BoundaryIssue(IScanIssue):
    def __init__(self, helpers, exchange, point_name, payload, status):
        self.helpers = helpers
        self.exchange = exchange
        self.point_name = point_name
        self.payload = payload
        self.status = status
        service = exchange.getHttpService()
        self.service = service
        self.url = helpers.analyzeRequest(service, exchange.getRequest()).getUrl()

    def getUrl(self):
        return self.url

    def getIssueName(self):
        return "Business boundary value accepted: " + self.point_name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return "Low"

    def getConfidence(self):
        return "Tentative"

    def getIssueBackground(self):
        return "A money or quantity boundary value received a successful response. Verify the resulting business state before treating this as a vulnerability."

    def getRemediationBackground(self):
        return "Validate business values server-side, apply explicit numeric bounds, and use decimal arithmetic for currency calculations."

    def getIssueDetail(self):
        return (
            "Insertion point: %s<br>Payload: %s<br>HTTP status: %d<br>"
            "The successful status is a heuristic and does not prove that the value was persisted."
            % (
                self._html(self.point_name),
                self._html(self.payload),
                self.status,
            )
        )

    def getRemediationDetail(self):
        return "Reject out-of-range values and verify all totals, discounts, currencies, and quantities against authoritative server-side data."

    def getHttpMessages(self):
        return array([self.exchange], IHttpRequestResponse)

    def getHttpService(self):
        return self.service

    def _html(self, value):
        return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class BurpExtender(
    IBurpExtender,
    ITab,
    IContextMenuFactory,
    IScannerCheck,
    IScannerInsertionPointProvider,
):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.lock = threading.RLock()
        self.service = None
        self.request = None
        self.target_url = None
        self.target_method = ""
        self.fields = []
        self.displayed_fields = []
        self.results = []
        self.running = False
        self.scanner_state_changes_enabled = False
        callbacks.setExtensionName("Money and Quantity Boundary Fuzzer")
        self._build_ui()
        callbacks.registerContextMenuFactory(self)
        callbacks.registerScannerCheck(self)
        callbacks.registerScannerInsertionPointProvider(self)
        callbacks.addSuiteTab(self)
        callbacks.printOutput("Money and Quantity Boundary Fuzzer loaded")

    def getTabCaption(self):
        return "Money Fuzzer"

    def getUiComponent(self):
        return self.panel

    def createMenuItems(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages:
            return None
        message_info = messages[0]
        item = JMenuItem("Analyze money/quantity fields in request")
        item.addActionListener(_Action(lambda: self._load_message(message_info)))
        items = ArrayList()
        items.add(item)
        return items

    def _build_ui(self):
        self.panel = JPanel(BorderLayout(6, 6))
        controls = JPanel(FlowLayout(FlowLayout.LEFT))
        self.run_button = JButton("Run selected probes")
        self.run_button.addActionListener(_Action(self._run_selected))
        self.clear_button = JButton("Clear results")
        self.clear_button.addActionListener(_Action(self._clear_results))
        self.unsafe_box = JCheckBox("Allow state-changing replay", False)
        self.scanner_unsafe_box = JCheckBox(
            "Scanner POST/PUT/PATCH/DELETE (may change state)", False
        )
        self.scanner_unsafe_box.addActionListener(
            _Action(self._toggle_scanner_state_changes)
        )
        controls.add(self.run_button)
        controls.add(self.clear_button)
        controls.add(self.unsafe_box)
        controls.add(self.scanner_unsafe_box)
        self.panel.add(controls, BorderLayout.NORTH)

        self.field_model = _ReadOnlyModel(
            ["Field", "Class", "Type", "Current value", "Occurrence", "Probe"], 0
        )
        self.field_table = JTable(self.field_model)
        self.field_table.setAutoCreateRowSorter(True)
        self.field_table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)

        self.result_model = _ReadOnlyModel(
            ["Field", "Payload", "HTTP", "Body bytes", "Time ms", "Outcome"], 0
        )
        self.result_table = JTable(self.result_model)
        self.result_table.setAutoCreateRowSorter(True)
        self.result_table.getSelectionModel().addListSelectionListener(
            _SelectionListener(self._show_selected_result)
        )
        self.result_details = JTextArea(5, 80)
        self.result_details.setEditable(False)
        self.result_details.setLineWrap(True)

        results_split = JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            JScrollPane(self.result_table),
            JScrollPane(self.result_details),
        )
        results_split.setResizeWeight(0.72)

        field_panel = JPanel(BorderLayout(4, 4))
        field_panel.add(JLabel("Detected price, quantity, discount, and currency fields"), BorderLayout.NORTH)
        field_panel.add(JScrollPane(self.field_table), BorderLayout.CENTER)
        result_panel = JPanel(BorderLayout(4, 4))
        result_panel.add(JLabel("Boundary probe results"), BorderLayout.NORTH)
        result_panel.add(results_split, BorderLayout.CENTER)
        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, field_panel, result_panel)
        split.setResizeWeight(0.48)
        self.panel.add(split, BorderLayout.CENTER)

        footer = JPanel(BorderLayout())
        self.target_label = JLabel("Request: none")
        self.status_label = JLabel(
            "Load a request from Burp. Automated Scanner checks run only on in-scope GET/HEAD requests."
        )
        footer.add(self.target_label, BorderLayout.NORTH)
        footer.add(self.status_label, BorderLayout.SOUTH)
        self.panel.add(footer, BorderLayout.SOUTH)

    def _load_message(self, message_info):
        service = message_info.getHttpService()
        request = message_info.getRequest()
        if service is None or request is None:
            self.status_label.setText("Selected item has no HTTP request/service.")
            return
        self._load_request(service, request)

    def _toggle_scanner_state_changes(self):
        if not self.scanner_unsafe_box.isSelected():
            self.scanner_state_changes_enabled = False
            self.status_label.setText(
                "Automated Scanner probes are limited to GET/HEAD."
            )
            return
        answer = JOptionPane.showConfirmDialog(
            self.panel,
            "Burp Scanner may send multiple boundary probes to scoped POST/PUT/PATCH/DELETE requests. These can create or modify orders and other application data. Enable this only for a test environment?",
            "Enable state-changing Scanner probes",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE,
        )
        self.scanner_state_changes_enabled = answer == JOptionPane.YES_OPTION
        if not self.scanner_state_changes_enabled:
            self.scanner_unsafe_box.setSelected(False)
        else:
            self.status_label.setText(
                "State-changing Scanner probes enabled for in-scope POST/PUT/PATCH/DELETE requests."
            )

    def _load_request(self, service, request):
        try:
            request_info = self.helpers.analyzeRequest(service, request)
            self.service = service
            self.request = request
            self.target_url = request_info.getUrl()
            self.target_method = str(request_info.getMethod()).upper()
            self.target_label.setText(
                "Request: %s %s" % (self.target_method, self.target_url)
            )
            self._discover_fields(service, request)
            self.status_label.setText(
                "Found %d candidate insertion point(s). Captured request stays in memory."
                % len(self.fields)
            )
        except Exception as error:
            self.status_label.setText("Could not analyze request: " + str(error))

    def _discover_fields(self, service, request):
        request_info = self.helpers.analyzeRequest(service, request)
        parameters = list(request_info.getParameters())
        counts = {}
        for parameter in parameters:
            key = (str(parameter.getName()).lower(), int(parameter.getType()))
            counts[key] = counts.get(key, 0) + 1

        seen = {}
        fields = []
        for parameter in parameters:
            name = str(parameter.getName())
            parameter_type = int(parameter.getType())
            family = _field_family(
                name, str(parameter.getValue()), parameter_type
            )
            if family is None or not self._supported_type(parameter_type):
                continue
            key = (name.lower(), parameter_type)
            seen[key] = seen.get(key, 0) + 1
            point = _BoundaryInsertionPoint(
                self,
                service,
                request,
                parameter,
                family,
                seen[key],
                counts[key],
            )
            fields.append(point)
            if parameter_type in (int(IParameter.PARAM_URL), int(IParameter.PARAM_BODY)):
                fields.append(
                    _BoundaryInsertionPoint(
                        self,
                        service,
                        request,
                        parameter,
                        family,
                        seen[key],
                        counts[key],
                        True,
                    )
                )
            if len(fields) >= _MAX_FIELDS:
                break

        self.fields = fields
        self.displayed_fields = list(fields)
        self.field_model.setRowCount(0)
        for point in fields:
            value = point.getBaseValue()
            if len(value) > 80:
                value = value[:77] + "..."
            if point.duplicate:
                occurrence = "Add another"
                probe = "Conflicting duplicate"
            else:
                occurrence = "%d/%d" % (point.occurrence, point.total)
                probe = "Boundary values"
            self.field_model.addRow(
                [
                    point.name,
                    point.family,
                    self._type_name(point.parameter_type),
                    value,
                    occurrence,
                    probe,
                ]
            )

    def _supported_type(self, parameter_type):
        return parameter_type in (
            int(IParameter.PARAM_URL),
            int(IParameter.PARAM_BODY),
            int(getattr(IParameter, "PARAM_JSON", -100)),
        )

    def _type_name(self, parameter_type):
        for constant_name, label in (
            ("PARAM_URL", "URL"),
            ("PARAM_BODY", "Form/body"),
            ("PARAM_JSON", "JSON"),
        ):
            value = getattr(IParameter, constant_name, None)
            if value is not None and int(value) == parameter_type:
                return label
        return str(parameter_type)

    def _encode_parameter_value(self, request_text, start, end, parameter_type, payload):
        if parameter_type in (int(IParameter.PARAM_URL), int(IParameter.PARAM_BODY)):
            return self.helpers.urlEncode(payload)
        json_type = int(getattr(IParameter, "PARAM_JSON", -100))
        if parameter_type == json_type:
            segment = request_text[start:end]
            if segment.startswith('"') and segment.endswith('"'):
                return json.dumps(payload)
            if start > 0 and end < len(request_text):
                if request_text[start - 1] == '"' and request_text[end] == '"':
                    return json.dumps(payload)[1:-1]
        return payload

    def _selected_fields(self):
        selected_rows = self.field_table.getSelectedRows()
        fields = []
        for row in selected_rows:
            model_row = self.field_table.convertRowIndexToModel(row)
            if model_row < len(self.displayed_fields):
                fields.append(self.displayed_fields[model_row])
        return fields

    def _run_selected(self):
        if self.running:
            return
        if self.request is None or self.service is None:
            self.status_label.setText("Load a request from Burp first.")
            return
        selected = self._selected_fields()
        if not selected:
            self.status_label.setText("Select one or more detected fields.")
            return
        if len(selected) > _MAX_SELECTED_FIELDS:
            self.status_label.setText(
                "Select no more than %d field probes at a time." % _MAX_SELECTED_FIELDS
            )
            return
        payload_count = sum(
            len(_boundary_payloads(point.family, point.base_value))
            for point in selected
        )
        if payload_count > _MAX_MANUAL_REQUESTS:
            self.status_label.setText("Probe set exceeds the %d-request limit." % _MAX_MANUAL_REQUESTS)
            return
        if not self.callbacks.isInScope(self.target_url):
            self.status_label.setText("Active tests are blocked outside Burp scope.")
            return
        if self.target_method not in ("GET", "HEAD"):
            if not self.unsafe_box.isSelected():
                self.status_label.setText(
                    "Non-GET/HEAD replay blocked. Enable the override only when safe."
                )
                return
            answer = JOptionPane.showConfirmDialog(
                self.panel,
                "These probes will replay a %s request up to %d times and may change prices, orders, or account state. Continue?"
                % (self.target_method, payload_count),
                "Confirm state-changing boundary tests",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE,
            )
            if answer != JOptionPane.YES_OPTION:
                return

        service = self.service
        target_url = self.target_url
        fields = list(selected)
        self.running = True
        self._set_controls_enabled(False)
        self.status_label.setText("Running %d bounded boundary probes..." % payload_count)
        extension = self

        class ProbeWorker(SwingWorker):
            def doInBackground(worker_self):
                return extension._run_manual_probes(
                    service, target_url, fields
                )

            def done(worker_self):
                extension.running = False
                extension._set_controls_enabled(True)
                try:
                    results = worker_self.get()
                    extension._show_results(results)
                    extension.status_label.setText(
                        "Completed %d probe(s). Accepted responses are candidates for manual business-state verification."
                        % len(results)
                    )
                except Exception as error:
                    extension.status_label.setText("Probe run failed: " + str(error))

        ProbeWorker().execute()

    def _run_manual_probes(self, service, target_url, fields):
        rows = []
        for point in fields:
            for payload in _boundary_payloads(point.family, point.base_value):
                if not self.callbacks.isInScope(target_url):
                    rows.append(self._result_row(point, payload, None, 0, "Blocked: out of scope"))
                    continue
                started = System.nanoTime()
                try:
                    mutated_request = point.buildRequest(self.helpers.stringToBytes(payload))
                    exchange = self.callbacks.makeHttpRequest(service, mutated_request)
                    elapsed_ms = (System.nanoTime() - started) / 1000000.0
                    response = exchange.getResponse() if exchange is not None else None
                    rows.append(
                        self._result_row(point, payload, response, elapsed_ms, None)
                    )
                except Exception as error:
                    rows.append(
                        self._result_row(
                            point, payload, None, 0, "Error: " + str(error)
                        )
                    )
        return rows

    def _result_row(self, point, payload, response, elapsed_ms, error):
        if error:
            status = "-"
            body_length = "-"
            outcome = error
            details = error
        elif response is None:
            status = "No response"
            body_length = "-"
            outcome = "Inconclusive"
            details = "No HTTP response was received."
        else:
            response_info = self.helpers.analyzeResponse(response)
            status_code = int(response_info.getStatusCode())
            body_length = len(response) - int(response_info.getBodyOffset())
            accepted = _is_accepted(self.helpers, response)
            status = str(status_code)
            outcome = "Accepted; verify state" if accepted else "Rejected/validation response"
            details = (
                "Parameter: %s\nClass: %s\nProbe: %s\nHTTP: %d\n"
                "Body bytes: %d\nElapsed: %.1f ms\nOutcome: %s\n"
                "Acceptance is based on 2xx status and absence of common validation text; verify business state manually."
                % (
                    point.name,
                    point.family,
                    payload,
                    status_code,
                    body_length,
                    elapsed_ms,
                    outcome,
                )
            )
        return {
            "field": point.getInsertionPointName(),
            "payload": payload,
            "http": status,
            "body_length": str(body_length),
            "elapsed_ms": "%.1f" % elapsed_ms,
            "outcome": outcome,
            "details": details,
        }

    def _set_controls_enabled(self, enabled):
        self.run_button.setEnabled(enabled)
        self.clear_button.setEnabled(enabled)
        self.unsafe_box.setEnabled(enabled)
        self.scanner_unsafe_box.setEnabled(enabled)

    def _show_results(self, rows):
        self.results = rows
        self.result_model.setRowCount(0)
        for row in rows:
            self.result_model.addRow(
                [
                    row["field"],
                    row["payload"],
                    row["http"],
                    row["body_length"],
                    row["elapsed_ms"],
                    row["outcome"],
                ]
            )
        self.result_details.setText("")

    def _show_selected_result(self, event):
        if event.getValueIsAdjusting():
            return
        row = self.result_table.getSelectedRow()
        if row < 0:
            self.result_details.setText("")
            return
        model_row = self.result_table.convertRowIndexToModel(row)
        if model_row < len(self.results):
            self.result_details.setText(self.results[model_row]["details"])

    def _clear_results(self):
        if self.running:
            return
        self.results = []
        self.result_model.setRowCount(0)
        self.result_details.setText("")
        self.status_label.setText("Results cleared.")

    def getInsertionPoints(self, base_request_response):
        request = base_request_response.getRequest()
        service = base_request_response.getHttpService()
        if request is None or service is None:
            return None
        try:
            request_info = self.helpers.analyzeRequest(service, request)
            method = str(request_info.getMethod()).upper()
            if not _scanner_method_allowed(method, self.scanner_state_changes_enabled):
                return None
            if not self.callbacks.isInScope(request_info.getUrl()):
                return None
            parameters = list(request_info.getParameters())
            counts = {}
            for parameter in parameters:
                key = (str(parameter.getName()).lower(), int(parameter.getType()))
                counts[key] = counts.get(key, 0) + 1
            seen = {}
            points = ArrayList()
            for parameter in parameters:
                name = str(parameter.getName())
                parameter_type = int(parameter.getType())
                family = _field_family(
                    name, str(parameter.getValue()), parameter_type
                )
                if family is None or not self._supported_type(parameter_type):
                    continue
                if int(parameter.getValueStart()) < 0 or int(parameter.getValueEnd()) < int(parameter.getValueStart()):
                    continue
                key = (name.lower(), parameter_type)
                seen[key] = seen.get(key, 0) + 1
                points.add(
                    _BoundaryInsertionPoint(
                        self, service, request, parameter, family, seen[key], counts[key]
                    )
                )
                if parameter_type in (int(IParameter.PARAM_URL), int(IParameter.PARAM_BODY)):
                    points.add(
                        _BoundaryInsertionPoint(
                            self, service, request, parameter, family, seen[key],
                            counts[key], True,
                        )
                    )
                if points.size() >= _MAX_FIELDS:
                    break
            return points if not points.isEmpty() else None
        except Exception as error:
            self.callbacks.printError("Could not create business insertion points: " + str(error))
            return None

    def doPassiveScan(self, base_request_response):
        return None

    def doActiveScan(self, base_request_response, insertion_point):
        if not isinstance(insertion_point, _BoundaryInsertionPoint):
            return None
        request = base_request_response.getRequest()
        service = base_request_response.getHttpService()
        if request is None or service is None:
            return None
        try:
            method, request_url = _request_location(self.helpers, service, request)
            if not _scanner_method_allowed(method, self.scanner_state_changes_enabled):
                return None
            if not self.callbacks.isInScope(request_url):
                return None
            for payload in _boundary_payloads(
                insertion_point.family, insertion_point.base_value
            ):
                test_request = insertion_point.buildRequest(
                    self.helpers.stringToBytes(payload)
                )
                exchange = self.callbacks.makeHttpRequest(service, test_request)
                response = exchange.getResponse() if exchange is not None else None
                if response is None or not _is_accepted(self.helpers, response):
                    continue
                response_info = self.helpers.analyzeResponse(response)
                issue = _BoundaryIssue(
                    self.helpers,
                    exchange,
                    insertion_point.getInsertionPointName(),
                    payload,
                    int(response_info.getStatusCode()),
                )
                issues = ArrayList()
                issues.add(issue)
                return issues
        except Exception as error:
            self.callbacks.printError("Business boundary scan failed: " + str(error))
        return None

    def consolidateDuplicateIssues(self, existing_issue, new_issue):
        if (
            existing_issue.getIssueName() == new_issue.getIssueName()
            and str(existing_issue.getUrl()) == str(new_issue.getUrl())
        ):
            return -1
        return 0
