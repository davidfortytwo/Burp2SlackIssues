"""Regression tests for the davidfortytwo/Burp2SlackIssues remediation.

DEFECT: two `except Exception: pass` blocks (burp2slack.py ~156-159 and
~188-190) with every logging call commented out, so every delivery failure
was invisible. The module also cannot be imported outside Burp because it
depends on the Jython-only `burp` / `java.*` modules, so the tests stub
those out and exercise the extension logic directly.

Run with:  python test_burp2slack.py
"""
import importlib.util
import io
import logging
import os
import sys
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TARGET = os.path.join(HERE, "burp2slack.py")


# --------------------------------------------------------------------------
# Minimal stand-ins for the Jython-only modules Burp provides.
# --------------------------------------------------------------------------
class _FakeSwing(object):
    def __getattr__(self, name):
        def _factory(*a, **kw):
            return _FakeWidget()
        return _factory


class _FakeWidget(object):
    def __init__(self, *a, **kw):
        self._selected = True
        self._text = ""

    def isSelected(self):
        return self._selected

    def setSelected(self, value):
        self._selected = value

    def getText(self):
        return self._text

    def setText(self, value):
        self._text = value

    def getFont(self):
        return self

    def deriveFont(self, size):
        return self

    def setFont(self, f):
        pass

    def setForeground(self, c):
        pass

    def setMaximumSize(self, s):
        pass

    def setLayout(self, l):
        pass


def install_jython_stubs():
    """Install fake `burp`, `java.*` and `javax.*` modules into sys.modules."""
    burp = types.ModuleType("burp")

    class _Iface(object):
        pass

    for name in ("IBurpExtender", "IScannerListener", "IHttpListener", "ITab"):
        setattr(burp, name, type(name, (_Iface,), {}))
    sys.modules["burp"] = burp

    java_pkg = types.ModuleType("java")
    java_pkg.__path__ = []
    awt = types.ModuleType("java.awt")
    awt.Color = lambda *a, **kw: None
    awt.Dimension = lambda *a, **kw: None
    swing = types.ModuleType("javax.swing")
    swing.__getattr__ = lambda name: _FakeSwing()
    net = types.ModuleType("java.net")
    net.URL = _FakeURL
    net.URLEncoder = _FakeURLEncoder
    net.HttpURLConnection = _FakeHttpURLConnection
    ssl = types.ModuleType("javax.net.ssl")
    ssl.HttpsURLConnection = _FakeHttpURLConnection

    java_pkg.awt = awt
    java_pkg.net = net
    javax_pkg = types.ModuleType("javax")
    javax_pkg.__path__ = []
    javax_pkg.swing = swing
    javax_pkg.net = net

    for name, mod in (("java", java_pkg), ("java.awt", awt), ("java.net", net),
                      ("javax", javax_pkg), ("javax.swing", swing),
                      ("javax.net.ssl", ssl)):
        sys.modules[name] = mod


class _FakeURL(object):
    def __init__(self, url):
        self.url = url

    def openConnection(self):
        return _FakeHttpURLConnection()


class _FakeURLEncoder(object):
    @staticmethod
    def encode(value, encoding):
        return value.replace(" ", "%20")


class _FakeHttpURLConnection(object):
    HTTP_OK = 200
    response_code = 200
    fail_on_write = False

    def __init__(self, *a, **kw):
        self.written = b""
        self.props = {}

    def setDoOutput(self, v):
        pass

    def setRequestMethod(self, m):
        pass

    def setRequestProperty(self, k, v):
        self.props[k] = v

    def getOutputStream(self):
        outer = self

        class _Out(object):
            def write(self, data):
                if _FakeHttpURLConnection.fail_on_write:
                    raise IOError("connection reset by peer")
                outer.written += data

            def close(self):
                pass

        return _Out()

    def getResponseCode(self):
        return _FakeHttpURLConnection.response_code

    def getResponseMessage(self):
        return "OK" if _FakeHttpURLConnection.response_code == 200 else "Bad Request"


def load_module():
    install_jython_stubs()
    spec = importlib.util.spec_from_file_location("burp2slack_under_test", TARGET)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class CapturedLog(logging.Handler):
    """Capture records emitted through the logging module."""

    def __init__(self):
        logging.Handler.__init__(self, logging.DEBUG)
        self.records = []

    def emit(self, record):
        self.records.append((record.levelname, record.getMessage()))

    def levels(self):
        return [lvl for lvl, _ in self.records]

    def text(self):
        return "\n".join("{}: {}".format(lvl, msg) for lvl, msg in self.records)


class TestLoggingIsWired(unittest.TestCase):
    """DEFECT: every logging call was commented out and handlers were `pass`."""

    def setUp(self):
        self.mod = load_module()
        self.log = CapturedLog()
        root = logging.getLogger()
        root.setLevel(logging.DEBUG)
        root.addHandler(self.log)
        self.addCleanup(root.removeHandler, self.log)
        self.addCleanup(root.setLevel, root.level)

    def test_logging_is_imported(self):
        with open(TARGET, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("import logging", src)
        self.assertNotIn("# import logging", src)

    def test_basicconfig_is_not_commented_out(self):
        with open(TARGET, encoding="utf-8") as fh:
            src = fh.read()
        self.assertNotIn("# logging.basicConfig", src)
        self.assertIn("logging.basicConfig", src)

    def test_no_silent_pass_in_exception_handlers(self):
        """The two silent handlers must no longer be bare `pass`."""
        import ast
        with open(TARGET, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), TARGET)

        # Scope: the two handlers named in the defect report.
        targets = ("newScanIssue", "send_notification")
        silent = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == "BurpExtender":
                for fn in node.body:
                    if isinstance(fn, ast.FunctionDef) and fn.name in targets:
                        for handler in ast.walk(fn):
                            if isinstance(handler, ast.ExceptHandler):
                                body = handler.body
                                if len(body) == 1 and isinstance(body[0], ast.Pass):
                                    silent.append((fn.name, handler.lineno))
        self.assertEqual(silent, [],
                         "except handler(s) {0} still swallow the error".format(silent))

    def test_log_helper_writes_to_stderr(self):
        import logging
        buf = io.StringIO()
        old = sys.stderr
        sys.stderr = buf
        try:
            self.mod._log('ERROR', 'delivery failed')
        finally:
            sys.stderr = old
        self.assertIn("delivery failed", buf.getvalue())
        self.assertIn("ERROR", buf.getvalue())


class TestSendNotificationLogsFailures(unittest.TestCase):
    """DEFECT: send_notification() swallowed every transport failure."""

    def setUp(self):
        self.mod = load_module()
        self.log = CapturedLog()
        root = logging.getLogger()
        root.setLevel(logging.DEBUG)
        root.addHandler(self.log)
        self.addCleanup(root.removeHandler, self.log)
        self.addCleanup(root.setLevel, root.level)

        class _Box(object):
            def getText(self):
                return "https://hooks.slack.example/T/B/X"

        class _Ext(object):
            webhookInput = _Box()

        self.ext = _Ext()

    def test_transport_failure_is_logged(self):
        _FakeHttpURLConnection.fail_on_write = True
        try:
            self.mod.BurpExtender.send_notification(self.ext, "hello")
        finally:
            _FakeHttpURLConnection.fail_on_write = False
        text = self.log.text()
        self.assertIn("Failed to send message to Slack", text)
        self.assertIn("ERROR", self.log.levels())

    def test_non_200_response_is_logged(self):
        _FakeHttpURLConnection.response_code = 400
        try:
            self.mod.BurpExtender.send_notification(self.ext, "hello")
        finally:
            _FakeHttpURLConnection.response_code = 200
        text = self.log.text()
        self.assertIn("Failed to send message to Slack", text)
        self.assertIn("400", text)

    def test_successful_send_logs_debug(self):
        self.mod.BurpExtender.send_notification(self.ext, "hello")
        text = self.log.text()
        self.assertIn("Slack response code: 200", text)


class TestNewScanIssueLogsFailures(unittest.TestCase):
    """DEFECT: newScanIssue() swallowed every build/delivery failure."""

    def setUp(self):
        self.mod = load_module()
        self.log = CapturedLog()
        root = logging.getLogger()
        root.setLevel(logging.DEBUG)
        root.addHandler(self.log)
        self.addCleanup(root.removeHandler, self.log)
        self.addCleanup(root.setLevel, root.level)

    def test_error_is_logged_when_issue_lookup_fails(self):
        class _Ext(object):
            # Empty dicts: the lookup `self.severityBox[issue.getSeverity()]`
            # evaluates issue.getSeverity() first, which raises.
            severityBox = {}
            confidenceBox = {}

        class _BadIssue(object):
            def getSeverity(self):
                raise ValueError("unknown severity")

        ext = _Ext()
        try:
            self.mod.BurpExtender.newScanIssue(ext, _BadIssue())
        except Exception:
            # The handler catches Exception, so nothing should escape.
            pass
        text = self.log.text()
        self.assertIn("Error in newScanIssue", text)
        self.assertIn("unknown severity", text)
        self.assertIn("ERROR", self.log.levels())


class TestReadmeDocumentsEgress(unittest.TestCase):
    """Requirement: document the HTTP response body egress to the webhook."""

    def test_readme_documents_response_body_egress(self):
        with open(os.path.join(HERE, "README.md"), encoding="utf-8") as fh:
            src = fh.read()
        low = src.lower()
        self.assertIn("egress", low)
        self.assertIn("response", low)
        self.assertIn("500", src)
        self.assertIn("slack", low)

    def test_readme_mentions_unredacted_secrets(self):
        with open(os.path.join(HERE, "README.md"), encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("redact", src.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)