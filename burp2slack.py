# A simple Burp Suite Extension to send issue notifications to a Slack channel while scanning
# Author: David Espejo (Fortytwo Security) david@fortytwo.nl
import json
import logging
import sys
from burp import IBurpExtender
from burp import IScannerListener
from burp import IHttpListener
from burp import ITab
from java.awt import Color
from javax import swing
from java.awt import Dimension
from java.net import URL, URLEncoder
from java.net import HttpURLConnection
from javax.net.ssl import HttpsURLConnection

# Route diagnostics to the file configured here AND to Burp's own output/error
# stream, so a failed delivery is visible even if the log file is unwritable.
# Burp captures stderr from extension threads and shows it in the Extensions >
# Errors output tab.
LOG_FILENAME = 'burp2slack.log'
logging.basicConfig(
    filename=LOG_FILENAME,
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
)


def _log(level, message):
    """Emit to the log file and to Burp's output stream.

    Both sinks are used deliberately: the file survives a restart, stderr is
    what a user sees while scanning.

    Uses sys.stderr.write rather than print(..., file=...) because Burp's
    embedded Jython is Python 2.7, where print(file=...) is a SyntaxError.
    """
    try:
        level_no = logging.getLevelName(level)
        if isinstance(level_no, int):
            logging.log(level_no, message)
    except Exception as e:
        # Never let logging itself break issue processing, but do not fail
        # silently either: a broken log sink is exactly the kind of failure
        # this extension was supposed to surface.
        try:
            sys.stderr.write("[Burp2SlackIssues] logging failure: {}\n".format(e))
        except Exception:
            pass
    try:
        sys.stderr.write("[Burp2SlackIssues] {}: {}\n".format(level, message))
    except Exception:
        pass

class BurpExtender(IBurpExtender, IScannerListener, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Burp2SlackIssues")
        callbacks.registerScannerListener(self)
        callbacks.registerHttpListener(self)

        # UI
        self.tab = swing.JPanel()
        layout = swing.GroupLayout(self.tab)
        self.tab.setLayout(layout)
        layout.setAutoCreateGaps(True)

        titleLabel = swing.JLabel("Channel Configuration")
        titleLabel.setFont(titleLabel.getFont().deriveFont(24.0))
        titleLabel.setForeground(Color(255, 140, 0))

        webhookLabel = swing.JLabel("Slack Webhook URL:")
        self.webhookInput = swing.JTextField('', 80)
        self.webhookInput.setMaximumSize(Dimension(500, 30))  # set the max size to limit height

        # Load saved webhook URL
        webhook_url = callbacks.loadExtensionSetting('webhook_url')
        if webhook_url is not None:
            self.webhookInput.setText(webhook_url)
        notificationTitleLabel = swing.JLabel("Notification Configuration")
        notificationTitleLabel.setFont(notificationTitleLabel.getFont().deriveFont(24.0))
        notificationTitleLabel.setForeground(Color(255, 140, 0))

        separator = swing.JSeparator()  # create a separator

        self.requestBox = swing.JCheckBox("Include request")
        self.responseBox = swing.JCheckBox("Include response")

        self.severityBox = {
            'Information': swing.JCheckBox("Information"),
            'Low': swing.JCheckBox("Low"),
            'Medium': swing.JCheckBox("Medium"),
            'High': swing.JCheckBox("High"),
            'Critical': swing.JCheckBox("Critical")
        }

        self.confidenceBox = {
            'Firm': swing.JCheckBox("Firm"),
            'Certain': swing.JCheckBox("Certain"),
            'Tentative': swing.JCheckBox("Tentative")
        }

        saveButton = swing.JButton('Save', actionPerformed=self.saveConfig)

        layout.setHorizontalGroup(
            layout.createParallelGroup()
                .addGroup(layout.createSequentialGroup()
                    .addComponent(titleLabel))
                .addGroup(layout.createSequentialGroup()
                    .addComponent(webhookLabel)
                    .addComponent(self.webhookInput))
                .addComponent(separator)  # add separator to layout
                .addGroup(layout.createSequentialGroup()
                    .addComponent(notificationTitleLabel))
                .addGroup(layout.createSequentialGroup()
                    .addComponent(self.requestBox))
                .addGroup(layout.createSequentialGroup()
                    .addComponent(self.responseBox))
                .addGroup(layout.createSequentialGroup()
                    .addComponent(self.severityBox['Information'])
                    .addComponent(self.severityBox['Low'])
                    .addComponent(self.severityBox['Medium'])
                    .addComponent(self.severityBox['High'])
                    .addComponent(self.severityBox['Critical']))
                .addGroup(layout.createSequentialGroup()
                    .addComponent(self.confidenceBox['Firm'])
                    .addComponent(self.confidenceBox['Certain'])
                    .addComponent(self.confidenceBox['Tentative']))
                .addGroup(layout.createSequentialGroup()
                    .addComponent(saveButton))
        )
        layout.setVerticalGroup(
            layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup()
                    .addComponent(titleLabel))
                .addGroup(layout.createParallelGroup()
                    .addComponent(webhookLabel)
                    .addComponent(self.webhookInput))
                .addComponent(separator)  # add separator to layout
                .addGroup(layout.createParallelGroup()
                    .addComponent(notificationTitleLabel))
                .addPreferredGap(swing.LayoutStyle.ComponentPlacement.RELATED)  # Add a related gap
                .addGroup(layout.createParallelGroup()
                    .addComponent(self.requestBox))
                .addGroup(layout.createParallelGroup()
                    .addComponent(self.responseBox))
                .addGroup(layout.createParallelGroup()
                    .addComponent(self.severityBox['Information'])
                    .addComponent(self.severityBox['Low'])
                    .addComponent(self.severityBox['Medium'])
                    .addComponent(self.severityBox['High'])
                    .addComponent(self.severityBox['Critical']))
                .addGroup(layout.createParallelGroup()
                    .addComponent(self.confidenceBox['Firm'])
                    .addComponent(self.confidenceBox['Certain'])
                    .addComponent(self.confidenceBox['Tentative']))
                .addGroup(layout.createParallelGroup()
                    .addComponent(saveButton))
        )

        callbacks.addSuiteTab(self)
        return

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # To be implemented. This will process all HTTP messages from Proxy
        pass

    def newScanIssue(self, issue):
        # logging.debug('newScanIssue called')
        issueDetails = None
        try:
            if self.severityBox[issue.getSeverity()].isSelected() and self.confidenceBox[issue.getConfidence()].isSelected():
                # logging.debug('Severity and Confidence selected')
                issueDetails = {
                    'title': issue.getIssueName(),
                    'severity': issue.getSeverity(),
                    'confidence': issue.getConfidence(),
                    'host': issue.getHttpService().getHost(),
                    'path': issue.getUrl().getPath(),
                }
                if self.requestBox.isSelected() or self.responseBox.isSelected():
                    httpMessages = issue.getHttpMessages()
                    if httpMessages:
                        if self.requestBox.isSelected():
                            request = self._helpers.bytesToString(httpMessages[0].getRequest())
                            issueDetails['request'] = request[:500]
                        if self.responseBox.isSelected():
                            response = self._helpers.bytesToString(httpMessages[0].getResponse())
                            issueDetails['response'] = response[:500]
                chunks = self.split_message(json.dumps(issueDetails), 2000)
                for chunk in chunks:
                    self.send_notification(chunk)
        except Exception as e:
            # Previously this handler was a bare `pass`, so every failure to
            # build or deliver a notification was invisible.
            _log('ERROR', 'Error in newScanIssue: {}'.format(e))
            _log('DEBUG', 'Issue details were: {}'.format(issueDetails))

    def send_notification(self, text):
        params = None
        try:
            url = URL(self.webhookInput.getText())
            connection = url.openConnection()
            connection.setDoOutput(True)
            connection.setRequestMethod("POST")
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")

            # Format the parameters
            payload = {"text": text}
            params = "payload={}".format(URLEncoder.encode(json.dumps(payload), "UTF-8"))

            _log('DEBUG', 'Sending notification with payload: {}'.format(params))

            output = connection.getOutputStream()
            output.write(params.encode("UTF-8"))
            output.close()

            responseCode = connection.getResponseCode()
            responseMessage = connection.getResponseMessage()

            _log('DEBUG', "Slack response code: {}".format(responseCode))
            _log('DEBUG', "Slack response message: {}".format(responseMessage))
            if responseCode != HttpURLConnection.HTTP_OK:
                # Previously `pass`: a 4xx/5xx from Slack was silently discarded.
                _log('ERROR', "Failed to send message to Slack: HTTP {} {}".format(responseCode, responseMessage))

        except Exception as e:
            # Previously `pass`: every transport-level failure was invisible.
            # `params` may be unbound if the failure happened before line 171.
            _log('ERROR', "Failed to send message to Slack: {}".format(e))
            _log('DEBUG', "Payload was: {}".format(params))

    def getTabCaption(self):
        return "Burp2SlackIssues"

    def getUiComponent(self):
        return self.tab

    def saveConfig(self, event):
        # logging.debug('saveConfig called')
        webhook_url = self.webhookInput.getText()
        self._callbacks.saveExtensionSetting('webhook_url', webhook_url)
        include_request = self.requestBox.isSelected()
        include_response = self.responseBox.isSelected()
        include_severity = {k: v.isSelected() for k, v in self.severityBox.items()}
        include_confidence = {k: v.isSelected() for k, v in self.confidenceBox.items()}
        # logging.debug('Saved configuration: webhook_url={}, include_request={}, include_response={}, include_severity={}, include_confidence={}'.format(webhook_url, include_request, include_response, include_severity, include_confidence))

        # Send a test notification
        self.send_notification('Extension configured')

    def split_message(self, message, length):
        return [message[i:i+length] for i in range(0, len(message), length)]

