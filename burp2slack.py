# A simple Burp Suite Extension to send issue notifications to a Slack channel while scanning
# Author: David Espejo (Fortytwo Security) david@fortytwo.nl
import json
# import logging
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

# logging.basicConfig(filename='burp2slack.log', level=logging.DEBUG)

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
            # logging.error('Error in newScanIssue: ' + str(e))
            # logging.debug('Issue details were: ' + json.dumps(issueDetails))  # Log the issue details
            pass

    def send_notification(self, text):
        try:
            url = URL(self.webhookInput.getText())
            connection = url.openConnection()
            connection.setDoOutput(True)
            connection.setRequestMethod("POST")
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")

            # Format the parameters
            payload = {"text": text}
            params = "payload={}".format(URLEncoder.encode(json.dumps(payload), "UTF-8"))

            # logging.debug('Sending notification with payload: {}'.format(params))  # Log the payload

            output = connection.getOutputStream()
            output.write(params.encode("UTF-8"))
            output.close()

            responseCode = connection.getResponseCode()
            responseMessage = connection.getResponseMessage()

            # logging.debug("Slack response code: {}".format(responseCode))
            # logging.debug("Slack response message: {}".format(responseMessage))
            if responseCode != HttpURLConnection.HTTP_OK:
                pass
                # logging.error("Failed to send message to Slack")

        except Exception as e:
            pass
            # logging.error("Failed to send message to Slack: {} Payload was: {}".format(e, params))  # Log the exception and the payload

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

