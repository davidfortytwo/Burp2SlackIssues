# Burp2SlackIssues
Burp Extension to connect to Slack, with filtering options

## Data egress

This extension sends data to an **external Slack webhook**. The webhook URL is
configured by the operator and is stored as a Burp extension setting; whatever
you paste there is the destination for all issue data.

What leaves your machine:

| Field | Source | Truncation |
|---|---|---|
| `title` | `issue.getIssueName()` | none |
| `severity` | `issue.getSeverity()` | none |
| `confidence` | `issue.getConfidence()` | none |
| `host` | `issue.getHttpService().getHost()` | none |
| `path` | `issue.getUrl().getPath()` | none |
| `request` | raw HTTP request, **only if "Include request" is checked** | first 500 chars (`burp2slack.py`) |
| `response` | raw HTTP response, **only if "Include response" is checked** | first 500 chars (`burp2slack.py`) |

Be aware of two things:

1. **The request and response bodies are not redacted.** The first 500
   characters of a raw HTTP request very often contain `Authorization` headers,
   session cookies, bearer tokens and API keys, and the first 500 characters of
   a response often contain JSON payloads containing the same. Anything captured
   this way is transmitted to a third-party service outside your perimeter.
   Leave both checkboxes unchecked unless you have accepted that.
2. **Slack is an external processor.** Issue data, including whatever secrets the
   first 500 characters contain, is disclosed to Slack. For engagements with
   client-confidential data, point the extension at a self-hosted Slack or use a
   separate non-production Burp instance.

The `split_message()` helper additionally chunks the JSON payload into 2000-char
pieces, so one issue can produce multiple webhook requests.

## Troubleshooting

Failures were previously swallowed by two `except Exception: pass` handlers with
all logging commented out, so a misconfigured webhook produced no output at all.
Both handlers now log. Diagnostics go to two places:

- `burp2slack.log`, next to wherever Burp was started (`logging`, DEBUG level).
- Burp's own output stream — see the **Extensions > Errors** output tab.

Every delivered notification and every failure is logged at DEBUG, including the
exact payload sent and the HTTP status returned by Slack.