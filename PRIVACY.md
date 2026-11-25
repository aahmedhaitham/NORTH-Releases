# NORTH privacy policy

## Local desktop use

NORTH opens in local mode. It reads network addresses assigned to the computer, device addresses Windows has observed, and a limited set of recent Sysmon records when the account can read that log. Those records can include hostnames, IP addresses, hardware addresses, process names, filenames, and timestamps. NORTH uses them to show your network inventory, event history, and investigation evidence.

The local desktop stores its device history and any saved cloud workspace address in its application data folder. Local mode does not send Windows events or network observations to a NORTH server. Reports are saved to a location you choose when you export them.

## Optional workspace and collectors

When you connect the desktop to a cloud workspace, it contacts the HTTPS address you select for sign-in and data retrieval. Connecting the desktop does not start a collector. When you separately pair and start a collector with a workspace, the collector sends its events, investigation reports, device observations and configured router traffic totals to that workspace. The workspace operator controls access and retention. Stopping a collector or revoking its key stops future syncs. Existing workspace records remain until the operator removes them.

## Optional AI

The local Ollama feature sends evidence-derived observations to the Ollama service you configure. If the workspace operator enables Workers AI, the cloud service sends generic event descriptions to Cloudflare to prioritize observations. This feature keeps raw logs, device addresses, hostnames, and evidence IDs out of the model input.
