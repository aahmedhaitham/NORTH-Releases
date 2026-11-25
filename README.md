# NORTH

**Network Operations, Reconnaissance, Threat Hunting**

NORTH is a Windows security console for investigating activity on your PC. It opens to local data without an account, server address, or access key.

[Download the Windows x64 preview](https://github.com/aahmedhaitham/NORTH-Releases/releases/tag/v0.2.0-preview.1) · [MIT License](LICENSE)

- **ATLAS** shows local interfaces, observed devices, and network connections.
- **IRIS** lets you inspect recent Windows events when Sysmon is installed and readable.
- **ECHO** links related events into a timeline with source evidence.

The desktop preview is unsigned. Windows may show a publisher warning. The instructions below cover development, use with synthetic fixtures, and optional self-hosted infrastructure.

## Run the demo on Windows

After installing the dependencies below once, double-click **Start NORTH.cmd** in the repository folder to start the backend and frontend. Double-click it again to restart both. If they were started manually, stop those tabs with **Ctrl+C** the first time. Open or refresh [the console](http://127.0.0.1:5173/). To stop servers started by the launcher, run `& '.\Start NORTH.cmd' -Stop` from PowerShell in the repository folder.

From the repository root, use two PowerShell terminals. The native setup uses SQLite and works without Docker or Ollama.

Terminal 1:

```powershell
Set-Location backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m uvicorn main:app
```

Terminal 2:

```powershell
Set-Location frontend
npm.cmd ci
npm.cmd run dev
```

Open [the console](http://127.0.0.1:5173). Select the PowerShell case, inspect the ATLAS evidence link, replay the timeline in ECHO, and export the report. Open **Raw evidence** to see the original sanitized event.

**Overview** is the home screen for activity charts, event counts, recent cases, and collector health. Use **ATLAS** for devices and observed connections, **IRIS** to search the event feed, and **ECHO** to replay investigations. A supported browser can install NORTH as a standalone app. Look for **Install NORTH** or your browser's install option. An installed local instance still connects to the NORTH servers on that device. Other devices need a reachable HTTPS deployment.

With Docker and Compose available, run `docker compose up --build` at the repository root and open [the Docker console](http://127.0.0.1:8080). Compose uses PostgreSQL and keeps the database on a named volume.

## Run on Kali or another Linux distribution

Use the Docker Compose command above, or run the same two services natively with Python 3.14 and Node 26. From `backend`, use `python3 -m venv .venv`, `.venv/bin/python -m pip install -r requirements-dev.txt`, then `.venv/bin/python -m uvicorn main:app`. In a second terminal from `frontend`, use `npm ci` and `npm run dev`.

To try a Linux case with the backend running, run `python ingest.py fixtures/linux-ssh-demo.jsonl --format journal` from `backend` on Windows, or use `python3` on Kali. The fixture contains three synthetic OpenSSH failures and requires no SSH service.

For a real Kali journal sample without starting SSH, run `sudo /usr/bin/true`, then `sudo journalctl _COMM=sudo --since '2 minutes ago' --no-pager -o json --grep 'COMMAND=/usr/bin/true$' > kali-journal.jsonl`. Transfer that local file to the Git-ignored `raw-logs` directory, preview with `python backend/ingest.py raw-logs/kali-journal.jsonl --format journal --check`, and omit `--check` to import. This produces an observed sudo command case from the actual journal.

## Deploy the public portfolio demo

Create a [Render Blueprint](https://render.com/docs/infrastructure-as-code) connected to this repository. The included `render.yaml` deploys a single Docker web service. It serves the React console and the FastAPI routes from the same HTTPS origin, including the live WebSocket, timeline replay and report export. Visitors can investigate the bundled synthetic Windows and Kali cases without an account. Ingestion and live model calls are disabled on the public instance. The demo uses an ephemeral SQLite database seeded at startup. The PostgreSQL configuration remains available through Docker Compose.

After deployment, run the smoke check against the assigned URL with `python backend/smoke_demo.py https://YOUR-SERVICE.onrender.com --read-only` from a Python environment with the backend requirements installed.

For a static portfolio build, run `npm run build -- --mode portfolio` from `frontend`, then run `python backend/export_portfolio.py frontend/dist/demo` from the repository root using the backend environment. Upload the contents of `frontend/dist` to a static host such as [Cloudflare Pages](https://developers.cloudflare.com/pages/get-started/direct-upload/). This version replays the two bundled synthetic cases in the browser and provides their reports as downloads. It does not connect to the local NORTH database.

## Run a private NORTH Cloud workspace

The Cloudflare Worker serves the browser app and uses D1 for private collector data. The console remains available when collectors are off and displays each collector's last sync time. A single operator can switch between multiple collector feeds. NORTH stores events and investigation reports by collector and adds events in batches of up to 100. A collector records a batch as delivered only after the cloud accepts it. The network view displays the latest snapshot for the selected collector.

From the repository root:

On Windows, after `npx wrangler login`, run `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Deploy-NorthCloud.ps1` to create or reuse the database, build the app, and configure the secrets. Run it with `-ShowAccessKey` to display the sign-in key on the same Windows account. The encrypted keys stay under the ignored `.north-launcher` directory. This command does not send local telemetry. The manual equivalents and collector setup follow.

1. Authenticate with `npx wrangler login`, run `npx wrangler d1 create north-cloud`, and copy `cloud/wrangler.example.jsonc` to `cloud/wrangler.jsonc`. Set `database_id` to the ID returned by Wrangler.
2. Run `npx wrangler d1 execute north-cloud --config cloud/wrangler.jsonc --remote --file cloud/schema.sql`, then `npm --prefix frontend run build -- --mode cloud` and `npx wrangler deploy --config cloud/wrangler.jsonc`.
3. Generate three independent random secrets, each at least 32 characters. Run `npx wrangler secret put NORTH_ACCESS_KEY --config cloud/wrangler.jsonc` for the sign-in key, then repeat separately for `NORTH_INGEST_KEY` and `NORTH_SESSION_SECRET`. Keep those values private.
4. To opt in to uploading your actual local telemetry, set `NORTH_CLOUD_URL` and `NORTH_CLOUD_INGEST_KEY` in the terminal used to start NORTH. Set distinct `NORTH_CLOUD_SOURCE` identifiers for collectors that share a workspace, such as `main-pc` and `lab-vm`. Optionally set `NORTH_CLOUD_LABEL` to a friendly name. On Windows, start NORTH in that same terminal with `& '.\Start NORTH.cmd'`. The collector sends batches that include source event fields and network observations to the HTTPS workspace. Leave the cloud variables unset to keep telemetry local.

Use the sign-in key from a phone or computer at the deployed HTTPS URL. The cloud console can manage collector access. Ollama drafting runs with the local backend.

To connect an additional Windows device, open **Collectors**, give the device a name and select **Create pairing**. On the device, install Python 3.11 or later with the Windows launcher and run the displayed command from the NORTH folder. Enter the HTTPS workspace address and the key when prompted. The standalone collector installs its Python dependencies on first launch, stores its key for the current Windows user, and runs without the development servers. Double-click **Start NORTH Collector.cmd** for later sessions. Leave its window open while collecting. Sysmon event collection requires permission to read the existing Sysmon log. Revoke a pairing from **Collectors** to stop future uploads while keeping its existing history.

ECHO surfaces cross-collector observations sharing an address within five minutes of a case's latest event. IRIS can make a brief with citations to that case's events. Deploy with `-EnableCloudAI` to let Workers AI prioritize the brief using generic event descriptions. Hostnames, addresses, raw logs and evidence IDs stay out of the model input. The brief remains available from recorded evidence when the model is off or unavailable. [Workers AI bindings](https://developers.cloudflare.com/workers-ai/configuration/bindings/)

For per-device traffic, the standalone collector supports an OpenWrt router running `nlbwmon`. Use an SSH host alias that already works with key authentication and a verified host key, then run `& '.\Start NORTH Collector.cmd' -OpenWrtHost my-router` on the paired collector. ATLAS displays download and upload totals by device MAC from the router's current accounting period. These counters depend on the router's forwarding and accounting coverage. [OpenWrt traffic accounting documentation](https://github.com/jow-/nlbwmon)

To remember the cloud connection in the Windows launcher, run `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Connect-NorthCloud.ps1 -Enable -Url https://YOUR-WORKSPACE.workers.dev`, then restart with **Start NORTH.cmd**. This opts the PC into sending its collected events, investigations, and network observations to that private workspace. To stop future syncs, run the same tool with `-Disable` and restart NORTH. Disconnecting the collector does not delete data already stored in Cloudflare.

### Windows desktop client

The Windows x64 client opens directly on **This computer**. It displays local network interfaces, nearby devices from the Windows neighbor cache, and up to 200 recent Sysmon events if the account can read that log. It can link a PowerShell process to a script file creation for an evidence timeline. Local data is read on demand and stays on the computer. A browser, Python, server address and key are unnecessary for local use.

Use **Workspace → Open cloud workspace** to open a saved or build-time workspace, or **Connect to a different workspace** to enter another HTTPS address. Cloud sign-in and collector pairing apply to that private workspace. The desktop cloud session lasts until the app closes or the cloud session expires.

To build the portable client from the repository root, run `npm.cmd --prefix frontend ci`, `npm.cmd --prefix desktop ci`, and `npm.cmd --prefix desktop run package:windows`. The portable file is `desktop/dist/NORTH-Desktop-Windows-x64.exe`. Set `NORTH_DESKTOP_DEFAULT_URL` at build time to provide an optional cloud workspace.

Run `npm.cmd --prefix desktop run package:installer` to build `desktop/dist/NORTH-Setup-Windows-x64.exe`. The manual **Build NORTH for Windows** GitHub workflow packages both Windows builds. Code signing requires a publisher certificate.

## Add lab data or use local AI

### View your network

Open **Network** to see reporting devices and observed inbound and outbound connections. Select a linked investigation to review its evidence.

Open **Events** to search collected telemetry by host, process, address, or keyword. Filter by event type and expand a record to view its source fields and evidence ID. The newest page refreshes automatically. Older pages use a timestamp and event ID cursor so new activity does not move the page boundary.

On Windows, **Start NORTH.cmd** includes the automatic neighbor-cache collector. It reads the existing cache every 30 seconds and keeps the current snapshot in memory. On a native Linux installation, start FastAPI with `NORTH_NETWORK_AUTO=1 .venv/bin/python -m uvicorn main:app` and the `ip` utility available. Enable automatic collection only for a private NORTH instance. The public deployment disables it.

The first usable snapshot starts a saved device baseline. NORTH flags previously unseen MAC-and-interface combinations in subsequent snapshots. Open **Newly observed devices** to see the addresses and first/last observation times, then mark a finding reviewed. A changed or randomized MAC can show as new, and moving the collector to another network can reveal many new devices. The finding records a cache observation and does not determine whether a device is harmful or still online.

On Windows, the launcher also collects configured Sysmon process, connection and file-creation records about every 15 seconds after Sysmon is installed. NORTH saves the record cursor with the imported events and resumes after a restart. The launcher does not install or reconfigure Sysmon. Check **Windows event collection** in **Network** for status.

For another device source, choose **Import a device list**. You can load a saved neighbor cache or a router inventory converted to a JSON array with fields `address`, optional `name` and `mac`. The browser keeps imported records in memory and clears them when the page reloads.

- **Wazuh and Sysmon.** Preview a sanitized export from an authorized, isolated lab with `python backend/ingest.py path/to/alerts.json --check`. NORTH accepts a JSON array, JSON Lines, or indexer search hits containing `_source`. It selects Sysmon event IDs 1, 3, and 11 and reports how many cases the export can reconstruct. Omit `--check` to import into a running local backend. For Docker, add `--base-url http://127.0.0.1:8080`. Start with a fresh database and set `NORTH_SEED_DEMO=0` to evaluate lab events independently of the bundled case. Wazuh alerts can omit telemetry below the alert threshold, so consult the [Wazuh alert documentation](https://documentation.wazuh.com/current/user-manual/manager/alert-management.html) if expected events are missing.
- **Linux OpenSSH.** If OpenSSH already writes to your Linux journal, export your own service's existing records with `journalctl -u ssh.service -u sshd.service --since today --no-pager -o json > ssh-journal.jsonl`. Preview with `python3 backend/ingest.py ssh-journal.jsonl --format journal --check`. Omit `--check` to import to your local NORTH instance. IRIS flags groups of three failures from the same source on the same host within five minutes, ATLAS maps the inbound address, and ECHO lists the original events. Keep real exports local.
- **Ollama.** With a local server running and `qwen2.5-coder:7b` available, click **Generate draft** in IRIS. Override the server or model with `OLLAMA_URL` or `OLLAMA_MODEL` as needed. NORTH derives observations and their citations from Sysmon event types. Ollama ranks those observations, and NORTH accepts only selections drawn from the current case. Analysts can open the cited raw events in ECHO. The rule-based report works independently.

The console binds to localhost in the documented setups. Its API has no user authentication and is intended for a single analyst in a local lab.

### Local model benchmark

With Ollama running, execute `.\.venv\Scripts\python.exe compare_models.py` from `backend`. The script calls the NORTH draft endpoint in-process against the bundled case and a version with the network event removed.

On the development laptop, `qwen2.5-coder:7b` returned six valid drafts out of six, ranked file creation first in all six, and took a median of **0.61 seconds** after warm-up. The reported `huihui_ai/qwen3-abliterated:8b-v2` run was partial. Its warm-up and first two timed runs returned HTTP 502 because the endpoint could not verify the model selection. The two timed attempts took **6.20 seconds** and **6.57 seconds**. These observations support keeping Qwen2.5-Coder as the default for the current IRIS configuration.

## Test and explain

For a live Windows capture without a Wazuh server, use [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) with `tools/sysmon-demo.xml` on a machine where Sysmon is not already configured. Run `tools/Capture-NorthTelemetry.ps1` in PowerShell with access to the Sysmon log. It creates a comment-only file and exports its process and file-creation events to the Git-ignored `raw-logs` folder. Preview the resulting JSON with `python backend/ingest.py <capture.json> --check`, then omit `--check` to import it into a running local backend. This direct capture checks Sysmon and NORTH ingestion. Checking Wazuh forwarding requires a Wazuh deployment.

### Verify Wazuh forwarding

1. Use an authorized, isolated [Wazuh manager on a supported Linux host](https://documentation.wazuh.com/current/installation-guide/wazuh-server/index.html) and [enroll the Windows agent](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/index.html). Keep the manager and agent traffic on the private lab network.
2. Add the block in `tools/wazuh-sysmon-localfile.xml` inside the agent's existing `ossec_config` and restart the agent. Use a fresh run of the capture script after enrollment. [Wazuh event-channel collection](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/configuration.html)
3. Find the marker from the fresh capture in the manager's JSON alerts or, with JSON archiving enabled for the test, its JSON archive. Keep only the matching process and file-creation records. Copy the resulting JSON Lines into the Git-ignored `raw-logs` folder and run the NORTH import with `--check`. Expect two supported events and one case. Then import and verify both records in ECHO. [Wazuh event logging](https://documentation.wazuh.com/current/user-manual/manager/event-logging.html)

Run `.\.venv\Scripts\python.exe -m pytest tests` from `backend`, and `npm.cmd run build` from `frontend`. For a standard-library-only core check, run `python -m unittest discover -s tests -p test_core.py` from `backend`.

The repository's **Verify NORTH** GitHub Actions workflow runs the backend suite and frontend build. A separate job starts Docker Compose, checks the console and evidence through its HTTP and WebSocket gateway, then restarts with seeding disabled to check PostgreSQL persistence. To run the smoke check against your local Windows demo, use `.\.venv\Scripts\python.exe smoke_demo.py http://127.0.0.1:5173` from `backend` while both servers are running.

1. Ingestion normalizes times to UTC and inserts them transactionally. The database rejects duplicate evidence IDs.
2. IRIS links process creation and a script write by agent and process GUID within a two-minute window. This is a triage signal. Legitimate administration can produce it.
3. A WebSocket sends authoritative case snapshots, including after reconnect. This keeps the small demo simple. For sustained telemetry volumes, the next design step would be incrementally materialized cases and bounded event queries.
4. ATLAS displays observed destination relationships. ECHO sorts by UTC time and stable ID for deterministic playback. The export uses the same observations and evidence IDs.

An interview walkthrough can show all four steps with one case, then explain the trade-offs behind the detection rule, idempotent storage, WebSocket snapshots, and optional AI.

See the [12-week roadmap](ROADMAP.md) for milestones, acceptance checks, and interview questions.
