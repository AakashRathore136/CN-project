# TinyGuard — Real Local Network Monitor

This version reads real telemetry from the computer running it. It does not generate demo measurements and does not upload telemetry to a cloud service.

## What it measures
- CPU utilization and memory utilization from the local operating system.
- Total network-interface byte counters and approximate send/receive rates between samples.
- Round-trip latency to a target using the OS `ping` utility.
- Whether each ping probe received a reply.
- Local history, evidence-based rule alerts, and CSV export.

## Important limitation
This is a **real telemetry monitor with rule-based anomaly checks**, not yet a trained ML model that can reliably forecast future faults. A single failed ping is only one failed probe and can be caused by ICMP filtering. The displayed risk score is a transparent rule indicator, **not a calibrated probability of failure**. Use a target you are authorized to probe. Public targets may rate-limit or block ping.

## Requirements
- Python 3.10+
- Windows 10/11, macOS, or Linux
- `ping` utility available on PATH (normally included with Windows/macOS/Linux)

## Run on Windows
Open PowerShell in this folder:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m uvicorn app:app --host 127.0.0.1 --port 8000
```

If PowerShell blocks activation, use:
```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000 in Chrome or Edge. To stop, press Ctrl+C in the terminal.

## Use
1. Enter a target such as your router's gateway IP or `1.1.1.1`.
2. Click **Take one sample** to measure once.
3. Click **Start monitoring** to collect a sample every three seconds.
4. Review the measured latency, reachability, CPU, memory, traffic rates, and the assessment evidence.
5. Click **Export CSV** to save samples collected during this run.
6. Click **Pause** to stop periodic polling. Clear history removes the in-memory sample/event history.

## API
- `GET /api/health` — local monitor health.
- `GET /api/sample?target=1.1.1.1` — collect one real sample.
- `GET /api/history` — current in-memory history.
- `GET /api/export.csv` — export samples as CSV.
- `POST /api/clear` — clear in-memory history.

## Privacy and safety
The app binds to `127.0.0.1`, so it is only reachable from your own computer by default. It reads OS-level counters and sends one ping per sample to the selected target. It does not sniff packets or collect payloads, passwords, browser history, or other users' traffic. The target receives normal ICMP probe packets. Do not use a target you do not have permission to test.

## How the assessment works
- Failed ping: connectivity issue indicator.
- Any failed probe: recorded as a failed sample (the UI explicitly avoids treating one failure as proof of sustained loss).
- Latency at or above 150 ms: high-latency indicator.
- Latency well above the median of recent successful probes: baseline anomaly indicator, after enough baseline samples exist.
- CPU at or above 90% or memory at or above 92%: local resource pressure indicator.

Thresholds are starting points and should be tuned for your network and use case. They are not universal fault definitions.

## Team
- Adidev Kuniyil — 24BCE2369
- Naveen Renjith — 24BCE2460
- Aakash Rathore — 24BCE2512

B.Tech Computer Science and Engineering, SCOPE · 2024–2028
