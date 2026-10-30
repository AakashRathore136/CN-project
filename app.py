from __future__ import annotations
import asyncio, platform, socket, subprocess, time, statistics, shutil
from collections import deque
from datetime import datetime, timezone
from typing import Optional
import psutil
from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path

APP_DIR = Path(__file__).parent
app = FastAPI(title="TinyGuard Real Network Monitor", version="1.0")
app.mount("/static", StaticFiles(directory=APP_DIR / "static"), name="static")

history = deque(maxlen=180)
events = deque(maxlen=100)
baseline = deque(maxlen=60)
last_net = None
last_net_time = None
last_ping = None

def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")

def ping_target(host: str, timeout_s: float = 1.2):
    """Return measured ICMP latency when OS ping is available; otherwise return an explicit error."""
    if not host or any(c in host for c in " ;|&`$<>"):
        return {"ok": False, "latency_ms": None, "error": "Invalid target"}
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout_s * 1000)), host]
    else:
        # -W is seconds on common Linux/macOS variants; timeout wraps macOS/Linux command.
        cmd = ["ping", "-c", "1", host]
        if shutil.which("timeout"):
            cmd = ["timeout", str(timeout_s + 0.4)] + cmd
    if not shutil.which("ping"):
        return {"ok": False, "latency_ms": None, "error": "The ping utility is not installed"}
    try:
        start = time.perf_counter()
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s + 1.0)
        elapsed = (time.perf_counter() - start) * 1000
        out = (p.stdout + "\n" + p.stderr).lower()
        if p.returncode != 0 or ("timed out" in out) or ("100% packet loss" in out) or ("100.0% packet loss" in out):
            return {"ok": False, "latency_ms": None, "error": "No ping reply"}
        # Prefer parsed OS-reported RTT, with measured elapsed time as fallback.
        import re
        patterns = [
            r"time[=<]\s*([\d.]+)\s*ms",
            r"time\s*=\s*([\d.]+)\s*ms",
            r"temps[=<]\s*([\d.]+)\s*ms",
        ]
        for pat in patterns:
            m = re.search(pat, out)
            if m:
                return {"ok": True, "latency_ms": float(m.group(1)), "error": None}
        return {"ok": True, "latency_ms": round(elapsed, 2), "error": None}
    except subprocess.TimeoutExpired:
        return {"ok": False, "latency_ms": None, "error": "Ping timed out"}
    except Exception as e:
        return {"ok": False, "latency_ms": None, "error": str(e)}

def local_metrics():
    global last_net, last_net_time
    cpu = psutil.cpu_percent(interval=0.15)
    vm = psutil.virtual_memory()
    counters = psutil.net_io_counters()
    current_time = time.time()
    tx_rate = rx_rate = None
    if last_net is not None and last_net_time is not None:
        dt = max(current_time - last_net_time, 0.001)
        tx_rate = max(0, counters.bytes_sent - last_net.bytes_sent) / dt
        rx_rate = max(0, counters.bytes_recv - last_net.bytes_recv) / dt
    last_net, last_net_time = counters, current_time
    return {
        "cpu_percent": round(cpu, 1),
        "memory_percent": round(vm.percent, 1),
        "bytes_sent_total": counters.bytes_sent,
        "bytes_recv_total": counters.bytes_recv,
        "tx_bytes_per_sec": round(tx_rate, 1) if tx_rate is not None else None,
        "rx_bytes_per_sec": round(rx_rate, 1) if rx_rate is not None else None,
        "interfaces": list(psutil.net_if_addrs().keys()),
        "platform": platform.platform(),
        "hostname": socket.gethostname()
    }

def assess(m):
    """Transparent rules/baseline anomaly checks, not a trained ML failure predictor."""
    reasons = []
    latency = m.get("latency_ms")
    loss = m.get("packet_loss_percent")
    if not m.get("target_reachable"):
        reasons.append("Target did not reply to ping")
    if loss is not None and loss > 0:
        reasons.append(f"Packet loss observed: {loss:.0f}%")
    if latency is not None and latency >= 150:
        reasons.append(f"High latency: {latency:.1f} ms (threshold 150 ms)")
    elif latency is not None and len(baseline) >= 8:
        med = statistics.median(baseline)
        if med > 0 and latency > max(med * 2.5, med + 40):
            reasons.append(f"Latency is elevated versus recent baseline ({med:.1f} ms median)")
    if m["cpu_percent"] >= 90:
        reasons.append(f"High CPU utilization: {m['cpu_percent']:.1f}%")
    if m["memory_percent"] >= 92:
        reasons.append(f"High memory utilization: {m['memory_percent']:.1f}%")
    if not m.get("target_reachable"):
        risk, status = 90, "CONNECTIVITY ISSUE"
    elif loss and loss > 0:
        risk, status = min(95, 60 + int(loss)), "PACKET LOSS"
    elif latency is not None and latency >= 150:
        risk, status = min(90, 50 + int((latency-150)/5)), "HIGH LATENCY"
    elif m["cpu_percent"] >= 90 or m["memory_percent"] >= 92:
        risk, status = 55, "LOCAL RESOURCE PRESSURE"
    elif reasons:
        risk, status = 40, "ANOMALY"
    else:
        risk, status = 5, "NO ISSUE DETECTED"
    m["risk_score"] = risk
    m["status"] = status
    m["reasons"] = reasons or ["No configured threshold or baseline anomaly detected in this sample"]
    m["method"] = "Transparent threshold + recent-baseline checks; not trained ML"
    return m

@app.get("/", response_class=HTMLResponse)
def index():
    return (APP_DIR / "static" / "index.html").read_text(encoding="utf-8")

@app.get("/api/health")
def health():
    return {"ok": True, "timestamp": now_iso(), "hostname": socket.gethostname(),
            "platform": platform.platform(), "history_samples": len(history)}

@app.get("/api/sample")
def sample(target: str = Query(default="1.1.1.1", max_length=253)):
    m = local_metrics()
    p = ping_target(target)
    m.update({
        "timestamp": now_iso(),
        "target": target,
        "target_reachable": p["ok"],
        "latency_ms": p["latency_ms"],
        "ping_error": p["error"],
        # One ICMP probe per sample: a failed probe is recorded as a failed sample,
        # not treated as a statistically reliable long-window packet-loss estimate.
        "packet_loss_percent": 0 if p["ok"] else 100
    })
    result = assess(m)
    if p["ok"] and p["latency_ms"] is not None:
        baseline.append(p["latency_ms"])
    history.append(result.copy())
    if result["status"] != "NO ISSUE DETECTED":
        if not events or events[-1]["status"] != result["status"] or events[-1]["target"] != target:
            events.appendleft({
                "timestamp": result["timestamp"], "status": result["status"],
                "risk_score": result["risk_score"], "target": target,
                "reasons": result["reasons"]
            })
    return result

@app.get("/api/history")
def get_history():
    return {"samples": list(history), "events": list(events)}

@app.get("/api/export.csv")
def export_csv():
    import csv, io
    from fastapi.responses import StreamingResponse
    buf = io.StringIO()
    fields = ["timestamp","target","target_reachable","latency_ms","packet_loss_percent",
              "cpu_percent","memory_percent","tx_bytes_per_sec","rx_bytes_per_sec","risk_score","status","reasons"]
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in history:
        row = row.copy()
        row["reasons"] = "; ".join(row.get("reasons", []))
        writer.writerow(row)
    from fastapi.responses import Response
    return Response(content=buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=tinyguard_real_telemetry.csv"})

@app.post("/api/clear")
def clear_history():
    history.clear()
    events.clear()
    baseline.clear()
    return {"ok": True, "message": "Local in-memory history cleared"}
