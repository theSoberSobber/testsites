#!/usr/bin/env python3
"""Turn /var/log/testsites/access.jsonl into Prometheus metrics.

Single-threaded parser, incremental byte offset, survives rotation. No deps.
Scraped every 15s by Prometheus, so the parse cost is ~1s of one core at most.
"""
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_DIR = os.environ.get("LOG_DIR", "/var/log/testsites")
LOG = os.path.join(LOG_DIR, "access.jsonl")
PORT = int(os.environ.get("PORT", "9101"))
IP_WINDOW = 300.0  # seconds a client IP stays counted as "active"
BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120)

lock = threading.Lock()
offset = 0
counters = {}          # (name, ((label, value), ...)) -> float
ip_seen = {}           # ip -> last seen epoch
last_request = 0.0
hist = {b: 0 for b in BUCKETS}
hist_inf = 0
hist_sum = 0.0
hist_count = 0
parse_errors = 0
started = time.time()


def site_of(d):
    site = d.get("site")
    if site:
        return site
    host = (d.get("host") or "").split(".")[0]
    if host.startswith("testsites-"):
        return host[len("testsites-"):]
    return "index" if host == "testsites" else (host or "unknown")


def add(name, labels, value=1):
    key = (name, tuple(sorted(labels.items())) if isinstance(labels, dict) else tuple(labels))
    counters[key] = counters.get(key, 0) + value


def ingest(d, now):
    global last_request, hist_inf, hist_sum, hist_count
    site = site_of(d)
    ev = d.get("event")
    if ev == "request":
        add("testsites_requests_total", {"site": site, "method": d.get("method") or ""})
        ip = d.get("client_ip")
        if ip:
            ip_seen[ip] = now
        last_request = max(last_request, now)
        return
    if ev != "response":
        return
    add("testsites_responses_total", {"site": site, "status": str(d.get("status"))})
    add("testsites_response_bytes_total", {"site": site}, float(d.get("resp_bytes") or 0))
    dur = float(d.get("duration_ms") or 0) / 1000.0
    hist_sum += dur
    hist_count += 1
    for b in BUCKETS:
        if dur <= b:
            hist[b] += 1
    if dur > BUCKETS[-1]:
        hist_inf += 1
    detail = d.get("detail") or {}
    upload = sum(float(v) for k, v in detail.items()
                 if isinstance(v, (int, float)) and "bytes" in k and v)
    if upload:
        add("testsites_upload_bytes_total", {"site": site}, upload)
    if site == "ws" and d.get("status") == 101:
        add("testsites_ws_connections_total", {})


def poll():
    """Read whatever the writer appended since last time."""
    global offset, parse_errors
    try:
        size = os.stat(LOG).st_size
    except OSError:
        return  # missing or not readable yet; serve zeros rather than 500
    if size < offset:          # rotated or truncated: start over
        offset = 0
    if size == offset:
        return
    try:
        with open(LOG, "rb") as f:
            f.seek(offset)
            blob = f.read(size - offset)
    except OSError:
        return
    if not blob:
        return
    end = blob.rfind(b"\n")
    if end < 0:                # partial line, wait for the newline
        return
    chunk = blob[: end + 1]
    now = time.time()
    with lock:
        for line in chunk.splitlines():
            if not line.strip():
                continue
            try:
                ingest(json.loads(line), now)
            except Exception:
                parse_errors += 1
        offset += len(chunk)


def esc(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def render():
    global ip_seen
    poll()
    now = time.time()
    with lock:
        ip_seen = {ip: t for ip, t in ip_seen.items() if now - t <= IP_WINDOW}
        lines = []
        emitted_types = set()

        def series(name, labels, value, kind="counter", helptext=None):
            if name not in emitted_types:
                lines.append(f"# HELP {name} {helptext or name}")
                lines.append(f"# TYPE {name} {kind}")
                emitted_types.add(name)
            lab = ",".join(f'{k}="{esc(v)}"' for k, v in labels.items())
            lines.append(f"{name}{{{lab}}} {value}" if lab else f"{name} {value}")

        for (name, lab), value in sorted(counters.items()):
            kind = "counter" if name.endswith("_total") else "gauge"
            series(name, dict(lab), value, kind)

        # latency histogram
        lines.append("# HELP testsites_request_duration_seconds Response time")
        lines.append("# TYPE testsites_request_duration_seconds histogram")
        for b in BUCKETS:
            lines.append(f'testsites_request_duration_seconds_bucket{{le="{b}"}} {hist[b]}')
        lines.append(f'testsites_request_duration_seconds_bucket{{le="+Inf"}} {hist[b] + hist_inf}')
        lines.append(f"testsites_request_duration_seconds_sum {hist_sum:.6f}")
        lines.append(f"testsites_request_duration_seconds_count {hist_count}")

        series("testsites_unique_ips_5m", {}, len(ip_seen), "gauge",
               "Distinct client IPs seen in the last 5 minutes")
        series("testsites_last_request_timestamp_seconds", {}, f"{last_request:.3f}", "gauge",
               "Unix time of the most recent request")
        try:
            series("testsites_log_bytes", {}, os.stat(LOG).st_size, "gauge")
        except OSError:
            pass
        try:
            vfs = os.statvfs(LOG_DIR)
            free = vfs.f_bavail * vfs.f_frsize
            total = vfs.f_blocks * vfs.f_frsize
            series("testsites_disk_free_bytes", {}, free, "gauge")
            series("testsites_disk_free_pct", {}, f"{100.0 * free / total:.2f}", "gauge")
        except OSError:
            pass
        series("testsites_exporter_parse_errors_total", {}, parse_errors, "counter")
        series("testsites_exporter_uptime_seconds", {}, f"{now - started:.0f}", "gauge")
    return "\n".join(lines) + "\n"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/metrics"):
            body = render().encode()
            ctype = "text/plain; version=0.0.4; charset=utf-8"
        elif self.path.startswith("/healthz"):
            body, ctype = b"ok\n", "text/plain"
        else:
            body, ctype = b"metrics at /metrics\n", "text/plain"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print(f"exporting {LOG} on :{PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
