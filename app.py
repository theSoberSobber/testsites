#!/usr/bin/env python3
"""
testsites: Cloudflare tunnel test suite.
Single asyncio HTTP/1.1 server, routed by Host header. No third-party deps.
Every request is appended to logs/access.jsonl as one JSON object.
"""
import asyncio
import base64
import datetime
import gzip
import hashlib
import html
import json
import mimetypes
import os
import re
import struct
import time
from urllib.parse import parse_qs, urlsplit

BASE_DOMAIN = "1110777.xyz"
SITE = "testsites." + BASE_DOMAIN
PORT = int(os.environ.get("PORT", "8080"))
LOG_DIR = os.environ.get("LOG_DIR", "/home/pavit/testsites/logs")
LOG_PATH = os.path.join(LOG_DIR, "access.jsonl")
MAX_HEADER = 2048
CHUNK = 1024 * 1024
MAX_CONN = 200
MAX_WS_FRAME = 4 * 1024 * 1024
ACTIVE = 0
STARTED_AT = time.monotonic()

REASONS = {
    200: "OK", 201: "Created", 204: "No Content", 301: "Moved Permanently",
    302: "Found", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
    404: "Not Found", 405: "Method Not Allowed", 413: "Payload Too Large",
    418: "I'm a teapot", 429: "Too Many Requests", 500: "Internal Server Error",
    501: "Not Implemented", 503: "Service Unavailable",
}


# ----------------------------------------------------------------- logging ---
def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")


def log(**rec):
    rec.setdefault("ts", now_iso())
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        line = json.dumps(rec, default=str, ensure_ascii=False)[:16000] + "\n"
        fd = os.open(LOG_PATH, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        try:
            os.write(fd, line.encode("utf-8", "replace"))
        finally:
            os.close(fd)
    except Exception:
        pass


# -------------------------------------------------------------------- http ---
def read_headers_block(raw):
    headers = {}
    for line in raw.split(b"\r\n"):
        if not line:
            continue
        if b":" not in line:
            continue
        k, v = line.split(b":", 1)
        key = k.decode("latin-1").strip().lower()
        val = v.decode("latin-1").strip()
        if len(val) > MAX_HEADER:
            val = val[:MAX_HEADER] + "...[truncated]"
        headers[key] = (headers[key] + ", " + val) if key in headers else val
    return headers


async def read_request(reader):
    line = await asyncio.wait_for(reader.readline(), 30)
    if not line:
        return None
    try:
        method, target, version = line.decode("latin-1").strip().split(" ", 2)
    except ValueError:
        return None
    raw = b""
    total = 0
    while True:
        h = await asyncio.wait_for(reader.readline(), 30)
        if not h or h in (b"\r\n", b"\n"):
            break
        total += len(h)
        if total > 65536:
            break
        raw += h
    return method, target, version, read_headers_block(raw)


async def body_iter(reader, headers):
    te = headers.get("transfer-encoding", "").lower()
    if "chunked" in te:
        while True:
            size_line = await asyncio.wait_for(reader.readline(), 60)
            if not size_line:
                return
            token = size_line.split(b";")[0].strip()
            try:
                size = int(token, 16)
            except ValueError:
                return
            if size == 0:
                while True:
                    trailer = await asyncio.wait_for(reader.readline(), 30)
                    if trailer in (b"\r\n", b"\n", b""):
                        break
                return
            left = size
            while left > 0:
                data = await asyncio.wait_for(reader.read(min(65536, left)), 120)
                if not data:
                    return
                left -= len(data)
                yield data
            await asyncio.wait_for(reader.readline(), 30)
    else:
        declared = headers.get("content-length")
        if declared is None:
            return
        left = int(declared)
        while left > 0:
            data = await asyncio.wait_for(reader.read(min(65536, left)), 120)
            if not data:
                return
            left -= len(data)
            yield data


async def respond(writer, status, headers=None, body=b"", head_only=False):
    headers = dict(headers or {})
    headers.setdefault("Date", datetime.datetime.now(datetime.timezone.utc).strftime(
        "%a, %d %b %Y %H:%M:%S GMT"))
    headers.setdefault("Connection", "close")
    headers.setdefault("X-Robots-Tag", "noindex, nofollow")
    headers.setdefault("X-Content-Type-Options", "nosniff")
    if body and "Content-Type" not in headers:
        headers["Content-Type"] = "text/html; charset=utf-8"
    if body and "Content-Length" not in headers:
        headers["Content-Length"] = str(len(body))
    writer.responded = True
    out = [f"HTTP/1.1 {status} {REASONS.get(status, 'OK')}"]
    out += [f"{k}: {v}" for k, v in headers.items()]
    writer.write(("\r\n".join(out) + "\r\n\r\n").encode("latin-1"))
    if body and not head_only:
        writer.write(body)
    try:
        await writer.drain()
    except (ConnectionResetError, BrokenPipeError):
        pass


def json_respond(writer, status, obj, head_only=False):
    body = json.dumps(obj, indent=2, default=str).encode()
    return respond(writer, status, {"Content-Type": "application/json; charset=utf-8"}, body, head_only)


def html_page(title, body, extra_head=""):
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
:root{{color-scheme:dark}}
body{{font:15px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:28px;max-width:960px}}
h1{{color:#58a6ff;font-size:22px;margin:0 0 4px}} h2{{font-size:16px;color:#8b949e;margin:26px 0 8px}}
a{{color:#58a6ff;text-decoration:none}} a:hover{{text-decoration:underline}}
table{{width:100%;border-collapse:collapse;margin:10px 0}} td,th{{text-align:left;padding:7px 10px;border-bottom:1px solid #21262d;vertical-align:top}}
th{{color:#8b949e;font-weight:600;font-size:13px;text-transform:uppercase;letter-spacing:.04em}}
code,pre{{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:2px 6px;font-size:13px}}
pre{{padding:12px;overflow:auto}} .mono{{font-size:13px}}
input[type=file]{{color:#c9d1d9}} button{{background:#238636;border:0;color:#fff;padding:9px 16px;border-radius:6px;font:inherit;cursor:pointer}}
.muted{{color:#8b949e;font-size:13px}} .ok{{color:#3fb950}} .warn{{color:#d29922}} .err{{color:#f85149}}
</style>{extra_head}</head><body>{body}</body></html>"""


# -------------------------------------------------------------------- sites ---
INDEX_ITEMS = [
    ("upload", "Streaming upload", "POST any body size; memory only, incremental hash, per-chunk digests"),
    ("gui", "GUI upload", "Browser form upload (multipart), streamed, never written to disk"),
    ("download", "Download / sink", "Content-Length of any size, or truly infinite chunked stream"),
    ("ws", "WebSocket echo", "ws:// and wss://, text + binary echo, ping/pong"),
    ("echo", "Echo", "Everything we see: method, path, query, headers, cookies, body preview"),
    ("ip", "Check IP", "Your IPv4/IPv6 as seen by the edge, plus socket peer"),
    ("tools", "Proxy tools", "delay, status codes, gzip, redirects, cookies, SSE, method echo"),
]


def site_url(name):
    return f"https://testsites-{name}.{BASE_DOMAIN}/"


def index_html():
    rows = "".join(
        f'<tr><td><a href="{site_url(name)}">testsites-{name}</a></td>'
        f'<td><b>{title}</b><br><span class="muted">{desc}</span></td></tr>'
        for name, title, desc in INDEX_ITEMS
    )
    return html_page("testsites — table of contents", f"""
<h1>testsites</h1>
<p class="muted">Cloudflare tunnel upload / proxy test suite under <code>{SITE}</code></p>
<table><tr><th>Site</th><th>What it does</th></tr>{rows}</table>
<h2>Quick curl</h2>
<pre># upload 5 GiB with zero disk use
head -c 5G /dev/zero | curl -s --data-binary @- {site_url('upload')}

# infinite download
curl -s "{site_url('download')}?infinite=1" | pv &gt; /dev/null

# exactly 100 MiB
curl -s -o /dev/null -w '%{{size_download}}\\n' "{site_url('download')}?bytes=104857600"</pre>
<p class="muted">Every request is logged to <code>{LOG_PATH}</code> as JSONL.</p>""")


def upload_json(**kw):
    return html_page("upload result", "<h1>upload</h1><p class='ok'>Received.</p><pre>"
                     + json.dumps(kw, indent=2, default=str) + "</pre>")


GUI_PAGE = """
<h1>GUI upload</h1>
<p class="muted">Streamed to memory, hashed, discarded. Nothing touches disk.</p>
<form id="up" method="post" enctype="multipart/form-data" action="/">
  <p><textarea name="text" rows="4" cols="60" placeholder="optional text payload"></textarea></p>
  <p><input id="files" type="file" name="file" multiple></p>
  <p><label><input id="raw" type="checkbox"> send text as raw body (no multipart)</label>
     <span class="muted" id="rawnote">files are ignored in raw mode</span></p>
  <p><button type="submit">Upload</button></p>
</form>
<p id="msg" class="warn"></p>
<p class="muted">Cloudflare Free caps a single request body at 100 MB; bigger uploads fail at
 the edge with 413/502 before reaching this server. Multiple files are multipart-only.</p>
<h2>curl</h2>
<pre>curl -s -F "file=@big.iso" __GUI__
printf 'raw text' | curl -s --data-binary @- -H 'Content-Type: text/plain' __GUI__</pre>
<script>
const f=document.getElementById('up'), files=document.getElementById('files'),
      raw=document.getElementById('raw'), msg=document.getElementById('msg'),
      note=document.getElementById('rawnote'), ta=document.querySelector('textarea[name=text]');
function sync(){ if(files.files.length>1){ raw.checked=false; } raw.disabled = files.files.length>1;
  note.textContent = files.files.length>1 ? 'raw mode unavailable with multiple files' : 'files are ignored in raw mode'; }
files.addEventListener('change', sync);
f.addEventListener('submit', async (e)=>{
  const total=[...files.files].reduce((a,b)=>a+b.size,0);
  if(!raw.checked && total===0 && !ta.value.trim()){ e.preventDefault(); msg.textContent='pick a file or type something first'; return; }
  if(!raw.checked && total > 95*1024*1024){ e.preventDefault();
    msg.textContent='Total '+(total/1048576).toFixed(1)+' MiB exceeds Cloudflare Free\'s 100 MB request limit, so the edge will fail it. Use files under 95 MiB.'; return; }
  if(raw.checked){ e.preventDefault(); msg.textContent='uploading raw…';
    const r=await fetch('/',{method:'POST',headers:{'Content-Type':'text/plain'},body:ta.value});
    document.open(); document.write(await r.text()); document.close(); }
});
</script>"""


def gui_html(host):
    return html_page("GUI upload", GUI_PAGE.replace("__GUI__", site_url("gui")))


def fmt_bytes(n):
    step = 1024.0
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < step or unit == "TiB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= step


async def stream_upload(reader, writer, headers, method, host, qs, head_only, path):
    chunk_size = int(qs.get("chunk", ["1048576"])[0])
    chunk_size = max(1024, min(chunk_size, 2 * 1024 * 1024))
    algos = {"sha256": hashlib.sha256()}
    extra = (qs.get("hash", [""])[0] or "").lower()
    if extra in ("md5", "sha1", "sha512", "sha256"):
        algos[extra] = getattr(hashlib, extra)()
    total = 0
    chunk_count = 0
    digests = []
    buf = bytearray()
    sample = bytearray()
    started = time.monotonic()
    last = started
    async for data in body_iter(reader, headers):
        total += len(data)
        for h in algos.values():
            h.update(data)
        if len(sample) < 256:
            sample += data[: 256 - len(sample)]
        buf += data
        while len(buf) >= chunk_size:
            piece = bytes(buf[:chunk_size])
            del buf[:chunk_size]
            chunk_count += 1
            if len(digests) < 64:
                digests.append(hashlib.sha256(piece).hexdigest())
        if time.monotonic() - last > 5:
            last = time.monotonic()
            log(event="upload_progress", host=host, path=path, bytes=total,
                chunks=chunk_count, client=client_ip(headers))
    if buf:
        chunk_count += 1
        if len(digests) < 64:
            digests.append(hashlib.sha256(bytes(buf)).hexdigest())
    elapsed = (time.monotonic() - started) * 1000.0
    result = {
        "ok": True,
        "bytes_received": total,
        "human": fmt_bytes(total),
        "sha256": algos["sha256"].hexdigest(),
        "hashes": {name: h.hexdigest() for name, h in algos.items()},
        "chunk_size": chunk_size,
        "chunk_count": chunk_count,
        "chunk_sha256_first64": digests,
        "elapsed_ms": round(elapsed, 1),
        "throughput_mbps": round((total * 8 / 1e6) / (elapsed / 1000), 2) if elapsed else None,
        "transfer_encoding": headers.get("transfer-encoding"),
        "declared_content_length": headers.get("content-length"),
        "method": method,
        "host": host,
        "client_ip": client_ip(headers),
        "collected_at": now_iso(),
    }
    if head_only:
        await respond(writer, 200, {"Content-Type": "application/json"}, b"", True)
    elif qs.get("format", ["json"])[0] == "html":
        await respond(writer, 200, body=upload_json(**result).encode())
    else:
        await json_respond(writer, 200, result)
    return {"bytes_received": total, "sha256": result["sha256"],
            "chunk_count": chunk_count, "sample_b64": base64.b64encode(bytes(sample)).decode()}


async def stream_download(writer, qs, head_only):
    pattern = (qs.get("pattern", ["seq"])[0] or "seq").lower()
    chunk_size = int(qs.get("chunk", ["65536"])[0])
    chunk_size = max(1024, min(chunk_size, 4 * 1024 * 1024))
    if pattern == "zero":
        block = b"\x00" * chunk_size
    elif pattern == "random":
        block = os.urandom(chunk_size)
    else:
        base = bytes(range(256))
        block = (base * (chunk_size // 256 + 1))[:chunk_size]
    rate = float(qs.get("rate", ["0"])[0] or 0)
    infinite = qs.get("infinite", ["0"])[0] in ("1", "true", "yes")
    total_target = int(qs["bytes"][0]) if "bytes" in qs else 0
    if not infinite and "bytes" not in qs:
        body = html_page("download", f"""
<h1>Download / sink</h1>
<p class="muted">Streams bytes generated on the fly. Nothing is read from disk.</p>
<table>
<tr><th>Query</th><th>Behaviour</th></tr>
<tr><td><a href="?bytes=1048576">?bytes=N</a></td><td>exactly N bytes with Content-Length</td></tr>
<tr><td><a href="?infinite=1">?infinite=1</a></td><td>endless chunked stream</td></tr>
<tr><td><code>?chunk=N</code></td><td>write size per chunk (default 65536)</td></tr>
<tr><td><code>?pattern=seq|zero|random</code></td><td>payload pattern</td></tr>
<tr><td><code>?rate=N</code></td><td>throttle to N bytes/second</td></tr>
<tr><td><a href="?bytes=1048576&amp;filename=demo.pdf">?filename=demo.pdf</a></td><td>Content-Type + Content-Disposition from the filename (pdf, zip, mp4, …)</td></tr>
</table>
<pre>curl -s -o /dev/null -w '%{{size_download}}\\n' "{site_url('download')}?bytes=104857600"
curl -s "{site_url('download')}?infinite=1" | pv &gt; /dev/null</pre>""")
        await respond(writer, 200, body=body.encode(), head_only=head_only)
        return {"stream": "landing"}
    sent = 0
    filename = safe_filename(qs.get("filename", [""])[0])
    ctype = (mimetypes.guess_type(filename)[0] if filename else None) or "application/octet-stream"
    headers = {"Content-Type": ctype,
               "Cache-Control": "no-store",
               "X-Accel-Buffering": "no"}
    if filename:
        headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    if infinite:
        headers["Transfer-Encoding"] = "chunked"
        writer.responded = True
        head = b"HTTP/1.1 200 OK\r\n" + b"".join(
            f"{k}: {v}\r\n".encode() for k, v in headers.items()) + b"\r\n"
        writer.write(head)
        try:
            while True:
                writer.write(b"%x\r\n" % len(block) + block + b"\r\n")
                await writer.drain()
                sent += len(block)
                if rate:
                    await asyncio.sleep(len(block) / rate)
        except (ConnectionResetError, BrokenPipeError):
            pass
        return {"stream": "infinite", "bytes_sent": sent, "pattern": pattern}
    headers["Content-Length"] = str(total_target)
    await respond(writer, 200, headers, b"", True)
    if head_only:
        return {"stream": "finite", "declared": total_target, "bytes_sent": 0}
    try:
        while sent < total_target:
            piece = block[: min(len(block), total_target - sent)]
            writer.write(piece)
            await writer.drain()
            sent += len(piece)
            if rate:
                await asyncio.sleep(len(piece) / rate)
    except (ConnectionResetError, BrokenPipeError):
        pass
    return {"stream": "finite", "declared": total_target, "bytes_sent": sent, "pattern": pattern}


def safe_filename(raw):
    """Never let request data reach a response header verbatim (CRLF injection)."""
    name = re.sub(r'[\r\n"\\\x00-\x1f]', "", raw or "").strip()
    name = name.replace("/", "_").replace("\\", "_")
    return name[:128]


def parse_cookies(raw):
    out = {}
    for part in (raw or "").split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()[:64]] = v.strip()[:512]
    return out


def vitals():
    """Self-reported health, cheap enough for a 15-minute cron."""
    import resource
    import shutil
    try:
        rss_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    except Exception:
        rss_kb = None
    try:
        du = shutil.disk_usage(LOG_DIR)
        disk = {"total_mb": round(du.total / 1048576),
                "free_mb": round(du.free / 1048576),
                "free_pct": round(du.free * 100.0 / du.total, 1)}
    except Exception:
        disk = None
    try:
        log_bytes = os.path.getsize(LOG_PATH)
    except Exception:
        log_bytes = 0
    try:
        archives = sum(1 for f in os.listdir(os.path.join(LOG_DIR, "archives"))
                       if f.endswith(".gz"))
    except Exception:
        archives = 0
    return {
        "ok": True,
        "ts": now_iso(),
        "pid": os.getpid(),
        "uptime_s": round(time.monotonic() - STARTED_AT),
        "active_conns": ACTIVE,
        "max_conns": MAX_CONN,
        "rss_kb": rss_kb,
        "log_bytes": log_bytes,
        "archives": archives,
        "disk": disk,
    }


def client_ip(headers):
    return (headers.get("cf-connecting-ip") or headers.get("true-client-ip")
            or (headers.get("x-forwarded-for", "").split(",")[0].strip() or None)
            or headers.get("x-real-ip") or None)


def ip_report(headers, peer):
    cf = headers.get("cf-connecting-ip")
    fam = None
    if cf:
        fam = "IPv6" if ":" in cf else "IPv4"
    peer_fam = "IPv6" if peer and ":" in peer[0] else "IPv4" if peer else None
    return {
        "cf_connecting_ip": cf,
        "family": fam,
        "true_client_ip": headers.get("true-client-ip"),
        "x_forwarded_for": headers.get("x-forwarded-for"),
        "x_real_ip": headers.get("x-real-ip"),
        "socket_peer": f"{peer[0]}:{peer[1]}" if peer else None,
        "socket_family": peer_fam,
        "cf_ray": headers.get("cf-ray"),
        "cf_ipcountry": headers.get("cf-ipcountry"),
        "cf_visitor": parse_cf_visitor(headers.get("cf-visitor")),
        "x_forwarded_proto": headers.get("x-forwarded-proto"),
        "server_local": LOCAL_IPS,
    }


def parse_cf_visitor(raw):
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return raw


LOCAL_IPS = {}


def load_local_ips():
    try:
        import socket as _s
        out = {}
        for fam, _, _, _, sa in _s.getaddrinfo(_s.gethostname(), None):
            out.setdefault("IPv6" if fam == _s.AF_INET6 else "IPv4", []).append(sa[0])
        LOCAL_IPS.update(out)
    except Exception:
        pass


WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


async def ws_session(reader, writer, headers, host, path):
    key = headers.get("sec-websocket-key")
    if not key or headers.get("upgrade", "").lower() != "websocket":
        await respond(writer, 400, body=b"expected websocket upgrade\n")
        return {"ws": "bad_handshake"}
    accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
    writer.responded = True
    writer.write(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                  "Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n").encode())
    await writer.drain()
    log(event="ws_open", host=host, path=path, client=client_ip(headers),
        user_agent=headers.get("user-agent"), cf_ray=headers.get("cf-ray"))
    frames = 0
    rx = tx = 0
    started = time.monotonic()
    try:
        while True:
            opcode, data = await read_ws_frame(reader)
            if opcode == 8:
                writer.write(ws_frame(8, data))
                await writer.drain()
                break
            if opcode == 9:
                writer.write(ws_frame(10, data))
                await writer.drain()
                continue
            if opcode in (1, 2):
                frames += 1
                rx += len(data)
                tx += len(data)
                writer.write(ws_frame(opcode, data))
                await writer.drain()
    except ValueError:
        try:
            writer.write(ws_frame(8, struct.pack("!H", 1009)))
            await writer.drain()
        except Exception:
            pass
        log(event="ws_reject", host=host, reason="frame_too_large")
    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as exc:
        log(event="ws_error", host=host, error=repr(exc))
    return {"ws": "closed", "frames": frames, "bytes_rx": rx, "bytes_tx": tx,
            "seconds": round(time.monotonic() - started, 2)}


async def read_ws_frame(reader):
    b1, b2 = await reader.readexactly(2)
    opcode = b1 & 0x0F
    masked = b2 & 0x80
    length = b2 & 0x7F
    if length == 126:
        length = struct.unpack("!H", await reader.readexactly(2))[0]
    elif length == 127:
        length = struct.unpack("!Q", await reader.readexactly(8))[0]
    if length > MAX_WS_FRAME:
        raise ValueError(f"frame too large: {length}")
    mask = await reader.readexactly(4) if masked else None
    payload = await reader.readexactly(length) if length else b""
    if mask:
        payload = bytes(c ^ mask[i % 4] for i, c in enumerate(payload))
    return opcode, payload


def ws_frame(opcode, payload=b""):
    head = bytes([0x80 | opcode])
    n = len(payload)
    if n < 126:
        return head + bytes([n]) + payload
    if n < 65536:
        return head + bytes([126]) + struct.pack("!H", n) + payload
    return head + bytes([127]) + struct.pack("!Q", n) + payload


# ----------------------------------------------------------------- routing ---
def route(host):
    host = (host or "").split(":")[0].lower().rstrip(".")
    if host in (SITE, "www." + SITE, ""):
        return "index"
    for prefix in (".testsites.", "."):
        if prefix == ".testsites.":
            m = re.match(r"^([a-z0-9][a-z0-9-]*)\.testsites\." + re.escape(BASE_DOMAIN) + r"$", host)
        else:
            m = re.match(r"^testsites-([a-z0-9][a-z0-9-]*)\." + re.escape(BASE_DOMAIN) + r"$", host)
        if m:
            return m.group(1)
    return None


async def handle(reader, writer):
    global ACTIVE
    ACTIVE += 1
    if ACTIVE > MAX_CONN:
        ACTIVE -= 1
        try:
            await respond(writer, 503, body=b"too many connections\n")
            writer.close()
        except Exception:
            pass
        return
    peer = writer.get_extra_info("peername")
    started = time.monotonic()
    meta = {"status": None, "extra": {}, "bytes": 0}
    host = path = method = None
    try:
        req = await read_request(reader)
        if req is None:
            return
        method, target, version, headers = req
        parts = urlsplit(target)
        path, qs = parts.path, parse_qs(parts.query)
        host = headers.get("host", "")
        site = route(host)
        log(event="request", host=host, site=site, method=method, path=path,
            query=parts.query, http_version=version, headers=headers,
            client_ip=client_ip(headers), peer=peer, cf_ray=headers.get("cf-ray"),
            user_agent=headers.get("user-agent"), referer=headers.get("referer"))
        if headers.get("expect", "").lower() == "100-continue":
            writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
            await writer.drain()
        head_only = method == "HEAD"

        if site == "ws":
            meta["extra"] = await ws_session(reader, writer, headers, host, path)
            meta["status"] = 101
            return

        if site == "index":
            if path in ("/", "/index.html"):
                meta["status"] = 200
                meta["bytes"] = len(index_html())
                await respond(writer, 200, body=index_html().encode(), head_only=head_only)
            elif path == "/health":
                meta["status"] = 200
                await json_respond(writer, 200, vitals(), head_only)
            else:
                meta["status"] = 404
                await respond(writer, 404, body=b"not found\n")

        elif site == "upload":
            if method in ("POST", "PUT", "PATCH"):
                meta["extra"] = await stream_upload(reader, writer, headers, method, host, qs, head_only, path)
                meta["status"] = 200
                meta["bytes"] = meta["extra"]["bytes_received"]
            else:
                meta["status"] = 200
                await respond(writer, 200, body=html_page("upload", f"""
<h1>Streaming upload</h1>
<p class="muted">POST/PUT/PATCH any size. Memory only, never written to disk.</p>
<pre>curl -s --data-binary @- "{site_url('upload')}" &lt; bigfile
head -c 50M /dev/zero | curl -s --data-binary @- "{site_url('upload')}"
curl -s -T big.iso "{site_url('upload')}?hash=md5"</pre>
<p class="muted">Through Cloudflare Free the edge rejects request bodies over 100 MB
(413/526/502) before they reach this server.</p>
<p class="muted">Query: <code>chunk</code> bytes per digest, <code>hash</code>=md5|sha1|sha512,
<code>format</code>=html|json.</p>""").encode())

        elif site == "gui":
            if method == "POST":
                meta["extra"] = await gui_upload(reader, writer, headers, host, path)
                meta["status"] = 200
            else:
                meta["status"] = 200
                await respond(writer, 200, body=gui_html(host).encode(), head_only=head_only)

        elif site == "download":
            if path not in ("/", "/download", "/sink"):
                meta["status"] = 404
                await respond(writer, 404, body=b"not found\n")
            else:
                meta["status"] = 200
                meta["extra"] = await stream_download(writer, qs, head_only)

        elif site in ("echo", "headers"):
            meta["status"] = 200
            preview = bytearray()
            async for data in body_iter(reader, headers):
                if len(preview) < 65536:
                    preview += data[: 65536 - len(preview)]
            await json_respond(writer, 200, {
                "method": method, "url": target, "path": path,
                "query_raw": parts.query, "query": qs,
                "http_version": version, "host": host,
                "headers": headers,
                "cookies": parse_cookies(headers.get("cookie")),
                "client": ip_report(headers, peer),
                "body_bytes": len(preview),
                "body_preview_b64": base64.b64encode(bytes(preview)).decode(),
            }, head_only)

        elif site == "ip":
            meta["status"] = 200
            await json_respond(writer, 200, ip_report(headers, peer), head_only)

        elif site == "tools":
            meta["extra"] = await tools(reader, writer, headers, method, path, qs, head_only)
            meta["status"] = meta["extra"].get("status", 200)

        else:
            meta["status"] = 404
            await respond(writer, 404, body=html_page("unknown host", f"""
<h1>Unknown host</h1><p><code>{host}</code> is not part of the test suite.</p>
<p><a href="https://{SITE}/">See the table of contents</a></p>""").encode(), head_only=head_only)

    except asyncio.TimeoutError:
        meta["status"] = meta["status"] or 408
    except (ConnectionResetError, BrokenPipeError):
        meta["status"] = meta["status"] or 499
    except Exception as exc:
        meta["status"] = 500
        log(event="error", host=host, path=path, error=repr(exc))
        if not getattr(writer, "responded", False):
            try:
                await respond(writer, 500, {"Content-Type": "application/json"},
                              b'{"error": "internal"}', False)
            except Exception:
                pass
    finally:
        ACTIVE -= 1
        dur = round((time.monotonic() - started) * 1000, 1)
        log(event="response", host=host, path=path, method=method, status=meta["status"],
            duration_ms=dur, resp_bytes=meta["bytes"], detail=meta["extra"])
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def gui_upload(reader, writer, headers, host, path):
    total = 0
    h = hashlib.sha256()
    head = bytearray()
    started = time.monotonic()
    async for data in body_iter(reader, headers):
        total += len(data)
        h.update(data)
        if len(head) < 16384:
            head += data[: 16384 - len(head)]
    multipart = "multipart/form-data" in headers.get("content-type", "").lower()
    names = re.findall(rb'filename="([^"]*)"', bytes(head)) if multipart else []
    elapsed = (time.monotonic() - started) * 1000
    files = [html.escape(n.decode("utf-8", "replace")) for n in names]
    text_field = ""
    if multipart:
        hit = re.search(rb'name="text"\r\n\r\n(.*?)\r\n--', bytes(head), re.S)
        if hit:
            text_field = html.escape(hit.group(1).decode("utf-8", "replace"))[:2000]
    else:
        text_field = html.escape(bytes(head).decode("utf-8", "replace"))[:2000]
    mode = "multipart" if multipart else "raw"
    body = f"""
<h1>Upload complete</h1>
<table>
<tr><th>Bytes received</th><td>{total:,} ({fmt_bytes(total)})</td></tr>
<tr><th>SHA-256</th><td><code>{h.hexdigest()}</code></td></tr>
<tr><th>Mode</th><td>{mode}</td></tr>
<tr><th>Files</th><td>{', '.join(files) if files else '<span class="muted">none</span>'}</td></tr>
<tr><th>Text</th><td>{(('<code>' + text_field + '</code>') if text_field else '<span class="muted">none</span>')}</td></tr>
<tr><th>Time</th><td>{elapsed:.0f} ms</td></tr>
<tr><th>Content-Length</th><td>{headers.get('content-length', 'chunked')}</td></tr>
</table>
<p class="muted">Body was streamed through memory and discarded.</p>
<p><a href="/">Upload another</a> · <a href="https://{SITE}/">Index</a></p>"""
    await respond(writer, 200, body=html_page("upload complete", body).encode())
    return {"gui_bytes": total, "sha256": h.hexdigest(), "files": files, "mode": mode}


async def tools(reader, writer, headers, method, path, qs, head_only):
    def q(name, default=None):
        return qs.get(name, [default])[0]

    if path in ("/", ""):
        body = html_page("proxy tools", f"""
<h1>Proxy tools</h1>
<table>
<tr><th>Endpoint</th><th>Effect</th></tr>
<tr><td><a href="/delay?ms=2000">/delay?ms=N</a></td><td>sleep N ms, then 200</td></tr>
<tr><td><a href="/status?code=418">/status?code=N</a></td><td>reply with status N</td></tr>
<tr><td><a href="/gzip?kb=256">/gzip?kb=N</a></td><td>gzip-compressed N KiB</td></tr>
<tr><td><a href="/redirect?n=2">/redirect?n=N</a></td><td>N chained 302 hops, then index</td></tr>
<tr><td><a href="/cookie?set=1">/cookie?set=1</a></td><td>set cookies, echo received ones</td></tr>
<tr><td><a href="/sse?n=5">/sse?n=N</a></td><td>N server-sent events, 1/s</td></tr>
<tr><td>/echo</td><td>mirror method, headers and body (64 KiB cap)</td></tr>
<tr><td>/slow?seconds=N&amp;kbps=N</td><td>slow trickle stream, for timeout tests</td></tr>
</table>
<p class="muted">All responses stream; nothing is buffered to disk.</p>""")
        await respond(writer, 200, body=body.encode(), head_only=head_only)
        return {"tool": "index"}

    if path == "/delay":
        ms = min(int(q("ms", "1000")) or 0, 300000)
        await asyncio.sleep(ms / 1000)
        await json_respond(writer, 200, {"slept_ms": ms}, head_only)
        return {"tool": "delay", "ms": ms}

    if path == "/status":
        code = int(q("code", "200") or 200)
        code = code if 100 <= code <= 599 else 200
        await respond(writer, code, {"Content-Type": "application/json"},
                      json.dumps({"requested_status": code}).encode(), head_only)
        return {"tool": "status", "code": code, "status": code}

    if path == "/gzip":
        kb = min(int(q("kb", "64") or 64), 4096)
        payload = (b"testsites gzip probe 0123456789\n" * (kb * 1024 // 33 + 1))[: kb * 1024]
        gz = gzip.compress(payload, 6)
        await respond(writer, 200, {"Content-Type": "text/plain; charset=utf-8",
                                    "Content-Encoding": "gzip",
                                    "X-Uncompressed-Size": str(len(payload))}, gz, head_only)
        return {"tool": "gzip", "raw": len(payload), "gzip": len(gz)}

    if path == "/redirect":
        n = min(int(q("n", "1") or 1), 20)
        if n <= 1:
            await respond(writer, 302, {"Location": f"https://{SITE}/"}, b"", head_only)
        else:
            await respond(writer, 302, {"Location": f"/redirect?n={n - 1}"}, b"", head_only)
        return {"tool": "redirect", "hops": n}

    if path == "/cookie":
        received = headers.get("cookie")
        await respond(writer, 200, {
            "Content-Type": "application/json",
            "Set-Cookie": "ts_a=1; Path=/; SameSite=Lax",
        }, json.dumps({"received_cookie": received,
                       "note": "also sent ts_a; add ?set=1 again to see it"}).encode(), head_only)
        return {"tool": "cookie", "received": received}

    if path == "/sse":
        n = min(int(q("n", "5") or 5), 1000)
        writer.responded = True
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                     b"Cache-Control: no-store\r\nConnection: close\r\n\r\n")
        for i in range(n):
            writer.write(f"data: {json.dumps({'i': i, 'ts': now_iso()})}\n\n".encode())
            await writer.drain()
            if i < n - 1:
                await asyncio.sleep(1)
        writer.write(b"event: done\ndata: {}\n\n")
        await writer.drain()
        return {"tool": "sse", "events": n}

    if path == "/slow":
        seconds = min(float(q("seconds", "10") or 10), 600)
        kbps = max(float(q("kbps", "8") or 8), 0.1)
        chunk = int(kbps * 1024 / 10)
        steps = int(seconds * 10)
        writer.responded = True
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                     b"Transfer-Encoding: chunked\r\nCache-Control: no-store\r\n\r\n")
        total = 0
        for _ in range(steps):
            payload = b"x" * chunk
            writer.write(b"%x\r\n" % len(payload) + payload + b"\r\n")
            await writer.drain()
            total += chunk
            await asyncio.sleep(0.1)
        writer.write(b"0\r\n\r\n")
        await writer.drain()
        return {"tool": "slow", "seconds": seconds, "kbps": kbps, "bytes": total}

    if path == "/echo":
        body = bytearray()
        async for data in body_iter(reader, headers):
            if len(body) < 65536:
                body += data[: 65536 - len(body)]
        payload = json.dumps({"method": method, "path": path, "query": qs,
                              "headers": headers,
                              "body_b64": base64.b64encode(bytes(body)).decode()},
                             indent=2).encode()
        await respond(writer, 200, {"Content-Type": "application/json"}, payload, head_only)
        return {"tool": "echo", "body_bytes": len(body)}

    await respond(writer, 404, body=b"unknown tool\n")
    return {"tool": "unknown", "status": 404}


async def main():
    load_local_ips()
    os.makedirs(LOG_DIR, exist_ok=True)
    server = await asyncio.start_server(handle, "0.0.0.0", PORT, backlog=512,
                                        limit=1024 * 1024)
    log(event="start", port=PORT, pid=os.getpid(), base_domain=BASE_DOMAIN)
    print(f"testsites listening on :{PORT}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
