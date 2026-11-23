# testsites

Cloudflare Tunnel test suite for verifying big uploads, long downloads, WebSockets and
what the edge does to headers. Runs on `debian` (`192.168.1.51`) behind the
`testsites` tunnel, publicly at `1110777.xyz`.

Single file, zero dependencies: `app.py` is a hand-rolled asyncio HTTP/1.1 + WebSocket
server. Nothing is written to disk; uploads are streamed through memory and hashed.

## Sites

> Cloudflare's Universal SSL covers `*.1110777.xyz` (one label only). **Nested
> `action.testsites.1110777.xyz` names fail the TLS handshake until Total TLS /
> Advanced Certificate Manager is enabled on the zone.** The flat
> `testsites-<action>` names below are the ones that work today. Both are routed in
> the tunnel ingress, so nested names start working the moment a cert exists.

| URL | What it does |
| --- | --- |
| https://testsites.1110777.xyz/ | Inventory / table of contents |
| https://testsites-upload.1110777.xyz/ | Streaming upload, memory only |
| https://testsites-gui.1110777.xyz/ | Browser form: text box, files, or raw-body mode |
| https://testsites-download.1110777.xyz/ | Content-Length sink or infinite stream |
| https://testsites-ws.1110777.xyz/ | WebSocket echo (text + binary) |
| https://testsites-headers.1110777.xyz/ | JSON dump of all request headers |
| https://testsites-ip.1110777.xyz/ | IPv4/IPv6 as seen by the edge |
| https://testsites-tools.1110777.xyz/ | delay, status, gzip, redirect, cookie, SSE, slow, echo |

## Examples

```bash
# upload, nothing on disk (Cloudflare Free rejects >100 MB per request)
head -c 50M /dev/zero | curl -s --data-binary @- https://testsites-upload.1110777.xyz/

# verify the hash round-trips
curl -s --data-binary @file.bin https://testsites-upload.1110777.xyz/

# exactly 100 MiB
curl -s -o /dev/null -w '%{size_download}\n' \
  "https://testsites-download.1110777.xyz/?bytes=104857600"

# long chunked stream, capped at 256 MiB
curl -s "https://testsites-download.1110777.xyz/?infinite=1" | pv > /dev/null
```

Upload query params: `chunk` (bytes per digest, default 1 MiB), `hash`
(`md5|sha1|sha512` in addition to sha256), `format=html|json`.
Download query params: `bytes`, `infinite`, `chunk`, `pattern=seq|zero|random`,
`rate` (bytes/sec), `filename=demo.pdf` (sets `Content-Type` and
`Content-Disposition` from the extension).

## Logging

Every request is appended to `logs/access.jsonl` (one JSON object per line):

- `request`: timestamp, host, resolved site, method, path, query string, all headers,
  client IP (`cf-connecting-ip`), socket peer, `cf-ray`, user agent, referer.
- `upload_progress`: every 5s while a body streams (bytes + chunk count).
- `response`: status, duration, response bytes, and a route-specific `detail` object
  (hash, chunk digests, bytes served, WS frame counts).
- `ws_open` / `error` / `start` events.

Upload bodies are never stored; a 256-byte prefix is kept base64-encoded for
analysis, plus full SHA-256.

## Abuse limits

This runs on a home uplink, so the defaults are deliberately conservative and
all overridable by env var:

| Limit | Default | Env |
| --- | --- | --- |
| Max bytes per stream (`bytes` or `infinite`) | 256 MiB | `MAX_STREAM_MB` |
| Shared egress rate across all clients | 16 MiB/s | `DL_RATE_MBPS` |
| Requests per IP per minute | 120 | `RATE_MAX` / `RATE_WINDOW` |
| Concurrent requests per IP | 8 | `PER_IP_CONN` |
| Concurrent connections overall | 200 | `MAX_CONN` |

Over the per-IP request budget the API answers `429` with the limit that was hit.
The shared token bucket is what actually protects the uplink: however many clients
download at once, total outbound converges to `DL_RATE_MBPS`.

## Network isolation

The container runs on an `--internal` Docker network with no route off the host,
so a compromised process cannot reach the LAN or the internet; it can only be
reached through the published `127.0.0.1:8080` port that `cloudflared` uses. There
are no inbound port forwards on the router: the tunnel is outbound-only.

## Monitoring

`.github/workflows/monitor.yml` runs every 15 minutes (plus manual dispatch) and
exercises the sites end to end: status codes, a 4 MiB upload checked against
SHA-256, exact `?bytes=` download length, `?filename=` content type, a real
WebSocket echo, cookie/header echo, 418 pass-through, delay, gzip, a GUI
multipart POST, and `/health` vitals (RSS, connections, disk headroom).

Every probe carries `X-Monitor: gha-cron`, a unique `X-Monitor-Run` id and the
`testsites-gha-monitor` user agent, so monitor traffic is trivially separable
from real traffic in `access.jsonl`:

```bash
jq -c 'select(.headers["x-monitor"]=="gha-cron")' access.jsonl
```

`/health` is public liveness only (`{"ok": true}`). Full vitals (RSS, connections,
disk, log size, archive count) require `X-Health-Token` matching the `HEALTH_TOKEN`
env var, which is also stored as the repo's `HEALTH_TOKEN` Actions secret.

## Privacy

[`/privacy`](https://testsites.1110777.xyz/privacy): assume everything is logged.
Headers, cookies, IP, user agent and a short body sample may end up in the JSONL
file. What happens to it afterwards is undecided; it may be analysed, it may be
deleted by the rotation. Do not send secrets.

## Ops

```bash
sudo systemctl status testsites testsites-tunnel
sudo journalctl -u testsites-tunnel -n 50
```

The app runs in Docker under **daemontools** (`svscan`), so each piece is supervised:

```
/service/testsites/run          python app on :8080
/service/testsites/log/run      multilog t s1000000 n10  -> stdout/stderr
/service/accesslog-rotate/run   size-based JSONL rotation
/service/accesslog-rotate/log/  multilog for the rotator itself
```

```bash
docker exec testsites svstat /service/testsites /service/accesslog-rotate
docker exec testsites svc -t /service/testsites      # restart the app
docker exec testsites svc -d /service/accesslog-rotate
```

`cloudflared` runs as a second container on the same internal network, with its own
`egress` network so it can reach Cloudflare. The app itself has **no** route off the
host and no published port, so the only way in is the tunnel, and a compromised app
process cannot reach the LAN or the internet. Tunnel config:
`/opt/testsites-tunnel/config.yml` (mounted read-only), tunnel `9dbf4b04-…`.

```bash
docker logs testsites-tunnel | grep 'Registered tunnel connection'
docker network inspect testsites-net --format '{{.Internal}}'   # true
```

### Access log rotation

`rotate-access-log.sh` polls `access.jsonl` every `INTERVAL` seconds and, once it
passes `MAX_BYTES` (default 64 MiB), renames it to
`archives/access-<UTC>.jsonl`, recreates the live path, gzips the archive and keeps
the newest `KEEP_ARCHIVES` (default 20) gzipped files.

Beyond time-based rotation it also enforces storage limits every poll:
`MIN_FREE_MB` (default 1024) prunes the oldest archive whenever the volume drops
below that free-space floor, and `MAX_ARCHIVE_MB` (default 2048) caps the archive
directory. That is what keeps a burst of traffic from filling the laptop's disk.

It is safe against the writer because the app opens the log with
`O_APPEND|O_CREAT` for every record and closes it immediately — there is no
long-lived fd to go stale. After the rename the next record recreates the file at
the original path, so no lines are lost. `/var/log/testsites` is a host volume, so
archives survive container rebuilds.
