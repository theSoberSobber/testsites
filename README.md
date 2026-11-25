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
`Content-Disposition` from the extension), `type=text/csv` (sends exactly that
`Content-Type`, overriding the filename guess; shortcuts `json`, `text`, `html`,
`csv`, `xml`, `pdf`, `zip`, `png`, `jpeg`, `mp4`, `bin`). The download landing
page has a small form for picking type and size.

## Webhook inspector

`POST https://testsites.1110777.xyz/hook` accepts any method, content type and
body, and hands back a link that renders it: method, path, query, every header,
client IP, size, SHA-256 and a pretty-printed (or hex) body.

- first 64 KiB of the body kept, last 50 captures, one hour TTL, memory only
- `GET /hook` lists captures, `GET /hook/<id>?raw=1` returns the raw body,
  `DELETE /hook/<id>` removes one
- `?status=204` makes the capture reply with that status instead of 202

Everything is HTML-escaped before rendering, so a body or header containing
markup is shown as text. Useful for GitHub, Stripe, or your own webhook senders.

## For agents

`https://testsites.1110777.xyz/llms.txt` describes every endpoint, query
parameter, limit and example in one plain-text file, in the
[llms.txt](https://llmstxt.org) shape. It is linked from the footer of every page
and from the index, so an agent that lands anywhere can find the rest.

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

Everything runs under Docker Compose (`docker-compose.yml` for the app and tunnel,
`monitoring/docker-compose.yml` for the metrics stack).

The app container sits on `testsites-net`, an `internal` network with no route off
the host, and publishes no ports at all: the only way in is `cloudflared` over that
same network. There are no inbound port forwards on the router; the tunnel is
outbound-only. `cloudflared` gets a second network (`testsites_egress`) for its
outbound connection to Cloudflare.

A small `testsites-netguard` systemd unit (`/usr/local/sbin/testsites-netguard.sh`)
adds `DOCKER-USER` and `INPUT` rules so the tunnel and monitoring subnets cannot
reach the home LAN (`192.168.0.0/16`, `10.0.0.0/8`), the host's SSH port, the
Tailscale address, the monitoring subnet (for the tunnel), or each other. The
rules match `--ctstate NEW`, so replies to published ports still work.

```bash
sudo systemctl status testsites-netguard
sudo iptables -S DOCKER-USER | grep REJECT
```

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

### Dashboards

The `monitoring/` stack runs Prometheus, Loki, Promtail, node_exporter and a small
stdlib exporter that tails `access.jsonl`. Grafana listens only on the Tailscale
address, never the LAN:

```
http://100.112.185.9:3000/d/testsites
```

The admin password lives in `monitoring/.env` (`GRAFANA_PASSWORD`, mode 600,
gitignored). The dashboard covers requests/responses by host and status, upload
and download bytes, request duration, unique IPs, log growth and disk headroom,
host CPU/memory/load, and Loki panels for access and container logs.

### External probes

Probe traffic is tagged at the source: the app records `probe` on every log
record that carries `X-Monitor` (GHA sends `gha-cron`). The exporter turns that
into `testsites_probe_requests_total`, `testsites_probe_responses_total`,
`testsites_probe_duration_seconds`, `testsites_probe_upload_bytes_total`,
`testsites_probe_last_seen_timestamp_seconds` and `testsites_probe_gap_seconds`.

The dashboard's "External probes" row shows probe age, success rate, count,
upload volume, latency and status mix. Last probe age is the important one: GHA
runs every 15 minutes, so anything past ~35 minutes means the tunnel, the runner
or the app is down. Grafana evaluates that from `time() - max(last_seen)`, which
still works when no probe can reach the box.

### Alerts

Provisioned in `monitoring/grafana/provisioning/alerting/`:

| rule | fires when |
| --- | --- |
| GHA probes stopped arriving | no probe in 30 min (critical) |
| GHA probes are failing | probes arrive but get non-2xx (warning) |
| Disk headroom below 10 percent | free space on the volume (warning) |
| Delivery self-test (paused) | manually unpaused, proves the phone buzzes |

Delivery is a webhook to [ntfy](https://ntfy.sh): subscribe to the topic in
`monitoring/.env` (`NTFY_TOPIC`, gitignored) in the ntfy app or at
`https://ntfy.sh/<topic>`. Treat it as a secret — anyone who knows the topic can
read it. Change the value and restart Grafana to rotate it.

This is deliberately two-layered. Grafana can notice *stale* probes, but it
cannot notice the whole box being down. That case is covered by the GHA workflow
itself going red (GitHub emails the workflow owner) — set that notification in
GitHub if you want it.

## Privacy

[`/privacy`](https://testsites.1110777.xyz/privacy): assume everything is logged.
Headers, cookies, IP, user agent and a short body sample may end up in the JSONL
file. What happens to it afterwards is undecided; it may be analysed, it may be
deleted by the rotation. Do not send secrets.

## Ops

```bash
cd /home/pavit/testsites
sudo docker compose ps
sudo docker compose logs --tail 50 tunnel
sudo docker compose up -d --build     # deploy a new app.py

cd monitoring && sudo docker compose ps && cd ..
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
