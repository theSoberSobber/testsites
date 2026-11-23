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
| https://testsites-gui.1110777.xyz/ | Browser form upload (multipart) |
| https://testsites-download.1110777.xyz/ | Content-Length sink or infinite stream |
| https://testsites-ws.1110777.xyz/ | WebSocket echo (text + binary) |
| https://testsites-headers.1110777.xyz/ | JSON dump of all request headers |
| https://testsites-ip.1110777.xyz/ | IPv4/IPv6 as seen by the edge |
| https://testsites-tools.1110777.xyz/ | delay, status, gzip, redirect, cookie, SSE, slow, echo |

## Examples

```bash
# 5 GiB upload, nothing on disk
head -c 5G /dev/zero | curl -s --data-binary @- https://testsites-upload.1110777.xyz/

# verify the hash round-trips
curl -s --data-binary @file.bin https://testsites-upload.1110777.xyz/

# exactly 100 MiB
curl -s -o /dev/null -w '%{size_download}\n' \
  "https://testsites-download.1110777.xyz/?bytes=104857600"

# endless
curl -s "https://testsites-download.1110777.xyz/?infinite=1" | pv > /dev/null
```

Upload query params: `chunk` (bytes per digest, default 1 MiB), `hash`
(`md5|sha1|sha512` in addition to sha256), `format=html|json`.
Download query params: `bytes`, `infinite`, `chunk`, `pattern=seq|zero|random`,
`rate` (bytes/sec), `filename=demo.pdf` (sets `Content-Type` and
`Content-Disposition` from the extension), `ext=pdf` (shorthand).

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

`testsites-tunnel.service` still runs on the host:
`cloudflared tunnel --protocol http2 run` (QUIC registration was unreliable on this
link, hence http2). Tunnel config: `~/.cloudflared/testsites.yml`, tunnel `9dbf4b04-…`.

### Access log rotation

`rotate-access-log.sh` polls `access.jsonl` every `INTERVAL` seconds and, once it
passes `MAX_BYTES` (default 64 MiB), renames it to
`archives/access-<UTC>.jsonl`, recreates the live path, gzips the archive and keeps
the newest `KEEP_ARCHIVES` (default 20) gzipped files.

It is safe against the writer because the app opens the log with
`O_APPEND|O_CREAT` for every record and closes it immediately — there is no
long-lived fd to go stale. After the rename the next record recreates the file at
the original path, so no lines are lost. `/var/log/testsites` is a host volume, so
archives survive container rebuilds.
