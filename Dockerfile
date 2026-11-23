FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      daemontools python3 gzip procps ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY app.py /app/app.py
COPY service /service
COPY rotate-access-log.sh /usr/local/bin/rotate-access-log.sh

RUN chmod +x /usr/local/bin/rotate-access-log.sh \
            /service/testsites/run /service/testsites/log/run \
            /service/accesslog-rotate/run /service/accesslog-rotate/log/run \
 && chmod -R a+rX /service /app \
 && chmod a+rx /usr/local/bin/rotate-access-log.sh \
 && mkdir -p /var/log/testsites/archives \
             /var/log/testsites/svc/testsites /var/log/testsites/svc/rotate \
 && groupadd -g 1001 app \
 && useradd -u 1001 -g 1001 -M -s /usr/sbin/nologin app \
 && chown -R 1001:1001 /var/log/testsites

# daemontools does not need root; bind 8080 (>1024) needs no privileges.
USER 1001:1001

ENV LOG_DIR=/var/log/testsites \
    MAX_BYTES=67108864 \
    KEEP_ARCHIVES=20 \
    INTERVAL=10 \
    MIN_FREE_MB=1024 \
    MAX_ARCHIVE_MB=2048 \
    MAX_STREAM_MB=256 \
    DL_RATE_MBPS=16 \
    PORT=8080

EXPOSE 8080
VOLUME ["/var/log/testsites"]
STOPSIGNAL SIGTERM
CMD ["/usr/bin/svscan", "/service"]
