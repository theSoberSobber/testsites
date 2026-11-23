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
 && mkdir -p /var/log/testsites/archives \
             /var/log/testsites/svc/testsites /var/log/testsites/svc/rotate

ENV LOG_DIR=/var/log/testsites \
    MAX_BYTES=67108864 \
    KEEP_ARCHIVES=20 \
    INTERVAL=10 \
    PORT=8080

EXPOSE 8080
VOLUME ["/var/log/testsites"]
STOPSIGNAL SIGTERM
CMD ["/usr/bin/svscan", "/service"]
