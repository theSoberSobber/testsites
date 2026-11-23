#!/bin/sh
# Size-based rotation + storage guard for the JSONL access log.
#
# The app opens the log with O_APPEND|O_CREAT for every record and closes it
# immediately, so it never holds a long-lived fd. Rename-based rotation is
# therefore writer-safe: after the move the next record recreates access.jsonl.
set -u

DIR="${LOG_DIR:-/var/log/testsites}"
MAX="${MAX_BYTES:-67108864}"
KEEP="${KEEP_ARCHIVES:-20}"
INTERVAL="${INTERVAL:-10}"
MIN_FREE_MB="${MIN_FREE_MB:-1024}"
MAX_ARCHIVE_MB="${MAX_ARCHIVE_MB:-2048}"
SRC="$DIR/access.jsonl"
ARC="$DIR/archives"

mkdir -p "$ARC"
echo "access-log rotator: dir=$DIR max=${MAX}B keep=$KEEP interval=${INTERVAL}s" \
     "min_free=${MIN_FREE_MB}MB max_archive=${MAX_ARCHIVE_MB}MB"

free_kb() { df -Pk "$ARC" 2>/dev/null | awk 'NR==2 {print $4}'; }
arc_kb()  { du -sk "$ARC" 2>/dev/null | awk '{print $1}'; }

prune() {
    pruned=0
    while :; do
        oldest=$(ls -1t "$ARC"/access-*.jsonl.gz 2>/dev/null | tail -1)
        [ -z "$oldest" ] && break
        f=$(free_kb); a=$(arc_kb)
        if [ "${f:-0}" -lt $((MIN_FREE_MB * 1024)) ] || [ "${a:-0}" -gt $((MAX_ARCHIVE_MB * 1024)) ]; then
            rm -f "$oldest" && pruned=$((pruned + 1)) || break
            echo "pruned $oldest (free=${f}KB archives=${a}KB)"
        else
            break
        fi
    done
    # count-based retention, independent of size
    for old in $(ls -1t "$ARC"/access-*.jsonl.gz 2>/dev/null | tail -n +$((KEEP + 1))); do
        rm -f "$old" && pruned=$((pruned + 1)) && echo "pruned $old (keep=$KEEP)"
    done
    return 0
}

while :; do
    if [ -f "$SRC" ]; then
        size=$(stat -c %s "$SRC" 2>/dev/null || echo 0)
        if [ "${size:-0}" -ge "$MAX" ]; then
            ts=$(date -u +%Y%m%dT%H%M%SZ)
            target="$ARC/access-$ts.jsonl"
            if mv "$SRC" "$target" 2>/dev/null; then
                # recreate at once; touch never truncates, so a record written
                # in the gap between mv and touch is not lost
                touch "$SRC" 2>/dev/null || true
                echo "rotated ${size}B -> $target"
                if gzip -9 "$target"; then
                    echo "compressed $target.gz"
                fi
            fi
        fi
    fi
    prune
    sleep "$INTERVAL"
done
