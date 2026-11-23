#!/bin/sh
# Size-based rotation for the JSONL access log.
#
# The app opens the log with O_APPEND|O_CREAT on every single record and closes it
# immediately, so it never holds a long-lived fd. That makes rename-based rotation
# writer-safe: once the file is moved aside, the next record recreates access.jsonl
# at the original path. No HUP, no copytruncate, no lost lines (worst case is one
# record landing in the archived inode during the few microseconds around the mv).
set -u

DIR="${LOG_DIR:-/var/log/testsites}"
MAX="${MAX_BYTES:-67108864}"
KEEP="${KEEP_ARCHIVES:-20}"
INTERVAL="${INTERVAL:-10}"
SRC="$DIR/access.jsonl"
ARC="$DIR/archives"

mkdir -p "$ARC"
echo "access-log rotator: dir=$DIR max=${MAX}B keep=$KEEP interval=${INTERVAL}s"

while :; do
    if [ -f "$SRC" ]; then
        size=$(stat -c %s "$SRC" 2>/dev/null || echo 0)
        if [ "${size:-0}" -ge "$MAX" ]; then
            ts=$(date -u +%Y%m%dT%H%M%SZ)
            target="$ARC/access-$ts.jsonl"
            if mv "$SRC" "$target" 2>/dev/null; then
                # recreate immediately so a writer never finds the path missing;
                # touch never truncates, so a record written in the gap survives
                touch "$SRC" 2>/dev/null || true
                echo "rotated ${size}B -> $target"
                # compress off the hot path; the writer is already on a fresh file
                gzip -9 "$target" && echo "compressed $target.gz"
                pruned=0
                for old in $(ls -1t "$ARC"/access-*.jsonl.gz 2>/dev/null | tail -n +$((KEEP + 1))); do
                    rm -f "$old" && pruned=$((pruned + 1))
                done
                [ "$pruned" -gt 0 ] && echo "pruned $pruned old archive(s)"
            fi
        fi
    fi
    sleep "$INTERVAL"
done
