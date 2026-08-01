#!/bin/bash
set -uo pipefail

REPO=/workspace
DB="$REPO/yyb_go/resource/db/yyb.db"
LOG="$REPO/scripts/backup.log"
mkdir -p "$REPO/scripts"

echo "$(date '+%F %T') backup start" >> "$LOG"

# checkpoint WAL into the main db file so the tracked snapshot is consistent
python3 - "$DB" <<'PY' >> "$LOG" 2>&1
import sqlite3, sys
try:
    con = sqlite3.connect(sys.argv[1], timeout=5)
    con.execute("PRAGMA wal_checkpoint(PASSIVE)")
    con.commit()
    con.close()
except Exception as e:
    print("checkpoint failed:", e)
PY

cd "$REPO"
git add -A
if git diff --cached --quiet; then
  echo "$(date '+%F %T') no changes, skip" >> "$LOG"
  exit 0
fi

git -c user.name="yyb-backup" -c user.email="yyb-backup@local" commit -m "backup $(date '+%F %T')" >> "$LOG" 2>&1
if git push origin master >> "$LOG" 2>&1; then
  echo "$(date '+%F %T') push ok" >> "$LOG"
else
  echo "$(date '+%F %T') push FAILED" >> "$LOG"
fi
