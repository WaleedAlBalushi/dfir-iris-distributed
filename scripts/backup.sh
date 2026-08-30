#!/usr/bin/env bash
set -Eeuo pipefail
DIR=${1:-$(pwd)}
[ -x "$DIR/setup.sh" ] || { echo "setup.sh not found in $DIR" >&2; exit 1; }
if [ -f "$DIR/.iris-role" ] && grep -qx 'database' "$DIR/.iris-role"; then
  exec "$DIR/setup.sh" backup
else
  exec "$DIR/setup.sh" backup-app
fi
