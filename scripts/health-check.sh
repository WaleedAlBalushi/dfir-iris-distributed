#!/usr/bin/env bash
set -Eeuo pipefail
DIR=${1:-$(pwd)}
[ -x "$DIR/setup.sh" ] || { echo "setup.sh not found in $DIR" >&2; exit 1; }
exec "$DIR/setup.sh" doctor
