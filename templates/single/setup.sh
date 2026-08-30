#!/usr/bin/env bash
set -Eeuo pipefail
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$DIR"
info(){ printf '[INFO] %s\n' "$*"; }
warn(){ printf '[WARN] %s\n' "$*" >&2; }
compose(){ docker compose "$@"; }
while :; do
  printf '\n============================================================\n'
  printf 'DFIR-IRIS Single-Node Management\n'
  printf '============================================================\n'
  printf '  1) Status\n  2) Start\n  3) Stop\n  4) Restart\n  5) Logs\n  6) Backup database\n  0) Exit\n'
  printf 'Choose: '
  read -r c
  case "$c" in
    1) compose ps ;;
    2) compose up -d ;;
    3) compose stop ;;
    4) compose restart ;;
    5) compose logs --tail=200 ;;
    6)
      mkdir -p backups
      . ./.env
      f="backups/iris_db_$(date +%Y%m%d_%H%M%S).sql.gz"
      compose exec -T db pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB" | gzip >"$f"
      chmod 600 "$f"
      info "Backup: $f"
      ;;
    0) exit 0 ;;
    *) warn "Invalid option." ;;
  esac
done
