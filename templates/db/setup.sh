#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$DIR"

info(){ printf '[INFO] %s\n' "$*"; }
ok(){ printf '[OK] %s\n' "$*"; }
warn(){ printf '[WARN] %s\n' "$*" >&2; }
die(){ printf '[ERROR] %s\n' "$*" >&2; exit 1; }
have(){ command -v "$1" >/dev/null 2>&1; }

load_env(){
  [ -f "$DIR/.env" ] || die "Missing $DIR/.env"
  set -a
  # shellcheck disable=SC1091
  . "$DIR/.env"
  set +a
}

compose(){
  docker compose -p "${COMPOSE_PROJECT_NAME:-iris-db}" -f "$DIR/docker-compose.yml" "$@"
}

pause_menu(){ printf '\nPress Enter to return...'; IFS= read -r _ || true; }

prompt_yes_no(){
  local prompt=$1 answer
  while :; do
    printf '\n%s\n  1) Yes\n  2) No\nChoose: ' "$prompt"
    IFS= read -r answer || return 1
    case "$answer" in 1|y|Y|yes|YES) return 0;; 2|n|N|no|NO) return 1;; *) warn "Choose 1 or 2.";; esac
  done
}

status_db(){ compose ps; }
start_db(){ compose up -d; }
stop_db(){ compose stop db; }
restart_db(){ compose restart db; }
logs_db(){ compose logs --tail=250 db; }

db_ready(){
  load_env
  docker exec iriswebapp_db pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB" >/dev/null 2>&1
}

health_db(){
  load_env
  local failed=0
  printf '\nDatabase health check\n'
  docker info >/dev/null 2>&1 && ok "Docker daemon reachable" || { warn "Docker unavailable"; failed=1; }
  compose config >/dev/null 2>&1 && ok "Compose configuration valid" || { warn "Compose config invalid"; failed=1; }
  docker ps --format '{{.Names}}' | grep -Fxq iriswebapp_db && ok "Database container running" || { warn "Database container not running"; failed=1; }
  if docker ps --format '{{.Names}}' | grep -Fxq iriswebapp_db; then
    db_ready && ok "PostgreSQL ready" || { warn "PostgreSQL not ready"; failed=1; }
    if docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" iriswebapp_db psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atqc 'select 1' 2>/dev/null | grep -qx 1; then
      ok "Database authentication successful"
    else
      warn "Database authentication failed"
      failed=1
    fi
  fi
  if have ss && ss -ltn | grep -Eq ":${POSTGRES_PORT}[[:space:]]"; then
    ok "Host is listening on PostgreSQL port $POSTGRES_PORT"
  else
    warn "Could not verify host listener on port $POSTGRES_PORT"
  fi
  [ "$failed" -eq 0 ] && ok "Database health check passed" || warn "Database health check found issues"
  return "$failed"
}

backup_db(){
  load_env
  db_ready || die "Database is not ready."
  mkdir -p "$DIR/backups"
  local file="$DIR/backups/iris_db_$(date +%Y%m%d_%H%M%S).sql.gz"
  info "Creating backup: $file"
  docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" iriswebapp_db \
    pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB" | gzip >"$file"
  chmod 600 "$file"
  ok "Backup completed: $file"
}

list_backups(){
  mkdir -p "$DIR/backups"
  printf '\nAvailable database backups\n'
  find "$DIR/backups" -maxdepth 1 -type f -name '*.sql.gz' -printf '%TY-%Tm-%Td %TH:%TM  %10s  %f\n' 2>/dev/null | sort -r || true
}

restore_db(){
  load_env
  mkdir -p "$DIR/backups"
  mapfile -t backups < <(find "$DIR/backups" -maxdepth 1 -type f -name '*.sql.gz' -printf '%p\n' | sort -r)
  [ "${#backups[@]}" -gt 0 ] || die "No .sql.gz backups found in $DIR/backups."
  printf '\nSelect backup to restore:\n'
  local i=1 choice
  for f in "${backups[@]}"; do printf '  %d) %s\n' "$i" "$(basename "$f")"; i=$((i+1)); done
  printf '  0) Back\nChoose: '
  IFS= read -r choice || return 1
  [ "$choice" != 0 ] || return 0
  case "$choice" in *[!0-9]*|'') die "Invalid selection.";; esac
  [ "$choice" -le "${#backups[@]}" ] || die "Invalid selection."
  local selected=${backups[$((choice-1))]}
  warn "Restore will replace data in database '$POSTGRES_DB'."
  printf 'Type RESTORE to continue: '
  IFS= read -r confirm
  [ "$confirm" = RESTORE ] || die "Restore cancelled."
  db_ready || die "Database is not ready."
  info "Restoring $(basename "$selected")"
  gunzip -c "$selected" | docker exec -i -e PGPASSWORD="$POSTGRES_PASSWORD" iriswebapp_db \
    psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"
  ok "Restore completed."
}

storage_info(){
  load_env
  printf '\nHost storage\n'
  df -h "$DIR" || true
  printf '\nDocker volume\n'
  local volume
  volume=$(docker volume ls --format '{{.Name}}' | grep -E '^iris-db_.*db_data$|_db_data$' | head -1 || true)
  if [ -n "$volume" ]; then
    docker system df -v 2>/dev/null | grep -A3 -F "$volume" || true
  else
    warn "DB data volume was not found by name."
  fi
  if db_ready; then
    printf '\nDatabase size\n'
    docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" iriswebapp_db psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -P pager=off -c \
      "SELECT pg_size_pretty(pg_database_size(current_database())) AS database_size;"
  fi
}

active_connections(){
  load_env
  db_ready || die "Database is not ready."
  docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" iriswebapp_db psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -P pager=off -c \
    "SELECT pid, usename, COALESCE(client_addr::text,'local') AS client, state, LEFT(query,80) AS query FROM pg_stat_activity WHERE datname=current_database() ORDER BY client, pid;"
}

test_app_connectivity(){
  load_env
  printf '\nApplication connectivity view\n'
  printf 'Configured application host: %s\n' "${APP_SERVER_IP:-<not configured>}"
  printf 'Database endpoint: %s:%s\n' "${POSTGRES_BIND_IP:-0.0.0.0}" "$POSTGRES_PORT"
  db_ready && ok "PostgreSQL is accepting connections" || { warn "PostgreSQL is not ready"; return 1; }
  if [ -n "${APP_SERVER_IP:-}" ]; then
    if have ping && ping -c 1 -W 2 "$APP_SERVER_IP" >/dev/null 2>&1; then
      ok "Application host responds to ping"
    else
      warn "Application host did not respond to ping (ICMP may be blocked)"
    fi
    printf '\nRecent/current PostgreSQL sessions from configured app host\n'
    docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" iriswebapp_db psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -P pager=off -c \
      "SELECT pid, usename, client_addr, state, backend_start FROM pg_stat_activity WHERE client_addr::text='${APP_SERVER_IP}' ORDER BY backend_start DESC;" || true
  fi
  info "Final proof of app-to-DB connectivity should be run from the application server with its setup.sh database test."
}

config_info(){
  load_env
  printf '\n============================================================\n'
  printf 'DFIR-IRIS Database Deployment Information\n'
  printf '============================================================\n'
  printf 'Role:                 Database Server\n'
  printf 'Install directory:    %s\n' "$DIR"
  printf 'IRIS release:         %s\n' "${IRIS_RELEASE:-unknown}"
  printf 'DB image:             %s:%s\n' "${DB_IMAGE_NAME:-}" "${DB_IMAGE_TAG:-}"
  printf 'Bind address:         %s\n' "${POSTGRES_BIND_IP:-}"
  printf 'PostgreSQL port:      %s\n' "${POSTGRES_PORT:-}"
  printf 'Database:             %s\n' "${POSTGRES_DB:-}"
  printf 'Database user:        %s\n' "${POSTGRES_USER:-}"
  printf 'Admin DB user:        %s\n' "${POSTGRES_ADMIN_USER:-}"
  printf 'Application host:     %s\n' "${APP_SERVER_IP:-not configured}"
  printf 'DB password:          <hidden>\n'
  printf 'DB admin password:    <hidden>\n'
}

vacuum_analyze(){
  load_env
  db_ready || die "Database is not ready."
  info "Running VACUUM (ANALYZE) on $POSTGRES_DB"
  docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" iriswebapp_db psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 -c 'VACUUM (ANALYZE);'
  ok "VACUUM ANALYZE completed."
}

maintenance_menu(){
  while :; do
    printf '\nDatabase Maintenance\n'
    printf '  1) Run VACUUM ANALYZE\n'
    printf '  2) Validate Compose configuration\n'
    printf '  3) Show Docker volume information\n'
    printf '  4) Pull configured database image\n'
    printf '  0) Back\nChoose: '
    IFS= read -r c || return 0
    case "$c" in
      1) vacuum_analyze; pause_menu ;;
      2) compose config; pause_menu ;;
      3) docker volume ls; pause_menu ;;
      4) compose pull db; pause_menu ;;
      0) return 0 ;;
      *) warn "Invalid option." ;;
    esac
  done
}

service_menu(){
  while :; do
    printf '\nDatabase Services\n'
    printf '  1) Status\n  2) Start Database\n  3) Stop Database\n  4) Restart Database\n  5) View Logs\n  0) Back\nChoose: '
    IFS= read -r c || return 0
    case "$c" in
      1) status_db; pause_menu;; 2) start_db; pause_menu;; 3) stop_db; pause_menu;; 4) restart_db; pause_menu;; 5) logs_db; pause_menu;; 0) return 0;; *) warn "Invalid option.";; esac
  done
}

backup_menu(){
  while :; do
    printf '\nBackup & Restore\n'
    printf '  1) Backup Database\n  2) List Backups\n  3) Restore Database\n  0) Back\nChoose: '
    IFS= read -r c || return 0
    case "$c" in 1) backup_db; pause_menu;; 2) list_backups; pause_menu;; 3) restore_db; pause_menu;; 0) return 0;; *) warn "Invalid option.";; esac
  done
}

health_menu(){
  while :; do
    printf '\nHealth & Connectivity\n'
    printf '  1) Database Health Check\n  2) Test Application Connectivity\n  0) Back\nChoose: '
    IFS= read -r c || return 0
    case "$c" in 1) health_db || true; pause_menu;; 2) test_app_connectivity || true; pause_menu;; 0) return 0;; *) warn "Invalid option.";; esac
  done
}

storage_menu(){
  while :; do
    printf '\nStorage & Connections\n'
    printf '  1) Storage Information\n  2) Active Database Connections\n  0) Back\nChoose: '
    IFS= read -r c || return 0
    case "$c" in 1) storage_info; pause_menu;; 2) active_connections; pause_menu;; 0) return 0;; *) warn "Invalid option.";; esac
  done
}

config_menu(){
  while :; do
    printf '\nConfiguration & Maintenance\n'
    printf '  1) Configuration Information\n  2) Maintenance Tools\n  0) Back\nChoose: '
    IFS= read -r c || return 0
    case "$c" in 1) config_info; pause_menu;; 2) maintenance_menu;; 0) return 0;; *) warn "Invalid option.";; esac
  done
}

interactive_menu(){
  while :; do
    printf '\n============================================================\n'
    printf '       DFIR-IRIS Database Management\n'
    printf '============================================================\n'
    printf '  1) Database Services\n'
    printf '  2) Backup & Restore\n'
    printf '  3) Health & Connectivity\n'
    printf '  4) Storage & Connections\n'
    printf '  5) Configuration & Maintenance\n'
    printf '  0) Exit\nChoose: '
    IFS= read -r c || exit 0
    case "$c" in 1) service_menu;; 2) backup_menu;; 3) health_menu;; 4) storage_menu;; 5) config_menu;; 0) exit 0;; *) warn "Invalid option.";; esac
  done
}

usage(){
  cat <<USAGE
Usage: ./setup.sh [command]
Commands:
  status | start | stop | restart | logs
  doctor | backup | list-backups | restore
  storage | connections | test-app | info | maintenance
USAGE
}

cmd=${1:-}
case "$cmd" in
  '') interactive_menu ;;
  status) status_db ;;
  start) start_db ;;
  stop) stop_db ;;
  restart) restart_db ;;
  logs) logs_db ;;
  doctor|health) health_db ;;
  backup) backup_db ;;
  list-backups) list_backups ;;
  restore) restore_db ;;
  storage) storage_info ;;
  connections) active_connections ;;
  test-app) test_app_connectivity ;;
  info) config_info ;;
  maintenance) maintenance_menu ;;
  -h|--help|help) usage ;;
  *) usage; exit 2 ;;
esac
