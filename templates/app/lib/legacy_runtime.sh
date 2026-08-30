#!/usr/bin/env bash
set -Eeuo pipefail

IFS='
	'

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$DIR"

info() { printf '[INFO] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

on_error() {
  rc=$?
  line=${BASH_LINENO[0]:-${LINENO}}
  printf '\n[ERROR] setup.sh failed at line %s with exit code %s.\n' "$line" "$rc" >&2
  exit "$rc"
}
trap on_error ERR

prompt_yes_no() {
  prompt=$1
  answer=""
  while :; do
    printf '\n%s\n' "$prompt"
    printf '  1) Yes\n'
    printf '  2) No\n'
    printf 'Choose 1 or 2: '
    IFS= read -r answer || die "Input stream closed."
    case "$answer" in
      1|y|Y|yes|YES|Yes) return 0 ;;
      2|n|N|no|NO|No) return 1 ;;
      *) warn "Please choose 1 for yes or 2 for no." ;;
    esac
  done
}

prompt_default() {
  label=$1
  default_value=$2
  value=""
  printf '\n%s\n' "$label" >&2
  printf 'Default: %s\n' "$default_value" >&2
  printf 'Press Enter to use the default, or type a value: ' >&2
  IFS= read -r value || die "Input stream closed."
  if [ -z "$value" ]; then
    value=$default_value
  fi
  printf '%s\n' "$value"
}

load_env() {
  [ -f "$DIR/.env" ] || die "Missing $DIR/.env"
  set -a
  # shellcheck disable=SC1091
  . "$DIR/.env"
  set +a
}

compose() {
  if docker compose version >/dev/null 2>&1; then
    docker compose -f docker-compose.yml -f docker-compose.installer.yml "$@"
  elif have docker-compose; then
    docker-compose -f docker-compose.yml -f docker-compose.installer.yml "$@"
  else
    die "Docker Compose is not available."
  fi
}

ensure_external_network() {
  load_env
  if [ "${USE_SHARED_NETWORK:-no}" = "yes" ]; then
    if docker network inspect "$SHARED_NETWORK" >/dev/null 2>&1; then
      info "External network already exists: $SHARED_NETWORK"
    else
      info "Creating external network: $SHARED_NETWORK"
      docker network create "$SHARED_NETWORK" >/dev/null
    fi
  fi
}

wait_for_iris() {
  i=1
  info "Waiting for the IRIS nginx container to accept commands."
  while [ "$i" -le 90 ]; do
    if docker exec iriswebapp_nginx sh -lc 'true' >/dev/null 2>&1; then
      info "IRIS nginx container is running."
      return 0
    fi
    printf '  waiting... (%s/90)\n' "$i"
    i=$((i + 1))
    sleep 5
  done
  warn "IRIS did not become ready in time. Use './setup.sh logs app' and './setup.sh logs nginx'."
  return 1
}

wait_for_iris_app() {
  attempts=${1:-60}
  port=${IRIS_UPSTREAM_PORT:-8000}
  i=1
  info "Waiting for the IRIS app container to accept local connections."
  while [ "$i" -le "$attempts" ]; do
    if docker exec iriswebapp_app python3 - "$port" >/dev/null 2>&1 <<'PYCHECK'
import socket
import sys

port = int(sys.argv[1])
with socket.create_connection(("127.0.0.1", port), 2):
    pass
PYCHECK
    then
      info "IRIS app container is accepting connections."
      return 0
    fi
    printf '  waiting for app... (%s/%s)\n' "$i" "$attempts"
    i=$((i + 1))
    sleep 3
  done
  warn "IRIS app did not become reachable on port $port in time."
  return 1
}

collect_iris_diagnostics() {
  diag_path=$1
  mkdir -p "$(dirname "$diag_path")"
  {
    printf 'IRIS diagnostics collected at %s\n\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '== docker ps ==\n'
    docker ps -a --filter 'name=iriswebapp' --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' || true
    printf '\n== compose ps ==\n'
    compose ps || true
    printf '\n== app container state ==\n'
    docker inspect -f 'status={{.State.Status}} running={{.State.Running}} restarting={{.State.Restarting}} oom_killed={{.State.OOMKilled}} exit_code={{.State.ExitCode}} error={{.State.Error}} started={{.State.StartedAt}} finished={{.State.FinishedAt}}' iriswebapp_app || true
    printf '\n== app selected environment ==\n'
    docker exec iriswebapp_app sh -lc 'env | grep -E "^(DOCKERIZED|IRIS_UPSTREAM|POSTGRES_SERVER|POSTGRES_PORT|POSTGRES_DB|CELERY_BROKER|IRIS_AUTHENTICATION_TYPE)=" | sed "s/=.*/=<set>/"' || true
    printf '\n== app process check ==\n'
    docker exec iriswebapp_app sh -lc 'ps -ef | sed -n "1,40p"' || true
    printf '\n== app listening sockets ==\n'
    docker exec iriswebapp_app sh -lc '(ss -ltnp || netstat -ltnp || true) 2>/dev/null' || true
    printf '\n== app port check ==\n'
    docker exec iriswebapp_app python3 - "${IRIS_UPSTREAM_PORT:-8000}" <<'PYCHECK' || true
import socket
import sys

port = int(sys.argv[1])
s = socket.socket()
s.settimeout(2)
rc = s.connect_ex(("127.0.0.1", port))
print(f"app_port_{port}_connect_rc={rc}")
s.close()
PYCHECK
    printf '\n== nginx recent logs ==\n'
    docker logs --tail=120 iriswebapp_nginx || true
    printf '\n== app recent logs ==\n'
    docker logs --tail=160 iriswebapp_app || true
  } >"$diag_path" 2>&1 || true
}

print_iris_diagnostic_excerpt() {
  diag_path=$1
  [ -f "$diag_path" ] || return 0
  warn "Recent IRIS diagnostics excerpt:"
  tail -n 90 "$diag_path" | sed 's/^/  /' >&2 || true
}

ensure_iris_app_ready() {
  context=${1:-IRIS operation}
  load_env
  iris_container_check
  if wait_for_iris_app 60; then
    return 0
  fi

  diag_path="$DIR/integrations/wazuh/iris-app-not-ready-$(date +%Y%m%d_%H%M%S).log"
  collect_iris_diagnostics "$diag_path"
  warn "IRIS app is not accepting connections during: $context"
  warn "Diagnostics saved: $diag_path"

  info "Attempting IRIS app recovery."
  compose up -d db rabbitmq app nginx >/dev/null 2>&1 || true
  compose restart app nginx >/dev/null 2>&1 || docker restart iriswebapp_app iriswebapp_nginx >/dev/null 2>&1 || true
  wait_for_iris || true
  if wait_for_iris_app 80; then
    info "IRIS app recovered successfully."
    return 0
  fi

  diag_path="$DIR/integrations/wazuh/iris-app-still-not-ready-$(date +%Y%m%d_%H%M%S).log"
  collect_iris_diagnostics "$diag_path"
  warn "IRIS app is still not accepting connections after recovery."
  warn "Diagnostics saved: $diag_path"
  print_iris_diagnostic_excerpt "$diag_path"
  return 1
}

iris_gateway_failure_seen() {
  log_path=$1
  [ -f "$log_path" ] || return 1
  grep -Eq 'IRIS HTTP error status=(502|503|504)|Bad Gateway|upstream|currently unavailable' "$log_path"
}

repair_iris_gateway_if_needed() {
  log_path=$1
  iris_gateway_failure_seen "$log_path" || return 1
  diag_path="$DIR/integrations/wazuh/iris-gateway-diagnostics-$(date +%Y%m%d_%H%M%S).log"
  warn "IRIS nginx returned a gateway error. Collecting IRIS diagnostics and attempting recovery."
  collect_iris_diagnostics "$diag_path"
  warn "IRIS diagnostics saved: $diag_path"
  ensure_iris_app_ready "gateway recovery" || true
  return 0
}

save_credentials() {
  load_env
  mkdir -p "$DIR/secrets"
  {
    printf 'DFIR-IRIS deployment credentials\n\n'
    printf 'IRIS URL: %s\n' "${IRIS_EXTERNAL_URL:-}"
    printf 'Username: %s\n' "${IRIS_ADM_USERNAME:-}"
    printf 'Password: %s\n' "${IRIS_ADM_PASSWORD:-}"
    printf 'API key: %s\n' "${IRIS_ADM_API_KEY:-}"
    printf 'Install directory: %s\n' "$DIR"
    printf 'Generated/updated: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } > "$DIR/secrets/initial-credentials.txt"
  chmod 600 "$DIR/secrets/initial-credentials.txt"
}

iris_db_container_exists() {
  docker ps -a --format '{{.Names}}' | grep -Fxq 'iriswebapp_db'
}

iris_db_state_present_setup() {
  project=${COMPOSE_PROJECT_NAME:-iriswebapp}
  if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -Fxq "${project}_db"; then
    return 0
  fi
  if docker ps -a \
    --filter "label=com.docker.compose.project=${project}" \
    --filter "label=com.docker.compose.service=db" \
    --format '{{.ID}}' 2>/dev/null | grep -q .; then
    return 0
  fi
  if docker volume ls \
    --filter "label=com.docker.compose.project=${project}" \
    --format '{{.Name}}' 2>/dev/null | grep -Eiq '(db|postgres|pgdata|data)'; then
    return 0
  fi
  if docker volume ls --format '{{.Name}}' 2>/dev/null | grep -Eiq "^${project}.*(db|postgres|pgdata|data)"; then
    return 0
  fi
  return 1
}

wait_for_iris_db() {
  i=1
  while [ "$i" -le 45 ]; do
    if docker exec iriswebapp_db sh -lc 'pg_isready -U "$1" -d "$2" >/dev/null 2>&1' sh "${POSTGRES_USER:-postgres}" "${POSTGRES_DB:-iriswebapp}" >/dev/null 2>&1; then
      return 0
    fi
    printf '  waiting for db... (%s/45)\n' "$i"
    i=$((i + 1))
    sleep 2
  done
  return 1
}

iris_db_password_authenticates() {
  candidate_password=$1
  docker exec -i iriswebapp_db sh -lc '
    export PGPASSWORD="$1"
    psql -v ON_ERROR_STOP=1 -U "$2" -d "$3" -c "select 1" >/dev/null
  ' sh "$candidate_password" "${POSTGRES_USER:-postgres}" "${POSTGRES_DB:-iriswebapp}" >/dev/null 2>&1
}

update_setup_env_value() {
  key=$1
  value=$2
  python3 - "$DIR/.env" "$key" "$value" <<'PYENVUPDATE'
from pathlib import Path
import sys

path = Path(sys.argv[1])
key = sys.argv[2]
value = sys.argv[3]
lines = path.read_text().splitlines()
out = []
changed = False
for line in lines:
    if line.startswith(key + "="):
        out.append(f"{key}={value}")
        changed = True
    else:
        out.append(line)
if not changed:
    out.append(f"{key}={value}")
path.write_text("\n".join(out) + "\n")
PYENVUPDATE
  chmod 600 "$DIR/.env"
}

prompt_secret_value() {
  label=$1
  value=""
  printf '\n%s: ' "$label" >&2
  if [ -t 0 ]; then
    stty -echo
    IFS= read -r value || { stty echo; die "Input stream closed."; }
    stty echo
    printf '\n' >&2
  else
    IFS= read -r value || die "Input stream closed."
  fi
  printf '%s\n' "$value"
}

guard_setup_db_credentials() {
  load_env
  if ! iris_db_state_present_setup; then
    return 0
  fi

  info "Existing IRIS database state detected. Validating .env database credentials before starting the app."
  compose up -d db >/dev/null
  wait_for_iris_db || {
    warn "IRIS database container did not become ready for credential validation."
    warn "Not starting the app/nginx stack until the database is healthy."
    return 1
  }

  if iris_db_password_authenticates "${POSTGRES_PASSWORD:-}"; then
    info "Current .env PostgreSQL credentials authenticate successfully."
    return 0
  fi

  warn "The current .env POSTGRES_PASSWORD does not authenticate to the existing IRIS PostgreSQL data volume."
  warn "Starting IRIS now would make the app worker fail to boot and nginx would return 502."
  printf '\nIRIS database credential recovery\n'
  printf '  1) Abort so I can recover the old .env/password safely\n'
  printf '  2) I know the existing PostgreSQL password; update .env to match it\n'
  printf '  3) Fresh IRIS only: delete IRIS containers and volumes, losing IRIS DB data\n'
  printf 'Choose 1, 2, or 3: '
  IFS= read -r db_choice || die "Input stream closed."
  case "$db_choice" in
    2)
      old_password=$(prompt_secret_value "Existing PostgreSQL password for user ${POSTGRES_USER:-postgres}")
      if iris_db_password_authenticates "$old_password"; then
        update_setup_env_value POSTGRES_PASSWORD "$old_password"
        if [ "${POSTGRES_ADMIN_USER:-}" = "${POSTGRES_USER:-}" ]; then
          update_setup_env_value POSTGRES_ADMIN_PASSWORD "$old_password"
        fi
        info "Updated $DIR/.env with the verified existing PostgreSQL password."
        load_env
        return 0
      fi
      die "The password entered did not authenticate to the existing IRIS database."
      ;;
    3)
      warn "DESTRUCTIVE ACTION: this deletes IRIS Docker volumes for this compose project."
      printf 'To confirm fresh IRIS data loss, type DELETE_IRIS_DB exactly: '
      IFS= read -r confirm_delete || die "Input stream closed."
      [ "$confirm_delete" = "DELETE_IRIS_DB" ] || die "Cancelled to protect the existing IRIS database."
      compose down -v
      info "Existing IRIS containers and volumes removed. A fresh database will be initialized."
      return 0
      ;;
    *)
      die "Cancelled to protect the existing IRIS database volume."
      ;;
  esac
}

install_iris() {
  load_env
  ensure_external_network
  info "Pulling IRIS container images."
  compose pull
  guard_setup_db_credentials
  info "Starting IRIS."
  compose up -d
  wait_for_iris || true
  ensure_iris_app_ready "IRIS startup" || return 1
  save_credentials
  show_info
}

stop_iris() {
  compose stop
}

restart_iris() {
  compose restart
  wait_for_iris || true
  ensure_iris_app_ready "IRIS restart" || return 1
}

status_iris() {
  compose ps
}

logs_iris() {
  service=${1:-app}
  compose logs --tail=200 "$service"
}

backup_db() {
  load_env
  mkdir -p "$DIR/backups"
  file="$DIR/backups/iris_db_$(date +%Y%m%d%H%M%S).sql.gz"
  info "Writing database backup: $file"
  compose exec -T db pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB" | gzip > "$file"
  chmod 600 "$file"
}

doctor() {
  failed=0
  load_env
  have docker || { warn "docker command missing."; failed=1; }
  compose version >/dev/null 2>&1 || { warn "docker compose command failed."; failed=1; }
  [ -f "$DIR/docker-compose.yml" ] || { warn "docker-compose.yml missing."; failed=1; }
  [ -f "$DIR/docker-compose.base.yml" ] || { warn "docker-compose.base.yml missing."; failed=1; }
  [ -f "$DIR/docker-compose.installer.yml" ] || { warn "docker-compose.installer.yml missing."; failed=1; }
  [ -f "$DIR/.env" ] || { warn ".env missing."; failed=1; }
  docker info >/dev/null 2>&1 || { warn "Docker daemon is not reachable."; failed=1; }
  compose config >/dev/null || { warn "Compose configuration failed validation."; failed=1; }
  if [ "$failed" -eq 0 ]; then
    info "Doctor checks passed."
  else
    warn "Doctor checks found issues."
  fi
  return "$failed"
}

show_info() {
  load_env
  printf '\nDFIR-IRIS deployment\n'
  printf 'URL:              %s\n' "${IRIS_EXTERNAL_URL:-}"
  printf 'Install dir:      %s\n' "$DIR"
  printf 'Release:          %s\n' "${IRIS_RELEASE:-}"
  printf 'Image tag:        %s\n' "${IRIS_IMAGE_TAG:-}"
  printf 'Credentials file: %s\n' "$DIR/secrets/initial-credentials.txt"
}

uninstall_iris() {
  warn "This stops and removes IRIS containers only. Docker volumes are kept."
  if prompt_yes_no "Continue with container removal?"; then
    compose down
  else
    die "Cancelled."
  fi
}

factory_reset() {
  warn "This removes IRIS containers and Docker volumes for this compose project."
  warn "Database data will be deleted."
  if prompt_yes_no "Continue with factory reset?"; then
    compose down -v
  else
    die "Cancelled."
  fi
}

iris_container_check() {
  docker ps --format '{{.Names}}' | grep -qx 'iriswebapp_app' || die "iriswebapp_app is not running. Start IRIS first."
  docker ps --format '{{.Names}}' | grep -qx 'iriswebapp_nginx' || die "iriswebapp_nginx is not running. Start IRIS first."
}

