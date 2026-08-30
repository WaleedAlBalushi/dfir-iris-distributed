#!/usr/bin/env bash
set -Eeuo pipefail

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$DIR"

# The following two modules are derived from the previously tested setup.sh.
# They preserve the Wazuh and OpenCTI management capability while the top-level
# menu and platform-management logic are redesigned for the distributed role.
# shellcheck disable=SC1091
. "$DIR/lib/legacy_runtime.sh"
# shellcheck disable=SC1091
. "$DIR/integrations/integration_tools.sh"

# ---------------------------------------------------------------------------
# Distributed application role overrides
# ---------------------------------------------------------------------------
compose() {
  docker compose -p "${COMPOSE_PROJECT_NAME:-iris-app}" -f "$DIR/docker-compose.distributed-app.yml" "$@"
}

pause_menu() {
  printf '\nPress Enter to return to the menu...'
  IFS= read -r _unused || true
}

load_env() {
  [ -f "$DIR/.env" ] || die "Missing $DIR/.env"
  set -a
  # shellcheck disable=SC1091
  . "$DIR/.env"
  set +a
}

wait_for_iris_app() {
  attempts=${1:-60}
  port=${IRIS_UPSTREAM_PORT:-8000}
  i=1
  while [ "$i" -le "$attempts" ]; do
    if docker exec iriswebapp_app python3 - "$port" >/dev/null 2>&1 <<'PY'
import socket, sys
with socket.create_connection(("127.0.0.1", int(sys.argv[1])), 2):
    pass
PY
    then
      return 0
    fi
    i=$((i + 1))
    sleep 2
  done
  return 1
}

ensure_iris_app_ready() {
  context=${1:-IRIS operation}
  load_env
  iris_container_check
  if wait_for_iris_app 50; then
    return 0
  fi
  warn "IRIS app is not ready during: $context"
  info "Attempting application-side recovery without touching the remote database."
  compose up -d rabbitmq app worker nginx >/dev/null 2>&1 || true
  compose restart app worker nginx >/dev/null 2>&1 || true
  wait_for_iris_app 60
}

status_app() { compose ps; }
start_app() { compose up -d; ensure_iris_app_ready "application startup" || return 1; }
stop_app() { compose stop; }
restart_app() { compose restart; ensure_iris_app_ready "application restart" || return 1; }

choose_app_log_service() {
  local service=""
  while :; do
    printf '\nApplication log service\n'
    printf '  1) app\n  2) worker\n  3) nginx\n  4) rabbitmq\n  5) all application services\n  0) Back\nChoose: '
    IFS= read -r choice || return 1
    case "$choice" in
      1|'') service=app; break ;;
      2) service=worker; break ;;
      3) service=nginx; break ;;
      4) service=rabbitmq; break ;;
      5) service=all; break ;;
      0) return 1 ;;
      *) warn "Invalid option." ;;
    esac
  done
  printf '%s\n' "$service"
}

logs_app() {
  local service=${1:-all}
  if [ "$service" = all ]; then
    compose logs --tail=250 app worker nginx rabbitmq
  else
    compose logs --tail=250 "$service"
  fi
}

remote_db_socket_test() {
  load_env
  python3 - "$POSTGRES_SERVER" "$POSTGRES_PORT" <<'PY'
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
with socket.create_connection((host, port), 5):
    pass
PY
}

remote_db_auth_test() {
  load_env
  if docker ps --format '{{.Names}}' | grep -Fxq iriswebapp_app; then
    if docker exec iriswebapp_app python3 - >/dev/null <<'PY'
import os
try:
    import psycopg2
except Exception:
    raise SystemExit(2)
conn = psycopg2.connect(
    host=os.environ['POSTGRES_SERVER'],
    port=int(os.environ.get('POSTGRES_PORT', '5432')),
    dbname=os.environ.get('POSTGRES_DB', 'iris_db'),
    user=os.environ['POSTGRES_USER'],
    password=os.environ['POSTGRES_PASSWORD'],
    connect_timeout=5,
)
with conn.cursor() as cur:
    cur.execute('select 1')
    assert cur.fetchone()[0] == 1
conn.close()
PY
    then
      return 0
    else
      rc=$?
      [ "$rc" -ne 2 ] && return "$rc"
    fi
  fi
  # Fallback to the PostgreSQL client image if the app Python environment
  # does not expose psycopg2 or the app is down.
  docker run --rm \
    -e PGPASSWORD="$POSTGRES_PASSWORD" \
    postgres:12-alpine \
    psql -v ON_ERROR_STOP=1 -h "$POSTGRES_SERVER" -p "$POSTGRES_PORT" \
      -U "$POSTGRES_USER" -d "${POSTGRES_DB:-iris_db}" -Atqc 'select 1' 2>/dev/null | grep -qx 1
}

db_connectivity_test() {
  load_env
  printf '\nRemote database connectivity\n'
  printf 'Target: %s:%s/%s\n' "$POSTGRES_SERVER" "$POSTGRES_PORT" "${POSTGRES_DB:-iris_db}"
  if remote_db_socket_test; then
    info "TCP connectivity passed."
  else
    warn "Cannot reach PostgreSQL TCP endpoint."
    return 1
  fi
  if remote_db_auth_test; then
    info "PostgreSQL authentication and SELECT test passed."
  else
    warn "PostgreSQL authentication test failed."
    return 1
  fi
}

https_health_test() {
  load_env
  python3 - "127.0.0.1" "${INTERFACE_HTTPS_PORT:-443}" <<'PY'
import ssl, sys, urllib.request
host, port = sys.argv[1], int(sys.argv[2])
url = f"https://{host}:{port}/" if port != 443 else f"https://{host}/"
ctx = ssl._create_unverified_context()
with urllib.request.urlopen(url, timeout=8, context=ctx) as r:
    if r.status not in (200, 301, 302, 303, 307, 308):
        raise SystemExit(f"unexpected HTTP status {r.status}")
print(f"HTTPS OK: {url} status={r.status}")
PY
}

doctor() {
  load_env
  local failed=0
  printf '\n============================================================\n'
  printf 'IRIS Application Health Check / Doctor\n'
  printf '============================================================\n'
  docker info >/dev/null 2>&1 && info "Docker daemon reachable" || { warn "Docker daemon unavailable"; failed=1; }
  compose config >/dev/null 2>&1 && info "Compose configuration valid" || { warn "Compose configuration invalid"; failed=1; }
  for c in iriswebapp_rabbitmq iriswebapp_app iriswebapp_worker iriswebapp_nginx; do
    if docker ps --format '{{.Names}}' | grep -Fxq "$c"; then info "$c running"; else warn "$c not running"; failed=1; fi
  done
  if remote_db_socket_test; then info "Remote PostgreSQL port reachable"; else warn "Remote PostgreSQL port unreachable"; failed=1; fi
  if remote_db_auth_test; then info "Remote PostgreSQL authentication passed"; else warn "Remote PostgreSQL authentication failed"; failed=1; fi
  if docker ps --format '{{.Names}}' | grep -Fxq iriswebapp_rabbitmq; then
    docker exec iriswebapp_rabbitmq rabbitmq-diagnostics -q ping >/dev/null 2>&1 && info "RabbitMQ ping passed" || { warn "RabbitMQ ping failed"; failed=1; }
  fi
  if wait_for_iris_app 2; then info "IRIS app port ${IRIS_UPSTREAM_PORT:-8000} responding"; else warn "IRIS app port not responding"; failed=1; fi
  if https_health_test >/tmp/iris_https_health.$$ 2>&1; then
    sed 's/^/[INFO] /' /tmp/iris_https_health.$$
  else
    warn "HTTPS health test failed: $(tail -1 /tmp/iris_https_health.$$ 2>/dev/null || true)"
    failed=1
  fi
  rm -f /tmp/iris_https_health.$$
  [ "$failed" -eq 0 ] && info "Doctor checks passed." || warn "Doctor checks found issues."
  return "$failed"
}

show_app_info() {
  load_env
  printf '\n============================================================\n'
  printf 'DFIR-IRIS Application Deployment Information\n'
  printf '============================================================\n'
  printf 'Role:                 Application Server\n'
  printf 'Install directory:    %s\n' "$DIR"
  printf 'IRIS release:         %s\n' "${IRIS_RELEASE:-unknown}"
  printf 'IRIS URL:             %s\n' "${IRIS_EXTERNAL_URL:-unknown}"
  printf 'Public host:          %s\n' "${PUBLIC_HOST:-unknown}"
  printf 'HTTPS port:           %s\n' "${INTERFACE_HTTPS_PORT:-443}"
  printf 'Database server:      %s\n' "${POSTGRES_SERVER:-unknown}"
  printf 'Database port:        %s\n' "${POSTGRES_PORT:-5432}"
  printf 'Database name:        %s\n' "${POSTGRES_DB:-iris_db}"
  printf 'Database user:        %s\n' "${POSTGRES_USER:-postgres}"
  printf 'Services:             nginx, app, worker, rabbitmq\n'
  printf 'Application network:  %s\n' "${IRIS_FRONTEND_NETWORK:-iris_app_frontend}"
  printf 'Backend network:      %s\n' "${IRIS_BACKEND_NETWORK:-iris_app_backend}"
  printf 'Secrets:              <hidden>\n'
}

certificate_info() {
  load_env
  local cert="$DIR/certificates/web_certificates/${CERT_FILENAME:-}"
  printf '\nTLS / Certificate Information\n'
  printf 'Configured certificate: %s\n' "$cert"
  if [ -f "$cert" ] && command -v openssl >/dev/null 2>&1; then
    openssl x509 -in "$cert" -noout -subject -issuer -serial -dates -fingerprint -sha256 || true
  else
    warn "Configured certificate was not found or openssl is unavailable."
  fi
}

security_check() {
  load_env
  printf '\nBasic Security / Hardening Check\n'
  local failed=0
  mode=$(stat -c '%a' "$DIR/.env" 2>/dev/null || true)
  if [ "$mode" = 600 ] || [ "$mode" = 640 ]; then info ".env permissions: $mode"; else warn ".env permissions are $mode (recommended 600/640)"; failed=1; fi
  [ -n "${IRIS_SECRET_KEY:-}" ] && [ "${IRIS_SECRET_KEY:-}" != 'AVerySuperSecretKey-SoNotThisOne' ] && info "IRIS secret key customized" || { warn "IRIS secret key is weak/default"; failed=1; }
  [ -n "${IRIS_ADM_API_KEY:-}" ] && info "IRIS API key configured" || warn "IRIS admin API key is not set"
  case "${POSTGRES_SERVER:-}" in localhost|127.*|db|'') warn "Database server does not look remote for distributed role: ${POSTGRES_SERVER:-unset}"; failed=1;; *) info "Remote database host configured";; esac
  docker ps --format '{{.Names}} {{.Ports}}' | grep -E '^iriswebapp_(app|worker|rabbitmq) ' | grep -Eq '0\.0\.0\.0|\[::\]' && { warn "An internal application service appears host-published"; failed=1; } || info "Internal app/worker/RabbitMQ services are not host-published"
  info "Deep OS/Docker/TLS hardening is intentionally outside version 1."
  return "$failed"
}

backup_app_data() {
  load_env
  local root="$DIR/backups/app_$(date +%Y%m%d_%H%M%S)"
  mkdir -p "$root"
  info "Backing up application configuration to $root"
  tar -C "$DIR" -czf "$root/configuration.tar.gz" \
    .env docker-compose.distributed-app.yml certificates integrations lib setup.sh 2>/dev/null || true
  chmod 600 "$root/configuration.tar.gz"
  for suffix in iris-downloads user_templates server_data; do
    volume="${COMPOSE_PROJECT_NAME:-iris-app}_${suffix}"
    if docker volume inspect "$volume" >/dev/null 2>&1; then
      info "Backing up volume: $volume"
      docker run --rm -v "$volume:/data:ro" -v "$root:/backup" alpine:3.20 \
        sh -c "cd /data && tar czf /backup/${suffix}.tar.gz ." >/dev/null
      chmod 600 "$root/${suffix}.tar.gz"
    fi
  done
  info "Application backup completed: $root"
}

sanitized_env() {
  sed -E 's/^([^#=]*(PASSWORD|TOKEN|API_KEY|SECRET|SALT|KEY)[^=]*)=.*/\1=<redacted>/I' "$DIR/.env"
}

support_bundle() {
  load_env
  local root="$DIR/backups/support-$(date +%Y%m%d_%H%M%S)"
  mkdir -p "$root"
  compose ps >"$root/compose-ps.txt" 2>&1 || true
  compose config >"$root/compose-config.txt" 2>&1 || true
  compose logs --tail=400 app worker nginx rabbitmq >"$root/application-logs.txt" 2>&1 || true
  sanitized_env >"$root/env.sanitized"
  docker network inspect "${IRIS_FRONTEND_NETWORK:-iris_app_frontend}" >"$root/frontend-network.json" 2>&1 || true
  docker network inspect "${IRIS_BACKEND_NETWORK:-iris_app_backend}" >"$root/backend-network.json" 2>&1 || true
  doctor >"$root/doctor.txt" 2>&1 || true
  if [ -d /var/log/opencti-iris-bridge ]; then
    tail -n 300 /var/log/opencti-iris-bridge/bridge.log >"$root/opencti-bridge.log.tail" 2>/dev/null || true
  fi
  local tarball="${root}.tar.gz"
  tar -C "$(dirname "$root")" -czf "$tarball" "$(basename "$root")"
  chmod 600 "$tarball"
  info "Support bundle: $tarball"
}

maintenance_menu() {
  while :; do
    printf '\nApplication Maintenance Tools\n'
    printf '  1) Validate Compose configuration\n'
    printf '  2) Pull current configured images\n'
    printf '  3) Restart App only\n'
    printf '  4) Restart Worker only\n'
    printf '  5) Restart Nginx only\n'
    printf '  6) Restart RabbitMQ only\n'
    printf '  0) Back\nChoose: '
    IFS= read -r c || return 0
    case "$c" in
      1) compose config; pause_menu ;;
      2) compose pull; pause_menu ;;
      3) compose restart app; pause_menu ;;
      4) compose restart worker; pause_menu ;;
      5) compose restart nginx; pause_menu ;;
      6) compose restart rabbitmq; pause_menu ;;
      0) return 0 ;;
      *) warn "Invalid option." ;;
    esac
  done
}

upgrade_readiness() {
  load_env
  printf '\nUpgrade Readiness Check\n'
  doctor || true
  printf '\nCurrent configured release: %s\n' "${IRIS_RELEASE:-unknown}"
  printf 'App image tag:              %s\n' "${APP_IMAGE_TAG:-unknown}"
  printf 'Nginx image tag:            %s\n' "${NGINX_IMAGE_TAG:-unknown}"
  printf '\nVersion 1 does not automatically change IRIS versions because official DB/schema upgrade requirements must be reviewed first.\n'
}

integration_tests_menu() {
  while :; do
    printf '\nIntegration Tests\n'
    printf '  1) Test IRIS HTTPS\n'
    printf '  2) Test Remote Database\n'
    printf '  3) Send Wazuh manual test alert\n'
    printf '  4) Test OpenCTI bridge/API (if configured)\n'
    printf '  0) Back\nChoose: '
    IFS= read -r c || return 0
    case "$c" in
      1) https_health_test || true; pause_menu ;;
      2) db_connectivity_test || true; pause_menu ;;
      3) send_wazuh_test_alert || true; pause_menu ;;
      4) opencti_bridge_preflight || true; pause_menu ;;
      0) return 0 ;;
      *) warn "Invalid option." ;;
    esac
  done
}

services_menu() {
  while :; do
    printf '\nIRIS Services\n'
    printf '  1) Status\n  2) Start IRIS\n  3) Stop IRIS\n  4) Restart IRIS\n  5) View Logs\n  0) Back\nChoose: '
    IFS= read -r c || return 0
    case "$c" in
      1) status_app; pause_menu ;;
      2) start_app || true; pause_menu ;;
      3) stop_app; pause_menu ;;
      4) restart_app || true; pause_menu ;;
      5) svc=$(choose_app_log_service || true); [ -n "${svc:-}" ] && logs_app "$svc"; pause_menu ;;
      0) return 0 ;;
      *) warn "Invalid option." ;;
    esac
  done
}

integrations_menu() {
  while :; do
    printf '\nIntegrations\n'
    printf '  1) Wazuh Integration\n'
    printf '  2) OpenCTI Integration\n'
    printf '  3) Integration Tests\n'
    printf '  0) Back\nChoose: '
    IFS= read -r c || return 0
    case "$c" in
      1) wazuh_menu ;;
      2) opencti_menu ;;
      3) integration_tests_menu ;;
      0) return 0 ;;
      *) warn "Invalid option." ;;
    esac
  done
}

health_diagnostics_menu() {
  while :; do
    printf '\nHealth & Diagnostics\n'
    printf '  1) Full Health Check / Doctor\n'
    printf '  2) Database Connectivity Test\n'
    printf '  3) Application Logs\n'
    printf '  4) Generate Support Bundle\n'
    printf '  0) Back\nChoose: '
    IFS= read -r c || return 0
    case "$c" in
      1) doctor || true; pause_menu ;;
      2) db_connectivity_test || true; pause_menu ;;
      3) logs_app all; pause_menu ;;
      4) support_bundle; pause_menu ;;
      0) return 0 ;;
      *) warn "Invalid option." ;;
    esac
  done
}

config_security_menu() {
  while :; do
    printf '\nConfiguration & Security\n'
    printf '  1) IRIS Configuration Information\n'
    printf '  2) Deployment Information\n'
    printf '  3) Certificates / TLS\n'
    printf '  4) Basic Security / Hardening Check\n'
    printf '  0) Back\nChoose: '
    IFS= read -r c || return 0
    case "$c" in
      1|2) show_app_info; pause_menu ;;
      3) certificate_info; pause_menu ;;
      4) security_check || true; pause_menu ;;
      0) return 0 ;;
      *) warn "Invalid option." ;;
    esac
  done
}

backup_maintenance_menu() {
  while :; do
    printf '\nBackup & Maintenance\n'
    printf '  1) Backup Application Data\n'
    printf '  2) Maintenance Tools\n'
    printf '  0) Back\nChoose: '
    IFS= read -r c || return 0
    case "$c" in
      1) backup_app_data; pause_menu ;;
      2) maintenance_menu ;;
      0) return 0 ;;
      *) warn "Invalid option." ;;
    esac
  done
}

upgrade_menu() {
  while :; do
    printf '\nUpgrade Tools\n'
    printf '  1) Upgrade Readiness Check\n'
    printf '  2) Pull Current Configured Images\n'
    printf '  0) Back\nChoose: '
    IFS= read -r c || return 0
    case "$c" in
      1) upgrade_readiness; pause_menu ;;
      2) compose pull; pause_menu ;;
      0) return 0 ;;
      *) warn "Invalid option." ;;
    esac
  done
}

interactive_menu() {
  while :; do
    printf '\n============================================================\n'
    printf '       DFIR-IRIS Application Management\n'
    printf '============================================================\n'
    printf '  1) IRIS Services\n'
    printf '  2) Integrations\n'
    printf '  3) Health & Diagnostics\n'
    printf '  4) Configuration & Security\n'
    printf '  5) Backup & Maintenance\n'
    printf '  6) Upgrade Tools\n'
    printf '  0) Exit\nChoose: '
    IFS= read -r c || exit 0
    case "$c" in
      1) services_menu ;;
      2) integrations_menu ;;
      3) health_diagnostics_menu ;;
      4) config_security_menu ;;
      5) backup_maintenance_menu ;;
      6) upgrade_menu ;;
      0) exit 0 ;;
      *) warn "Invalid option." ;;
    esac
  done
}

usage() {
  cat <<USAGE
Usage: ./setup.sh [command]

Application commands:
  status | start | stop | restart | logs [service]
  doctor | db-test | info | tls-info | security-check
  backup-app | support-bundle | maintenance | upgrade-check

Integration commands retained from the previous setup implementation:
  wazuh | wazuh-topology | wazuh-bundle | wazuh-local | wazuh-local-rollback
  wazuh-markdown | wazuh-rollback | wazuh-test | wazuh-selection-self-test
  opencti | opencti-full-setup | opencti-configure | opencti-preflight
  opencti-install | opencti-test | opencti-test-iris | opencti-test-opencti
  opencti-dry-run | opencti-live-write | opencti-enable-timer | opencti-disable-timer
  opencti-install-module | opencti-rollback-module | opencti-status
  opencti-capabilities | opencti-state-check | opencti-state-migrate
  opencti-rotate-logs | opencti-support-bundle | opencti-uninstall
USAGE
}

cmd=${1:-}
case "$cmd" in
  '') interactive_menu ;;
  status) status_app ;;
  start|install) start_app ;;
  stop) stop_app ;;
  restart) restart_app ;;
  logs) shift || true; logs_app "${1:-all}" ;;
  doctor|health) doctor ;;
  db-test|database-test) db_connectivity_test ;;
  info) show_app_info ;;
  tls-info) certificate_info ;;
  security-check) security_check ;;
  backup-app) backup_app_data ;;
  support-bundle) support_bundle ;;
  maintenance) maintenance_menu ;;
  upgrade-check) upgrade_readiness ;;
  wazuh|integrate-wazuh|wazuh-iris) wazuh_menu ;;
  wazuh-topology|detect-wazuh-topology) detect_wazuh_topology ;;
  wazuh-bundle|wazuh-remote-bundle) generate_wazuh_remote_bundle ;;
  wazuh-local|wazuh-container) install_wazuh_local_container || exit $? ;;
  wazuh-local-rollback|rollback-wazuh-local) rollback_wazuh_local_container || exit $? ;;
  wazuh-selection-self-test|wazuh-selector-test) wazuh_selection_self_test ;;
  wazuh-markdown|markdown-ui) apply_wazuh_markdown_patch ;;
  wazuh-rollback|rollback-wazuh-markdown) rollback_wazuh_markdown_patch ;;
  wazuh-test|test-wazuh-alert) send_wazuh_test_alert || exit $? ;;
  opencti|opencti-menu) opencti_menu ;;
  opencti-full-setup|opencti-auto-setup|opencti-deploy) shift || true; opencti_configure_full_setup "$@" ;;
  opencti-configure) shift || true; opencti_configure_bridge "$@" ;;
  opencti-preflight) opencti_bridge_preflight ;;
  opencti-install|opencti-install-service) opencti_install_bridge_service ;;
  opencti-test) opencti_bridge_preflight ;;
  opencti-test-iris) opencti_test_iris_api ;;
  opencti-test-opencti) opencti_test_opencti_api ;;
  opencti-dry-run) opencti_run_dry_once ;;
  opencti-live-write|opencti-live-write-once) opencti_run_live_once ;;
  opencti-enable-timer) opencti_enable_timer ;;
  opencti-disable-timer) opencti_disable_timer ;;
  opencti-install-module) opencti_install_iris_module ;;
  opencti-rollback-module) opencti_rollback_iris_module ;;
  opencti-status) opencti_status ;;
  opencti-capabilities|opencti-show-capabilities) opencti_show_capabilities ;;
  opencti-state-check) opencti_state_check ;;
  opencti-state-migrate) opencti_state_migrate ;;
  opencti-rotate-logs|opencti-clear-logs) opencti_rotate_logs ;;
  opencti-support-bundle) opencti_support_bundle ;;
  opencti-uninstall) opencti_uninstall_service_only ;;
  -h|--help|help) usage ;;
  *) usage; exit 2 ;;
esac
