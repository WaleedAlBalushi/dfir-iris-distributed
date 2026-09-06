#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

BASE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck disable=SC1091
. "$BASE_DIR/lib/common.sh"

DEFAULT_IRIS_VERSION="v2.4.29"
REPO_URL="https://github.com/dfir-iris/iris-web.git"

SOC_VERSION_FILE="$BASE_DIR/soc/VERSION"
SOC_BASE_FILE="$BASE_DIR/soc/BASE_COMMIT"
SOC_PATCH_DIR="$BASE_DIR/soc/patches"
SOC_IMAGE_NAME="iris-soc"

banner() {
  printf '\n============================================================\n'
  printf '        DFIR-IRIS Distributed Installer v1.1\n'
  printf '============================================================\n'
}

preflight() {
  require_root
  printf '\nChecking system...\n\n'
  [ "$(uname -s)" = Linux ] && ok "Linux detected" || die "Linux is required."
  ok "Running as root"
  ensure_basic_tools
  ok "Docker available"
  ok "Docker Compose available"
  have openssl && ok "OpenSSL available" || warn "OpenSSL not found; Python fallback will generate secrets."
}

validate_env_value() {
  local label=$1 value=$2
  case "$value" in
    *$'\n'*|*"'"*) die "$label cannot contain a newline or a single quote in installer v1." ;;
  esac
}

env_line() {
  local key=$1 value=$2
  validate_env_value "$key" "$value"
  printf "%s='%s'\n" "$key" "$value"
}

soc_release() {
  [ -f "$SOC_VERSION_FILE" ] || die "SOC VERSION file missing: $SOC_VERSION_FILE"
  tr -d '[:space:]' <"$SOC_VERSION_FILE"
}

soc_base_commit() {
  [ -f "$SOC_BASE_FILE" ] || die "SOC BASE_COMMIT file missing: $SOC_BASE_FILE"
  tr -d '[:space:]' <"$SOC_BASE_FILE"
}

prepare_soc_source() {
  local source_dir=$1
  local expected_base actual_base patch
  local patches=()

  expected_base=$(soc_base_commit)
  actual_base=$(git -C "$source_dir" rev-parse HEAD)

  [ "$actual_base" = "$expected_base" ] || \
    die "IRIS base mismatch. Expected $expected_base but cloned $actual_base"

  shopt -s nullglob
  patches=("$SOC_PATCH_DIR"/*.patch)
  shopt -u nullglob

  [ "${#patches[@]}" -gt 0 ] || \
    die "No SOC patches found in $SOC_PATCH_DIR"

  for patch in "${patches[@]}"; do
    info "Checking SOC patch: $(basename "$patch")"
    git -C "$source_dir" apply --check "$patch" || \
      die "SOC patch validation failed: $(basename "$patch")"

    info "Applying SOC patch: $(basename "$patch")"
    git -C "$source_dir" apply "$patch"
  done

  mkdir -p "$source_dir/.soc-build/patches"

  cp "$SOC_VERSION_FILE" "$source_dir/.soc-build/VERSION"
  cp "$SOC_BASE_FILE" "$source_dir/.soc-build/BASE_COMMIT"
  cp "$SOC_PATCH_DIR"/*.patch "$source_dir/.soc-build/patches/"

  printf '%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    >"$source_dir/.soc-build/BUILD_TIME"

  ok "SOC source prepared: $(soc_release)"
}

build_soc_app_image() {
  local source_dir=$1
  local release image

  release=$(soc_release)
  image="${SOC_IMAGE_NAME}:${release}"

  info "Building customized IRIS SOC image: $image"

  docker build \
    --label "org.opencontainers.image.title=DFIR-IRIS SOC" \
    --label "org.opencontainers.image.version=$release" \
    --label "org.opencontainers.image.revision=$(soc_base_commit)" \
    -t "$image" \
    -f "$source_dir/docker/webApp/Dockerfile" \
    "$source_dir"

  docker image inspect "$image" --format '{{.Id}}' \
    >"$source_dir/.soc-build/IMAGE_ID"

  ok "SOC image built successfully: $image"
}

prepare_target_dir() {
  local target=$1
  if [ ! -e "$target" ] || [ -z "$(ls -A "$target" 2>/dev/null || true)" ]; then
    mkdir -p "$target"
    return 0
  fi
  printf '\nTarget directory already exists and is not empty:\n  %s\n' "$target"
  printf '  1) Back up existing directory and continue\n'
  printf '  2) Choose another directory\n'
  printf '  3) Cancel\nChoose: '
  local c backup
  IFS= read -r c || die "Input stream closed."
  case "$c" in
    1)
      backup="${target}.backup-$(date +%Y%m%d_%H%M%S)"
      mv "$target" "$backup"
      mkdir -p "$target"
      info "Existing directory moved to $backup"
      ;;
    2) return 2 ;;
    *) return 1 ;;
  esac
}

postgres_auth_test() {
  local host=$1 port=$2 db=$3 user=$4 password=$5
  docker run --rm -e PGPASSWORD="$password" postgres:12-alpine \
    psql -v ON_ERROR_STOP=1 -h "$host" -p "$port" -U "$user" -d "$db" -Atqc 'select 1' 2>/dev/null | grep -qx 1
}

install_database_role() {
  banner
  printf 'Role selected: Database Server\n'

  local version install_dir bind_ip port db_name db_user db_pass db_admin_user db_admin_pass app_ip
  local detected_ip
  detected_ip=$(primary_ipv4 || true)
  [ -n "$detected_ip" ] || detected_ip="0.0.0.0"

  version=$(prompt_default "IRIS database image version" "$DEFAULT_IRIS_VERSION")
  while :; do
    install_dir=$(prompt_default "Database install directory" "/opt/iris-db")
    if prepare_target_dir "$install_dir"; then break; else rc=$?; [ "$rc" -eq 2 ] && continue; return 0; fi
  done

  bind_ip=$(prompt_default "Database bind IP (use the internal DB-server IP when possible)" "$detected_ip")
  while :; do
    port=$(prompt_default "PostgreSQL host port" "5432")
    validate_port "$port" && break
    warn "Port must be between 1 and 65535."
  done
  db_name=$(prompt_default "PostgreSQL database name" "iris_db")
  db_user=$(prompt_default "PostgreSQL application user" "postgres")
  db_pass=$(prompt_secret "PostgreSQL application password (Enter = generate)")
  [ -n "$db_pass" ] || db_pass=$(random_hex 24)
  db_admin_user=$(prompt_default "PostgreSQL admin user" "raptor")
  db_admin_pass=$(prompt_secret "PostgreSQL admin password (Enter = generate)")
  [ -n "$db_admin_pass" ] || db_admin_pass=$(random_hex 24)
  app_ip=$(prompt_optional "IRIS Application Server IP (recommended; used for documentation/connectivity checks)")

  printf '\n============================================================\n'
  printf 'Database Server Deployment Summary\n'
  printf '============================================================\n'
  printf 'Role:              Database Server\n'
  printf 'IRIS version:      %s\n' "$version"
  printf 'Install path:      %s\n' "$install_dir"
  printf 'Bind address:      %s\n' "$bind_ip"
  printf 'PostgreSQL port:   %s\n' "$port"
  printf 'Database:          %s\n' "$db_name"
  printf 'DB user:           %s\n' "$db_user"
  printf 'DB admin user:     %s\n' "$db_admin_user"
  printf 'App server:        %s\n' "${app_ip:-not specified}"
  printf 'Passwords:         <hidden>\n'
  printf '\n  1) Start installation\n  2) Cancel\nChoose: '
  local c
  IFS= read -r c || die "Input stream closed."
  [ "$c" = 1 ] || { info "Cancelled."; return 0; }

  cp "$BASE_DIR/templates/db/docker-compose.yml" "$install_dir/docker-compose.yml"
  cp "$BASE_DIR/templates/db/setup.sh" "$install_dir/setup.sh"
  chmod 750 "$install_dir/setup.sh"
  printf 'database\n' >"$install_dir/.iris-role"

  {
    env_line IRIS_RELEASE "$version"
    env_line COMPOSE_PROJECT_NAME "iris-db"
    env_line DB_IMAGE_NAME "ghcr.io/dfir-iris/iriswebapp_db"
    env_line DB_IMAGE_TAG "$version"
    env_line POSTGRES_BIND_IP "$bind_ip"
    env_line POSTGRES_PORT "$port"
    env_line POSTGRES_USER "$db_user"
    env_line POSTGRES_PASSWORD "$db_pass"
    env_line POSTGRES_ADMIN_USER "$db_admin_user"
    env_line POSTGRES_ADMIN_PASSWORD "$db_admin_pass"
    env_line POSTGRES_DB "$db_name"
    env_line APP_SERVER_IP "$app_ip"
  } >"$install_dir/.env"
  chmod 600 "$install_dir/.env"

  mkdir -p "$install_dir/secrets" "$install_dir/backups"
  {
    printf 'DFIR-IRIS distributed database connection\n'
    printf 'DB_SERVER=%s\n' "$bind_ip"
    printf 'POSTGRES_PORT=%s\n' "$port"
    printf 'POSTGRES_DB=%s\n' "$db_name"
    printf 'POSTGRES_USER=%s\n' "$db_user"
    printf 'POSTGRES_PASSWORD=%s\n' "$db_pass"
    printf 'POSTGRES_ADMIN_USER=%s\n' "$db_admin_user"
    printf 'POSTGRES_ADMIN_PASSWORD=%s\n' "$db_admin_pass"
  } >"$install_dir/secrets/application-connection.env"
  chmod 600 "$install_dir/secrets/application-connection.env"

  cd "$install_dir"
  info "Validating database Compose configuration."
  docker compose -p iris-db -f docker-compose.yml config >/dev/null
  info "Pulling PostgreSQL image."
  docker compose -p iris-db -f docker-compose.yml pull
  info "Starting PostgreSQL."
  docker compose -p iris-db -f docker-compose.yml up -d

  local i=1
  while [ "$i" -le 40 ]; do
    if docker exec iriswebapp_db pg_isready -U "$db_user" -d "$db_name" >/dev/null 2>&1; then break; fi
    sleep 2; i=$((i+1))
  done
  docker exec iriswebapp_db pg_isready -U "$db_user" -d "$db_name" >/dev/null 2>&1 || die "PostgreSQL did not become ready."
  ok "PostgreSQL is ready"

  if postgres_auth_test "$bind_ip" "$port" "$db_name" "$db_user" "$db_pass"; then
    ok "Host-side PostgreSQL authentication test passed"
  else
    warn "The DB is running, but the host-side published-port authentication test failed. Check bind IP/firewall/routing."
  fi

  printf '\n============================================================\n'
  printf 'Database Server Installation Complete\n'
  printf '============================================================\n'
  printf 'Endpoint:       %s:%s\n' "$bind_ip" "$port"
  printf 'Database:       %s\n' "$db_name"
  printf 'Management:     %s/setup.sh\n' "$install_dir"
  printf 'Connection file:%s/secrets/application-connection.env\n' "$install_dir"
  printf '\nCopy the connection file securely to the application server if you want to import it during APP installation.\n'
}

read_connection_file() {
  local file=$1
  [ -f "$file" ] || die "Connection file not found: $file"
  DB_SERVER=$(awk -F= '$1=="DB_SERVER"{sub(/^[^=]*=/,"");print;exit}' "$file")
  IMPORT_PORT=$(awk -F= '$1=="POSTGRES_PORT"{sub(/^[^=]*=/,"");print;exit}' "$file")
  IMPORT_DB=$(awk -F= '$1=="POSTGRES_DB"{sub(/^[^=]*=/,"");print;exit}' "$file")
  IMPORT_USER=$(awk -F= '$1=="POSTGRES_USER"{sub(/^[^=]*=/,"");print;exit}' "$file")
  IMPORT_PASS=$(awk -F= '$1=="POSTGRES_PASSWORD"{sub(/^[^=]*=/,"");print;exit}' "$file")
  IMPORT_ADMIN_USER=$(awk -F= '$1=="POSTGRES_ADMIN_USER"{sub(/^[^=]*=/,"");print;exit}' "$file")
  IMPORT_ADMIN_PASS=$(awk -F= '$1=="POSTGRES_ADMIN_PASSWORD"{sub(/^[^=]*=/,"");print;exit}' "$file")
}

install_application_role() {
  banner
  printf 'Role selected: Application Server\n'

  local version install_dir db_host db_port db_name db_user db_pass db_admin_user db_admin_pass
  local public_host https_port admin_user admin_email admin_pass iris_secret iris_salt api_key external_url
  local import_choice connection_file=""
  local soc_ver

  version="$DEFAULT_IRIS_VERSION"
  soc_ver=$(soc_release)

  printf '\nDatabase configuration source\n'
  printf '  1) Enter database details manually\n'
  printf '  2) Import DB connection file generated by the Database Server installer\n'
  printf 'Choose: '
  IFS= read -r import_choice || die "Input stream closed."
  if [ "$import_choice" = 2 ]; then
    connection_file=$(prompt_default "Path to DB connection file" "/tmp/application-connection.env")
    read_connection_file "$connection_file"
    db_host=$DB_SERVER; db_port=$IMPORT_PORT; db_name=$IMPORT_DB; db_user=$IMPORT_USER; db_pass=$IMPORT_PASS
    db_admin_user=$IMPORT_ADMIN_USER; db_admin_pass=$IMPORT_ADMIN_PASS
  else
    db_host=$(prompt_default "Database server IP or FQDN" "127.0.0.1")
    while :; do
      db_port=$(prompt_default "Database port" "5432")
      validate_port "$db_port" && break
      warn "Port must be between 1 and 65535."
    done
    printf '\n[INFO] Testing database network connectivity...\n'
    tcp_check "$db_host" "$db_port" 5 || die "Cannot connect to $db_host:$db_port. Fix database networking before continuing."
    ok "Database TCP endpoint reachable"
    db_name=$(prompt_default "Database name" "iris_db")
    db_user=$(prompt_default "Database application user" "postgres")
    db_pass=$(prompt_secret_confirm "Database application password")
    db_admin_user=$(prompt_default "Database admin user" "raptor")
    db_admin_pass=$(prompt_secret_confirm "Database admin password")
  fi

  printf '\n[INFO] Testing PostgreSQL application credentials...\n'
  postgres_auth_test "$db_host" "$db_port" "$db_name" "$db_user" "$db_pass" || die "PostgreSQL application-user authentication failed."
  ok "PostgreSQL application-user authentication passed"
  if postgres_auth_test "$db_host" "$db_port" "$db_name" "$db_admin_user" "$db_admin_pass"; then
    ok "PostgreSQL admin-user authentication passed"
  else
    warn "PostgreSQL admin-user authentication test failed. IRIS startup may fail if the selected release requires these credentials."
    prompt_yes_no "Continue anyway?" || return 0
  fi

  while :; do
    install_dir=$(prompt_default "IRIS application install directory" "/opt/iris-web")
    if prepare_target_dir "$install_dir"; then break; else rc=$?; [ "$rc" -eq 2 ] && continue; return 0; fi
  done

  detected=$(primary_ipv4 || true)
  [ -n "$detected" ] || detected=$(hostname -f 2>/dev/null || hostname)
  public_host=$(prompt_default "IRIS hostname, FQDN, or IP" "$detected")
  while :; do
    https_port=$(prompt_default "HTTPS port" "443")
    validate_port "$https_port" && break
    warn "Port must be between 1 and 65535."
  done
  if port_in_use "$https_port"; then
    warn "Port $https_port already appears to be in use."
    prompt_yes_no "Continue anyway?" || return 0
  fi
  admin_user=$(prompt_default "Administrator username" "administrator")
  admin_email=$(prompt_default "Administrator email" "admin@localhost")
  admin_pass=$(prompt_secret_confirm "Administrator password")
  iris_secret=$(random_hex 32)
  iris_salt=$(random_hex 24)
  api_key=$(random_hex 32)
  if [ "$https_port" = 443 ]; then external_url="https://${public_host}"; else external_url="https://${public_host}:${https_port}"; fi

  printf '\n============================================================\n'
  printf 'Application Server Deployment Summary\n'
  printf '============================================================\n'
  printf 'Role:              Application Server\n'
  printf 'IRIS version:      %s\n' "$version"
  printf 'Install path:      %s\n' "$install_dir"
  printf 'Application host:  %s\n' "$public_host"
  printf 'HTTPS port:        %s\n' "$https_port"
  printf 'Database server:   %s:%s\n' "$db_host" "$db_port"
  printf 'Database:          %s\n' "$db_name"
  printf 'Database user:     %s\n' "$db_user"
  printf 'Services:          Nginx, IRIS App, IRIS Worker, RabbitMQ\n'
  printf 'Administrator:     %s <%s>\n' "$admin_user" "$admin_email"
  printf 'Secrets:           <hidden>\n'
  printf '\n  1) Start installation\n  2) Cancel\nChoose: '
  local c
  IFS= read -r c || die "Input stream closed."
  [ "$c" = 1 ] || { info "Cancelled."; return 0; }

  rm -rf "$install_dir"
  info "Cloning DFIR-IRIS $version from the official repository."
  git clone --depth 1 --branch "$version" "$REPO_URL" "$install_dir"
  cd "$install_dir"

  prepare_soc_source "$install_dir"
  build_soc_app_image "$install_dir"

  cp "$BASE_DIR/templates/app/docker-compose.yml" "$install_dir/docker-compose.distributed-app.yml"
  cp "$BASE_DIR/templates/app/setup.sh" "$install_dir/setup.sh"
  mkdir -p "$install_dir/lib" "$install_dir/integrations"
  cp "$BASE_DIR/templates/app/lib/legacy_runtime.sh" "$install_dir/lib/legacy_runtime.sh"
  cp "$BASE_DIR/templates/app/integrations/integration_tools.sh" "$install_dir/integrations/integration_tools.sh"
  chmod 750 "$install_dir/setup.sh"
  printf 'application\n' >"$install_dir/.iris-role"

  {
    env_line IRIS_RELEASE "$version"
    env_line COMPOSE_PROJECT_NAME "iris-app"
    env_line APP_IMAGE_NAME "$SOC_IMAGE_NAME"
    env_line APP_IMAGE_TAG "$soc_ver"
    env_line NGINX_IMAGE_NAME "ghcr.io/dfir-iris/iriswebapp_nginx"
    env_line NGINX_IMAGE_TAG "$version"
    env_line SERVER_NAME "$public_host"
    env_line KEY_FILENAME "iris_dev_key.pem"
    env_line CERT_FILENAME "iris_dev_cert.pem"
    env_line POSTGRES_USER "$db_user"
    env_line POSTGRES_PASSWORD "$db_pass"
    env_line POSTGRES_ADMIN_USER "$db_admin_user"
    env_line POSTGRES_ADMIN_PASSWORD "$db_admin_pass"
    env_line POSTGRES_DB "$db_name"
    env_line POSTGRES_SERVER "$db_host"
    env_line POSTGRES_PORT "$db_port"
    env_line DOCKERIZED "1"
    env_line IRIS_SECRET_KEY "$iris_secret"
    env_line IRIS_SECURITY_PASSWORD_SALT "$iris_salt"
    env_line IRIS_UPSTREAM_SERVER "app"
    env_line IRIS_UPSTREAM_PORT "8000"
    env_line CELERY_BROKER "amqp://rabbitmq"
    env_line IRIS_AUTHENTICATION_TYPE "local"
    env_line IRIS_ADM_USERNAME "$admin_user"
    env_line IRIS_ADM_EMAIL "$admin_email"
    env_line IRIS_ADM_PASSWORD "$admin_pass"
    env_line IRIS_ADM_API_KEY "$api_key"
    env_line INTERFACE_HTTPS_PORT "$https_port"
    env_line PUBLIC_HOST "$public_host"
    env_line IRIS_EXTERNAL_URL "$external_url"
    env_line IRIS_FRONTEND_NETWORK "iris_app_frontend"
    env_line IRIS_BACKEND_NETWORK "iris_app_backend"
  } >"$install_dir/.env"
  chmod 600 "$install_dir/.env"

  mkdir -p "$install_dir/secrets" "$install_dir/backups"
  {
    printf 'DFIR-IRIS Application Credentials\n\n'
    printf 'IRIS URL: %s\n' "$external_url"
    printf 'Username: %s\n' "$admin_user"
    printf 'Password: %s\n' "$admin_pass"
    printf 'API key: %s\n' "$api_key"
    printf 'Database server: %s:%s\n' "$db_host" "$db_port"
  } >"$install_dir/secrets/initial-credentials.txt"
  chmod 600 "$install_dir/secrets/initial-credentials.txt"

  info "Validating distributed application Compose configuration."
  docker compose -p iris-app -f docker-compose.distributed-app.yml config >/dev/null
  info "Pulling external application dependencies."
  docker compose -p iris-app -f docker-compose.distributed-app.yml pull rabbitmq nginx
  info "Starting RabbitMQ, IRIS App, Worker, and Nginx."
  docker compose -p iris-app -f docker-compose.distributed-app.yml up -d

  local i=1
  while [ "$i" -le 60 ]; do
    if docker exec iriswebapp_app python3 - <<'PY' >/dev/null 2>&1
import socket
with socket.create_connection(('127.0.0.1', 8000), 2):
    pass
PY
    then break; fi
    sleep 3; i=$((i+1))
  done

  if "$install_dir/setup.sh" doctor; then
    ok "Application health checks passed"
  else
    warn "Installation completed but one or more health checks failed. Run: $install_dir/setup.sh doctor"
  fi

  printf '\n============================================================\n'
  printf 'Application Server Installation Complete\n'
  printf '============================================================\n'
  printf 'IRIS URL:       %s\n' "$external_url"
  printf 'Username:       %s\n' "$admin_user"
  printf 'Credentials:    %s/secrets/initial-credentials.txt\n' "$install_dir"
  printf 'Management:     %s/setup.sh\n' "$install_dir"
}

install_single_node() {
  banner
  warn "Single-Node mode is intended for lab/testing. The distributed DB/APP roles are the primary design."
  local version install_dir public_host https_port admin_user admin_email admin_pass db_pass db_admin_pass
  local soc_ver
  version="$DEFAULT_IRIS_VERSION"
  soc_ver=$(soc_release)
  while :; do
    install_dir=$(prompt_default "Install directory" "/opt/iris-single")
    if prepare_target_dir "$install_dir"; then break; else rc=$?; [ "$rc" -eq 2 ] && continue; return 0; fi
  done
  detected=$(primary_ipv4 || true); [ -n "$detected" ] || detected=localhost
  public_host=$(prompt_default "IRIS hostname or IP" "$detected")
  https_port=$(prompt_default "HTTPS port" "443"); validate_port "$https_port" || die "Invalid port."
  admin_user=$(prompt_default "Administrator username" "administrator")
  admin_email=$(prompt_default "Administrator email" "admin@localhost")
  admin_pass=$(prompt_secret_confirm "Administrator password")
  db_pass=$(random_hex 24); db_admin_pass=$(random_hex 24)
  rm -rf "$install_dir"
  git clone --depth 1 --branch "$version" "$REPO_URL" "$install_dir"
  cd "$install_dir"

  prepare_soc_source "$install_dir"
  build_soc_app_image "$install_dir"

  # IRIS_WORKER must be set only for the worker service.
  # Never place it in the shared .env because the web App then behaves as a worker.
  sed -i '/^[[:space:]]*- IRIS_WORKER$/s/IRIS_WORKER$/IRIS_WORKER=1/'     "$install_dir/docker-compose.base.yml"

  grep -q 'IRIS_WORKER=1' "$install_dir/docker-compose.base.yml" ||     die "Unable to configure the Single-Node worker environment"

  {
    env_line NGINX_IMAGE_NAME "ghcr.io/dfir-iris/iriswebapp_nginx"
    env_line NGINX_IMAGE_TAG "$version"
    env_line SERVER_NAME "$public_host"
    env_line KEY_FILENAME "iris_dev_key.pem"
    env_line CERT_FILENAME "iris_dev_cert.pem"
    env_line DB_IMAGE_NAME "ghcr.io/dfir-iris/iriswebapp_db"
    env_line DB_IMAGE_TAG "$version"
    env_line POSTGRES_USER "postgres"
    env_line POSTGRES_PASSWORD "$db_pass"
    env_line POSTGRES_ADMIN_USER "raptor"
    env_line POSTGRES_ADMIN_PASSWORD "$db_admin_pass"
    env_line POSTGRES_DB "iris_db"
    env_line POSTGRES_SERVER "db"
    env_line POSTGRES_PORT "5432"
    env_line APP_IMAGE_NAME "$SOC_IMAGE_NAME"
    env_line APP_IMAGE_TAG "$soc_ver"
    env_line DOCKERIZED "1"
    env_line IRIS_SECRET_KEY "$(random_hex 32)"
    env_line IRIS_SECURITY_PASSWORD_SALT "$(random_hex 24)"
    env_line IRIS_UPSTREAM_SERVER "app"
    env_line IRIS_UPSTREAM_PORT "8000"
    env_line CELERY_BROKER "amqp://rabbitmq"
    env_line IRIS_AUTHENTICATION_TYPE "local"
    env_line IRIS_ADM_USERNAME "$admin_user"
    env_line IRIS_ADM_EMAIL "$admin_email"
    env_line IRIS_ADM_PASSWORD "$admin_pass"
    env_line IRIS_ADM_API_KEY "$(random_hex 32)"
    env_line INTERFACE_HTTPS_PORT "$https_port"
  } >.env
  chmod 600 .env
  cp "$BASE_DIR/templates/single/setup.sh" "$install_dir/setup.sh"
  chmod 750 "$install_dir/setup.sh"
  printf 'single-node\n' >"$install_dir/.iris-role"
  docker compose pull rabbitmq db nginx
  docker compose up -d
  info "Single-node IRIS started. Management: $install_dir/setup.sh"
}

main_menu() {
  while :; do
    banner
    printf 'Select deployment type:\n\n'
    printf '  1) Database Server\n'
    printf '     PostgreSQL only\n\n'
    printf '  2) Application Server\n'
    printf '     Nginx + IRIS App + Worker + RabbitMQ\n\n'
    printf '  3) Single-Node / Lab\n'
    printf '     SOC-hardened all-in-one service layout\n\n'
    printf '  0) Exit\n\nChoose: '
    local c
    IFS= read -r c || exit 0
    case "$c" in
      1) install_database_role; return 0 ;;
      2) install_application_role; return 0 ;;
      3) install_single_node; return 0 ;;
      0) exit 0 ;;
      *) warn "Choose one of the listed options." ;;
    esac
  done
}

preflight
main_menu
