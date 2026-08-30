#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

info() { printf '[INFO] %s\n' "$*"; }
ok()   { printf '[OK] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die()  { printf '[ERROR] %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

require_root() {
  [ "$(id -u)" -eq 0 ] || die "Run this action as root or with sudo."
}

prompt_default() {
  local label=$1 default_value=$2 value=""
  printf '\n%s\n' "$label" >&2
  printf 'Default: %s\n' "$default_value" >&2
  printf 'Press Enter to use the default, or type another value: ' >&2
  IFS= read -r value || die "Input stream closed."
  [ -n "$value" ] || value=$default_value
  printf '%s\n' "$value"
}

prompt_optional() {
  local label=$1 value=""
  printf '\n%s\n' "$label" >&2
  printf 'Press Enter to leave blank, or type a value: ' >&2
  IFS= read -r value || die "Input stream closed."
  printf '%s\n' "$value"
}

prompt_secret() {
  local label=$1 value=""
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

prompt_secret_confirm() {
  local label=$1 first second
  while :; do
    first=$(prompt_secret "$label")
    second=$(prompt_secret "Confirm $label")
    if [ -n "$first" ] && [ "$first" = "$second" ]; then
      printf '%s\n' "$first"
      return 0
    fi
    warn "Values did not match or were empty. Try again."
  done
}

prompt_yes_no() {
  local prompt=$1 answer=""
  while :; do
    printf '\n%s\n' "$prompt"
    printf '  1) Yes\n  2) No\nChoose 1 or 2: '
    IFS= read -r answer || die "Input stream closed."
    case "$answer" in
      1|y|Y|yes|YES|Yes) return 0 ;;
      2|n|N|no|NO|No) return 1 ;;
      *) warn "Please choose 1 for yes or 2 for no." ;;
    esac
  done
}

random_hex() {
  local bytes=${1:-32}
  if have openssl; then
    openssl rand -hex "$bytes"
  else
    python3 - "$bytes" <<'PY'
import secrets, sys
print(secrets.token_hex(int(sys.argv[1])))
PY
  fi
}

validate_port() {
  local port=${1:-}
  case "$port" in *[!0-9]*|'') return 1 ;; esac
  [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}

primary_ipv4() {
  if have ip; then
    ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}'
  elif have hostname; then
    hostname -I 2>/dev/null | awk '{print $1}'
  fi
}

port_in_use() {
  local port=$1
  if have ss; then
    ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)$port$"
  else
    return 1
  fi
}

tcp_check() {
  local host=$1 port=$2 timeout=${3:-4}
  python3 - "$host" "$port" "$timeout" <<'PY'
import socket, sys
host, port, timeout = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
try:
    with socket.create_connection((host, port), timeout):
        pass
except Exception as exc:
    print(exc, file=sys.stderr)
    raise SystemExit(1)
PY
}

pause_menu() {
  printf '\nPress Enter to continue...'
  IFS= read -r _ || true
}

detect_pkg_manager() {
  if have apt-get; then printf 'apt\n'
  elif have dnf; then printf 'dnf\n'
  elif have yum; then printf 'yum\n'
  else return 1
  fi
}

install_host_prereqs() {
  local pm
  pm=$(detect_pkg_manager || true)
  [ -n "$pm" ] || die "No supported package manager found (apt, dnf, yum)."

  case "$pm" in
    apt)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -y
      apt-get install -y ca-certificates curl git python3 openssl
      ;;
    dnf) dnf install -y ca-certificates curl git python3 openssl ;;
    yum) yum install -y ca-certificates curl git python3 openssl ;;
  esac
}

install_docker_engine() {
  info "Docker was not found. Installing Docker Engine and Docker Compose plugin."
  install_host_prereqs

  local installer=/tmp/get-docker.sh
  curl -fsSL https://get.docker.com -o "$installer" || die "Could not download the Docker installer."
  sh "$installer" || die "Docker installation failed."
  rm -f "$installer"

  if have systemctl && [ -d /run/systemd/system ]; then
    systemctl enable --now docker >/dev/null 2>&1 || true
  elif have service; then
    service docker start >/dev/null 2>&1 || true
  fi

  have docker || die "Docker installation completed but the docker command is still unavailable."
}

ensure_compose_plugin() {
  docker compose version >/dev/null 2>&1 && return 0

  warn "Docker Compose plugin is missing. Attempting installation."
  local pm
  pm=$(detect_pkg_manager || true)
  case "$pm" in
    apt)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -y
      apt-get install -y docker-compose-plugin >/dev/null 2>&1 \
        || apt-get install -y docker-compose-v2 >/dev/null 2>&1 \
        || true
      ;;
    dnf) dnf install -y docker-compose-plugin >/dev/null 2>&1 || true ;;
    yum) yum install -y docker-compose-plugin >/dev/null 2>&1 || true ;;
  esac

  docker compose version >/dev/null 2>&1 || die "Docker Compose plugin could not be installed automatically."
}

ensure_basic_tools() {
  if ! have python3 || ! have git || ! have curl; then
    info "Installing missing host prerequisites."
    install_host_prereqs
  fi

  if ! have docker; then
    install_docker_engine
  fi

  if ! docker info >/dev/null 2>&1; then
    if have systemctl && [ -d /run/systemd/system ]; then
      info "Starting Docker service."
      systemctl enable --now docker >/dev/null 2>&1 || true
    elif have service; then
      service docker start >/dev/null 2>&1 || true
    fi
  fi

  docker info >/dev/null 2>&1 || die "Docker daemon is not reachable."
  ensure_compose_plugin
}

safe_write_file() {
  local path=$1
  mkdir -p "$(dirname "$path")"
  cat >"$path"
}

mask_value() {
  local value=${1:-}
  [ -n "$value" ] && printf '<set>\n' || printf '<empty>\n'
}
