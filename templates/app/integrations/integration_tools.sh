write_wazuh_iris_script() {
  script_path=$1
  customer_id=$2
  dashboard_url=$3

  mkdir -p "$(dirname "$script_path")"
  cat > "$script_path" <<'PYINT'
#!/var/ossec/framework/python/bin/python3
import json
import logging
import os
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

LOG_FILE = "/var/ossec/logs/integrations.log"
IRIS_CUSTOMER_ID = __IRIS_CUSTOMER_ID__
WAZUH_DASHBOARD_URL = __WAZUH_DASHBOARD_URL__

LOG_KWARGS = {
    "level": logging.INFO,
    "format": "%(asctime)s %(levelname)s custom-wazuh_iris: %(message)s",
    "datefmt": "%Y-%m-%d %H:%M:%S",
}
if os.path.isdir(os.path.dirname(LOG_FILE)):
    LOG_KWARGS["filename"] = LOG_FILE
else:
    LOG_KWARGS["stream"] = sys.stderr
if os.environ.get("WAZUH_IRIS_LOG_STDERR") == "1":
    LOG_KWARGS.pop("filename", None)
    LOG_KWARGS["stream"] = sys.stderr
logging.basicConfig(**LOG_KWARGS)


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def md_escape(value):
    if value is None or value == "":
        return "N/A"
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False)
    value = str(value).replace("|", "\\|").replace("\r", " ").replace("\n", "<br>")
    return value


def md_table(rows):
    lines = ["| Field | Value |", "|---|---|"]
    for field, value in rows:
        lines.append(f"| {md_escape(field)} | {md_escape(value)} |")
    return "\n".join(lines)


def flatten_dict(value, prefix=""):
    rows = []
    if not isinstance(value, dict):
        return rows
    for key in sorted(value.keys(), key=lambda item: str(item)):
        item = value.get(key)
        name = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(item, dict):
            rows.extend(flatten_dict(item, name))
        elif isinstance(item, list):
            if all(not isinstance(x, (dict, list)) for x in item):
                rows.append((name, ", ".join(str(x) for x in item)))
            else:
                rows.append((name, json.dumps(item, ensure_ascii=False)))
        else:
            rows.append((name, item))
    return rows


def iris_severity_from_wazuh(level):
    try:
        level = int(level)
    except Exception:
        level = 0
    if level < 5:
        return 2
    if level < 7:
        return 3
    if level < 10:
        return 4
    if level < 13:
        return 5
    return 6


def format_alert_details(alert):
    rule = alert.get("rule", {}) or {}
    agent = alert.get("agent", {}) or {}
    manager = alert.get("manager", {}) or {}
    mitre = rule.get("mitre", {}) or {}
    data = alert.get("data", {}) or {}
    full_log = str(alert.get("full_log", "N/A")).replace("```", "~~~")
    sections = []

    sections.append("## Wazuh Alert Summary")
    sections.append(md_table([
        ("Alert ID", alert.get("id", "N/A")),
        ("Timestamp", alert.get("timestamp", "N/A")),
        ("Source", "Wazuh"),
        ("Location", alert.get("location", "N/A")),
        ("Manager", manager.get("name", "N/A")),
    ]))

    sections.append("## Rule Details")
    sections.append(md_table([
        ("Rule ID", rule.get("id", "N/A")),
        ("Rule Level", rule.get("level", "N/A")),
        ("Description", rule.get("description", "N/A")),
        ("Groups", ", ".join(as_list(rule.get("groups"))) or "N/A"),
        ("Fired Times", rule.get("firedtimes", "N/A")),
    ]))

    sections.append("## Agent Details")
    sections.append(md_table([
        ("Agent ID", agent.get("id", "N/A")),
        ("Agent Name", agent.get("name", "N/A")),
        ("Agent IP", agent.get("ip", "N/A")),
    ]))

    sections.append("## MITRE ATT&CK")
    sections.append(md_table([
        ("Technique IDs", ", ".join(as_list(mitre.get("id"))) or "N/A"),
        ("Tactics", ", ".join(as_list(mitre.get("tactic"))) or "N/A"),
        ("Techniques", ", ".join(as_list(mitre.get("technique"))) or "N/A"),
    ]))

    event_rows = flatten_dict(data)
    if event_rows:
        sections.append("## Normalized Event Data")
        sections.append(md_table(event_rows[:35]))
        if len(event_rows) > 35:
            sections.append(f"_Additional event fields omitted for readability: {len(event_rows) - 35}_")

    sections.append("## Raw Log")
    sections.append("```text")
    sections.append(full_log)
    sections.append("```")
    return "\n\n".join(sections)


def build_payload(alert):
    rule = alert.get("rule", {}) or {}
    agent = alert.get("agent", {}) or {}
    level = rule.get("level", 0)
    alert_ref = alert.get("id") or f"wazuh-{utc_now()}"
    event_time = alert.get("timestamp") or utc_now()
    tags = ["wazuh", f"wazuh-level-{level}"]
    if agent.get("name"):
        tags.append("agent-" + str(agent.get("name")).replace(" ", "-"))
    for group in as_list(rule.get("groups")):
        if group:
            tags.append("group-" + str(group).replace(" ", "-").replace(",", ""))
    return {
        "alert_title": rule.get("description", "Wazuh alert"),
        "alert_description": format_alert_details(alert),
        "alert_source": "Wazuh",
        "alert_source_ref": alert_ref,
        "alert_source_link": WAZUH_DASHBOARD_URL,
        "alert_severity_id": iris_severity_from_wazuh(level),
        "alert_status_id": 2,
        "alert_source_event_time": event_time,
        "alert_note": "",
        "alert_tags": ",".join(tags),
        "alert_customer_id": IRIS_CUSTOMER_ID,
        "alert_source_content": alert,
    }


def post_to_iris(hook_url, api_key, payload):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        hook_url,
        data=data,
        method="POST",
        headers={
            "Authorization": "Bearer " + api_key,
            "Content-Type": "application/json",
            "User-Agent": "wazuh-iris-integration",
        },
    )
    if hook_url.lower().startswith("https://"):
        context = ssl._create_unverified_context()
        response_handle = urllib.request.urlopen(req, context=context, timeout=20)
    else:
        response_handle = urllib.request.urlopen(req, timeout=20)
    with response_handle as response:
        body = response.read().decode("utf-8", errors="replace")
        return response.status, body


def main():
    if len(sys.argv) < 4:
        logging.error("Insufficient arguments. Expected: alert_file api_key hook_url")
        return 1
    alert_file, api_key, hook_url = sys.argv[1], sys.argv[2], sys.argv[3]
    try:
        with open(alert_file, "r", encoding="utf-8") as f:
            alert = json.load(f)
    except Exception as exc:
        logging.exception("Failed to read alert file: %s", exc)
        return 1
    payload = build_payload(alert)
    try:
        status, body = post_to_iris(hook_url, api_key, payload)
        if status in (200, 201, 202, 204):
            logging.info("Sent Wazuh alert to IRIS. status=%s alert_ref=%s", status, payload.get("alert_source_ref"))
            return 0
        logging.error("IRIS returned non-success status=%s body=%s", status, body[:500])
        return 1
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        logging.error("IRIS HTTP error status=%s body=%s", exc.code, body[:1000])
        return 1
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        logging.error("IRIS connection error url=%s error=%s", hook_url, reason)
        return 1
    except Exception as exc:
        logging.exception("Failed to send alert to IRIS: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
PYINT

  python3 - "$script_path" "$customer_id" "$dashboard_url" <<'PYEDIT'
from pathlib import Path
import json
import sys

path = Path(sys.argv[1])
customer_id = sys.argv[2]
dashboard_url = sys.argv[3]
text = path.read_text()
text = text.replace("__IRIS_CUSTOMER_ID__", customer_id)
text = text.replace("__WAZUH_DASHBOARD_URL__", json.dumps(dashboard_url))
path.write_text(text)
PYEDIT
  chmod 750 "$script_path"
}

default_iris_hook_url() {
  load_env
  if [ -n "${IRIS_EXTERNAL_URL:-}" ]; then
    printf '%s\n' "${IRIS_EXTERNAL_URL%/}/alerts/add"
    return 0
  fi
  port=$(detect_iris_nginx_port || true)
  if [ -n "$port" ]; then
    printf 'https://127.0.0.1:%s/alerts/add\n' "$port"
  else
    printf 'https://127.0.0.1:%s/alerts/add\n' "${INTERFACE_HTTPS_PORT:-443}"
  fi
}

default_iris_container_hook_url() {
  load_env
  if [ "${USE_SHARED_NETWORK:-no}" = "yes" ] && [ -n "${IRIS_WEB_ALIAS:-}" ]; then
    printf 'https://%s:%s/alerts/add\n' "$IRIS_WEB_ALIAS" "${INTERFACE_HTTPS_PORT:-443}"
  else
    printf 'https://iriswebapp_nginx:%s/alerts/add\n' "${INTERFACE_HTTPS_PORT:-443}"
  fi
}

default_iris_app_hook_url() {
  load_env
  printf 'http://iriswebapp_app:%s/alerts/add\n' "${IRIS_UPSTREAM_PORT:-8000}"
}

emit_hook_candidate() {
  candidate=$1
  [ -n "$candidate" ] || return 0
  candidate=${candidate%/}
  case "$candidate" in
    */alerts/add) ;;
    http://*|https://*) candidate="${candidate}/alerts/add" ;;
  esac
  case "
${HOOK_CANDIDATES_SEEN:-}
" in
    *"
$candidate
"*) return 0 ;;
  esac
  HOOK_CANDIDATES_SEEN="${HOOK_CANDIDATES_SEEN:-}
$candidate"
  printf '%s\n' "$candidate"
}

detect_iris_nginx_port() {
  load_env
  have docker || return 1
  docker ps --format '{{.Names}}' | grep -Fxq 'iriswebapp_nginx' || return 1
  port=$(docker port iriswebapp_nginx "${INTERFACE_HTTPS_PORT:-443}/tcp" 2>/dev/null | awk -F: 'NR==1 {print $NF}' || true)
  [ -n "$port" ] || port=$(docker port iriswebapp_nginx 443/tcp 2>/dev/null | awk -F: 'NR==1 {print $NF}' || true)
  [ -n "$port" ] || return 1
  printf '%s\n' "$port"
}

iris_hook_url_candidates() {
  preferred=${1:-}
  load_env
  HOOK_CANDIDATES_SEEN=""
  emit_hook_candidate "$preferred"
  emit_hook_candidate "${IRIS_EXTERNAL_URL:-}"
  if port=$(detect_iris_nginx_port 2>/dev/null); then
    emit_hook_candidate "https://127.0.0.1:${port}/alerts/add"
    emit_hook_candidate "https://localhost:${port}/alerts/add"
  fi
  emit_hook_candidate "https://127.0.0.1:${INTERFACE_HTTPS_PORT:-443}/alerts/add"
  emit_hook_candidate "https://localhost:${INTERFACE_HTTPS_PORT:-443}/alerts/add"
}

iris_container_hook_url_candidates() {
  preferred=${1:-}
  load_env
  HOOK_CANDIDATES_SEEN=""
  emit_hook_candidate "$preferred"
  emit_hook_candidate "$(default_iris_container_hook_url)"
  emit_hook_candidate "https://iriswebapp_nginx:${INTERFACE_HTTPS_PORT:-443}/alerts/add"
  emit_hook_candidate "https://nginx:${INTERFACE_HTTPS_PORT:-443}/alerts/add"
  if [ "${USE_SHARED_NETWORK:-no}" = "yes" ] && [ -n "${IRIS_WEB_ALIAS:-}" ]; then
    emit_hook_candidate "https://${IRIS_WEB_ALIAS}:${INTERFACE_HTTPS_PORT:-443}/alerts/add"
  fi
  emit_hook_candidate "$(default_iris_app_hook_url)"
  emit_hook_candidate "http://app:${IRIS_UPSTREAM_PORT:-8000}/alerts/add"
  emit_hook_candidate "${IRIS_EXTERNAL_URL:-}"
}

detect_iris_api_key() {
  load_env
  if [ -n "${IRIS_ADM_API_KEY:-}" ]; then
    printf '%s\n' "$IRIS_ADM_API_KEY"
    return 0
  fi
  if [ -f "$DIR/secrets/initial-credentials.txt" ]; then
    key=$(awk -F': ' '/^API key:/ {print $2; exit}' "$DIR/secrets/initial-credentials.txt" 2>/dev/null || true)
    if [ -n "$key" ]; then
      printf '%s\n' "$key"
      return 0
    fi
  fi
  if have docker && docker ps --format '{{.Names}}' | grep -Fxq 'iriswebapp_app'; then
    key=$(docker exec iriswebapp_app printenv IRIS_ADM_API_KEY 2>/dev/null || true)
    if [ -n "$key" ]; then
      printf '%s\n' "$key"
      return 0
    fi
    key=$(docker exec iriswebapp_app python3 - 2>/dev/null <<'PYKEY' || true
import os

try:
    from app import app
    from app.models.authorization import User
except Exception:
    raise SystemExit(0)

with app.app_context():
    username = os.environ.get("IRIS_ADM_USERNAME")
    user = User.query.filter_by(user=username).first() if username else None
    if user is None:
        user = User.query.filter(User.api_key.isnot(None)).order_by(User.id.asc()).first()
    if user is not None and user.api_key:
        print(user.api_key)
PYKEY
)
    key=$(printf '%s\n' "$key" | tail -n 1)
    if [ -n "$key" ]; then
      printf '%s\n' "$key"
      return 0
    fi
  fi
  return 1
}

list_local_wazuh_containers() {
  if [ -n "${WAZUH_TOPOLOGY_TEST_RECORDS:-}" ]; then
    printf '%s\n' "$WAZUH_TOPOLOGY_TEST_RECORDS" | awk -F '\t' '
      NF >= 4 && $1 != "" && $2 != "" {
        print $1 "\t" $2 "\t" $3 "\t" $4
      }
    '
    return 0
  fi

  have docker || return 0
  docker info >/dev/null 2>&1 || return 0
  docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Labels}}' | awk -F '\t' '
    NF >= 3 {
      name=$1
      image=$2
      status=$3
      labels=$4
      low=tolower(name " " image " " labels)
      if (low !~ /wazuh/) {
        next
      }
      role="unknown"
      if (low ~ /dashboard/) {
        role="dashboard"
      } else if (low ~ /indexer|opensearch|elasticsearch/) {
        role="indexer"
      } else if (low ~ /manager/) {
        role="manager"
      }
      print role "\t" name "\t" image "\t" status
    }
  '
}

list_local_wazuh_manager_containers() {
  list_local_wazuh_containers | awk -F '\t' '
    $1 == "manager" && $2 != "" && $2 !~ /[[:space:]:]/ {
      if (!seen[$2]++) {
        print $2
      }
    }
  '
}

show_wazuh_topology() {
  printf '\n============================================================\n' >&2
  printf 'Wazuh topology detection (read-only)\n' >&2
  printf '============================================================\n' >&2
  printf 'OpenCTI bridge actions do not use this information and do not touch Wazuh.\n\n' >&2

  printf 'Local Docker Wazuh containers:\n' >&2
  found=0
  while IFS="$(printf '\t')" read -r role name image status; do
    [ -n "$name" ] || continue
    found=1
    printf '  - role=%s name=%s image=%s status=%s\n' "$role" "$name" "$image" "$status" >&2
  done <<EOF
$(list_local_wazuh_containers)
EOF
  if [ "$found" -eq 0 ]; then
    if have docker && docker info >/dev/null 2>&1; then
      printf '  none detected\n' >&2
    else
      printf '  Docker is unavailable or not running.\n' >&2
    fi
  fi

  printf '\nLocal systemd Wazuh manager:\n' >&2
  if have systemctl && systemctl list-unit-files wazuh-manager.service >/dev/null 2>&1; then
    if systemctl is-active wazuh-manager.service >/dev/null 2>&1; then
      printf '  wazuh-manager.service is active\n' >&2
    else
      printf '  wazuh-manager.service exists but is not active\n' >&2
    fi
  else
    printf '  wazuh-manager.service not detected\n' >&2
  fi

  if [ -d /var/ossec ]; then
    printf '  /var/ossec exists on this host\n' >&2
  else
    printf '  /var/ossec not detected on this host\n' >&2
  fi

  printf '\nProduction note:\n' >&2
  printf '  Install Wazuh manager integrations only on selected manager nodes.\n' >&2
  printf '  Do not deploy manager integrations to Wazuh dashboard or indexer nodes.\n' >&2
  printf '  Do not restart Wazuh automatically; restart only after explicit approval.\n' >&2
}

detect_wazuh_topology() {
  show_wazuh_topology
}

choose_wazuh_topology_mode() {
  default_mode=${1:-lab-single-node}
  printf '\nWazuh topology mode\n' >&2
  printf '  1) lab-single-node       One local Wazuh manager, still confirmed before changes\n' >&2
  printf '  2) production-multi-node Explicit target selection; no dashboard/indexer changes\n' >&2
  printf '  3) opencti-only          Skip all Wazuh logic\n' >&2
  printf 'Default: %s\n' "$default_mode" >&2
  printf 'Choose 1, 2, 3, or press Enter for the default: ' >&2
  IFS= read -r mode_choice || die "Input stream closed."
  case "$mode_choice" in
    "") printf '%s\n' "$default_mode" ;;
    1|lab-single-node) printf 'lab-single-node\n' ;;
    2|production-multi-node) printf 'production-multi-node\n' ;;
    3|opencti-only) printf 'opencti-only\n' ;;
    *) warn "Unknown mode; using $default_mode."; printf '%s\n' "$default_mode" ;;
  esac
}

select_wazuh_manager_containers() {
  mode=${1:-lab-single-node}
  managers=()
  selected=()
  mapfile -t managers < <(list_local_wazuh_manager_containers)

  if [ "${#managers[@]}" -eq 0 ]; then
    warn "No running local Wazuh manager containers were found."
    warn "Use the remote Wazuh manager bundle for remote or systemd manager nodes."
    return 1
  fi

  if [ "${#managers[@]}" -eq 1 ]; then
    printf '\nDetected one local Wazuh manager container:\n' >&2
    printf '  - %s\n' "${managers[0]}" >&2
    if prompt_yes_no "Use this Wazuh manager container as the target?" >&2; then
      printf '%s\n' "${managers[0]}"
      return 0
    fi
    warn "Cancelled Wazuh manager selection."
    return 1
  fi

  if [ "$mode" = "lab-single-node" ]; then
    warn "Multiple Wazuh manager containers were detected; lab-single-node mode still requires one explicit target."
  else
    warn "Production multi-node mode requires explicit manager target selection."
  fi

  printf '\nDetected Wazuh manager container candidates:\n' >&2
  idx=1
  for manager in "${managers[@]}"; do
    printf '  %s) %s\n' "$idx" "$manager" >&2
    idx=$((idx + 1))
  done
  printf '  a) all detected manager containers\n' >&2
  printf '  c) cancel\n' >&2
  printf 'Choose a number, a comma-separated list such as 1,3, "a" for all, or "c": ' >&2
  IFS= read -r selection || die "Input stream closed."
  case "$selection" in
    c|C|cancel|Cancel) warn "Cancelled Wazuh manager selection."; return 1 ;;
    a|A|all|ALL) selected=("${managers[@]}") ;;
    *)
      old_ifs=$IFS
      IFS=,
      # shellcheck disable=SC2206
      parts=($selection)
      IFS=$old_ifs
      for raw_idx in "${parts[@]}"; do
        idx=$(printf '%s' "$raw_idx" | tr -d ' ')
        case "$idx" in
          *[!0-9]*|"") warn "Invalid Wazuh selection: $idx"; return 1 ;;
        esac
        [ "$idx" -ge 1 ] 2>/dev/null || { warn "Invalid Wazuh selection: $idx"; return 1; }
        [ "$idx" -le "${#managers[@]}" ] || { warn "No Wazuh manager candidate number: $idx"; return 1; }
        selected+=("${managers[$((idx - 1))]}")
      done
      ;;
  esac

  if [ "${#selected[@]}" -eq 0 ]; then
    warn "No Wazuh manager containers selected."
    return 1
  fi

  seen=""
  for manager in "${selected[@]}"; do
    [ -n "$manager" ] || continue
    case "
$seen
" in
      *"
$manager
"*) continue ;;
    esac
    seen="${seen}
$manager"
    printf '%s\n' "$manager"
  done
}

validate_wazuh_manager_container() {
  container=${1:-}

  if [ -z "$container" ]; then
    warn "Empty Wazuh manager container name."
    return 1
  fi

  case "$container" in
    *[[:space:]]*|*":"*|*"Detected"*|*"candidates"*|*"role="*|*"name="*|*"image="*|*"status="*|*"("*|*")"*)
      warn "Invalid container target string: $container"
      return 1
      ;;
  esac

  if [ "${WAZUH_VALIDATION_TEST_MODE:-no}" = "yes" ]; then
    list_local_wazuh_manager_containers | grep -Fxq "$container" || {
      warn "Selected test container is not a Wazuh manager: $container"
      return 1
    }
    return 0
  fi

  have docker || { warn "Docker is required for local Wazuh container integration."; return 1; }
  docker ps --format '{{.Names}}' | grep -Fxq "$container" || {
    warn "Wazuh manager container is not running: $container"
    return 1
  }

  image=$(docker inspect "$container" --format '{{.Config.Image}}' 2>/dev/null || true)
  labels=$(docker inspect "$container" --format '{{range $k, $v := .Config.Labels}}{{printf "%s=%s " $k $v}}{{end}}' 2>/dev/null || true)
  low=$(printf '%s %s %s\n' "$container" "$image" "$labels" | tr '[:upper:]' '[:lower:]')

  case "$low" in
    *dashboard*|*indexer*)
      warn "Selected container is not a Wazuh manager: $container"
      return 1
      ;;
  esac

  case "$low" in
    *manager*|*wazuh/wazuh-manager*) ;;
    *)
      warn "Selected container does not look like a Wazuh manager by name/image/labels: $container"
      return 1
      ;;
  esac

  docker exec "$container" test -d /var/ossec || {
    warn "/var/ossec not found inside selected manager container: $container"
    return 1
  }

  docker exec "$container" sh -lc 'test -d /var/ossec/integrations || test -w /var/ossec' || {
    warn "/var/ossec/integrations is missing and /var/ossec is not writable inside: $container"
    return 1
  }
}

confirm_wazuh_manager_targets() {
  [ "$#" -gt 0 ] || { warn "No Wazuh manager targets were provided."; return 1; }

  printf '\nSelected Wazuh manager container target(s):\n' >&2
  for container in "$@"; do
    printf '  - %s\n' "$container" >&2
  done
  printf '\nThe installer will modify only these files on each selected manager container:\n' >&2
  printf '  /var/ossec/integrations/custom-wazuh_iris.py\n' >&2
  printf '  /var/ossec/etc/ossec.conf (timestamped backup first)\n' >&2
  printf '\nThe installer will not modify Wazuh dashboard or indexer containers.\n' >&2
  printf 'Wazuh will not be restarted unless you explicitly approve a restart for each manager.\n' >&2

  prompt_yes_no "Proceed with the selected Wazuh manager target(s)?" >&2
}

wazuh_selection_self_test_fail() {
  warn "Wazuh selection self-test failed: $*"
  return 1
}

wazuh_selection_self_test() {
  info "Running Wazuh topology/manager-selection self-test."
  failures=0

  one_manager=$(printf 'manager\twazuh-manager-single-node-01\twazuh/wazuh-manager:4.14.6\tUp 1 hour\n')
  mixed_topology=$(printf 'dashboard\twazuh-dashboard-single-node-01\twazuh/wazuh-dashboard:4.14.6\tUp 1 hour\nmanager\twazuh-manager-single-node-01\twazuh/wazuh-manager:4.14.6\tUp 1 hour\nindexer\twazuh-indexer-single-node-01\twazuh/wazuh-indexer:4.14.6\tUp 1 hour\n')
  multi_manager=$(printf 'manager\twazuh-manager-a\twazuh/wazuh-manager:4.14.6\tUp 1 hour\nmanager\twazuh-manager-b\twazuh/wazuh-manager:4.14.6\tUp 1 hour\ndashboard\twazuh-dashboard\twazuh/wazuh-dashboard:4.14.6\tUp 1 hour\nindexer\twazuh-indexer\twazuh/wazuh-indexer:4.14.6\tUp 1 hour\n')
  no_manager=$(printf 'dashboard\twazuh-dashboard\twazuh/wazuh-dashboard:4.14.6\tUp 1 hour\nindexer\twazuh-indexer\twazuh/wazuh-indexer:4.14.6\tUp 1 hour\n')

  WAZUH_TOPOLOGY_TEST_RECORDS=$one_manager
  out=$(list_local_wazuh_manager_containers)
  [ "$out" = "wazuh-manager-single-node-01" ] || { wazuh_selection_self_test_fail "one-manager list output was: $out"; failures=$((failures + 1)); }
  out=$(printf '1\n' | select_wazuh_manager_containers lab-single-node 2>/dev/null || true)
  [ "$out" = "wazuh-manager-single-node-01" ] || { wazuh_selection_self_test_fail "one-manager selected output was: $out"; failures=$((failures + 1)); }
  out=$(show_wazuh_topology 2>/dev/null || true)
  [ -z "$out" ] || { wazuh_selection_self_test_fail "show_wazuh_topology printed to stdout"; failures=$((failures + 1)); }

  WAZUH_TOPOLOGY_TEST_RECORDS=$mixed_topology
  out=$(list_local_wazuh_manager_containers)
  [ "$out" = "wazuh-manager-single-node-01" ] || { wazuh_selection_self_test_fail "mixed topology manager list output was: $out"; failures=$((failures + 1)); }

  WAZUH_TOPOLOGY_TEST_RECORDS=$multi_manager
  out=$(printf '1\n' | select_wazuh_manager_containers production-multi-node 2>/dev/null || true)
  [ "$out" = "wazuh-manager-a" ] || { wazuh_selection_self_test_fail "multi-manager single selection output was: $out"; failures=$((failures + 1)); }
  out=$(printf '1,2\n' | select_wazuh_manager_containers production-multi-node 2>/dev/null || true)
  [ "$out" = "$(printf 'wazuh-manager-a\nwazuh-manager-b')" ] || { wazuh_selection_self_test_fail "multi-manager multi-select output was: $out"; failures=$((failures + 1)); }
  out=$(printf 'a\n' | select_wazuh_manager_containers production-multi-node 2>/dev/null || true)
  [ "$out" = "$(printf 'wazuh-manager-a\nwazuh-manager-b')" ] || { wazuh_selection_self_test_fail "multi-manager all-select output was: $out"; failures=$((failures + 1)); }

  WAZUH_TOPOLOGY_TEST_RECORDS=$no_manager
  if printf '1\n' | select_wazuh_manager_containers production-multi-node >/tmp/wazuh-selection-empty.out 2>/dev/null; then
    wazuh_selection_self_test_fail "no-manager selection unexpectedly succeeded"
    failures=$((failures + 1))
  fi
  if [ -s /tmp/wazuh-selection-empty.out ]; then
    wazuh_selection_self_test_fail "no-manager selection printed stdout"
    failures=$((failures + 1))
  fi
  rm -f /tmp/wazuh-selection-empty.out

  WAZUH_TOPOLOGY_TEST_RECORDS=$one_manager
  WAZUH_VALIDATION_TEST_MODE=yes
  validate_wazuh_manager_container "wazuh-manager-single-node-01" || { wazuh_selection_self_test_fail "valid test manager rejected"; failures=$((failures + 1)); }
  for bad in \
    "" \
    "Detected Wazuh manager container candidates:" \
    "1) wazuh-manager-single-node-01" \
    "role=manager name=wazuh-manager-single-node-01" \
    "wazuh-dashboard-single-node-01" \
    "wazuh-manager-single-node-01:bad"; do
    if validate_wazuh_manager_container "$bad" >/dev/null 2>&1; then
      wazuh_selection_self_test_fail "polluted or invalid target was accepted: $bad"
      failures=$((failures + 1))
    fi
  done
  unset WAZUH_VALIDATION_TEST_MODE
  unset WAZUH_TOPOLOGY_TEST_RECORDS

  if sed -n '/^OPENCTI_BRIDGE_DIR=/,/^wazuh_menu()/p' "$0" | grep -Eq 'show_wazuh_topology|select_wazuh_manager_containers|list_local_wazuh|validate_wazuh_manager_container'; then
    wazuh_selection_self_test_fail "OpenCTI block contains Wazuh topology function calls"
    failures=$((failures + 1))
  fi

  if [ "$failures" -eq 0 ]; then
    info "Wazuh topology/manager-selection self-test passed."
    return 0
  fi
  warn "Wazuh topology/manager-selection self-test failed with $failures issue(s)."
  return 1
}

detect_wazuh_manager_container() {
  have docker || return 1
  name=$(docker ps --format '{{.Names}}' | awk '/^wazuh-manager-/ {print; exit}' || true)
  [ -n "$name" ] || name=$(docker ps --format '{{.Names}}' | awk '/^modular-wazuh-manager$/ {print; exit}' || true)
  [ -n "$name" ] || name=$(docker ps --format '{{.Names}}' | awk '/^wazuh-manager$/ {print; exit}' || true)
  [ -n "$name" ] || name=$(docker ps --format '{{.Names}}' | awk 'tolower($0) ~ /wazuh/ && tolower($0) ~ /manager/ {print; exit}' || true)
  [ -n "$name" ] || return 1
  printf '%s\n' "$name"
}

connect_wazuh_container_to_iris_network() {
  container=$1
  load_env
  [ -n "${IRIS_FRONTEND_NETWORK:-}" ] || return 0
  docker network inspect "$IRIS_FRONTEND_NETWORK" >/dev/null 2>&1 || {
    warn "IRIS frontend network was not found: $IRIS_FRONTEND_NETWORK"
    return 0
  }
  if docker inspect -f '{{range $name, $_ := .NetworkSettings.Networks}}{{println $name}}{{end}}' "$container" 2>/dev/null | grep -Fxq "$IRIS_FRONTEND_NETWORK"; then
    info "Wazuh manager container is already attached to $IRIS_FRONTEND_NETWORK."
    return 0
  fi
  if docker network connect "$IRIS_FRONTEND_NETWORK" "$container" >/dev/null 2>&1; then
    info "Connected Wazuh manager container to IRIS frontend network: $IRIS_FRONTEND_NETWORK"
  else
    warn "Could not connect $container to $IRIS_FRONTEND_NETWORK. The integration may need a host-reachable IRIS URL."
  fi
}

update_wazuh_container_hook_url() {
  container=$1
  working_url=$2
  [ -n "$working_url" ] || return 1

  docker exec "$container" sh -lc '
    set -e
    py=/var/ossec/framework/python/bin/python3
    [ -x "$py" ] || py=$(command -v python3 || true)
    [ -n "$py" ] || { echo "[ERROR] python3 is required inside the Wazuh manager container."; exit 1; }
    "$py" - "$1" <<'"'"'PYCONF'"'"'
from pathlib import Path
import re
import sys

url = sys.argv[1]
conf = Path("/var/ossec/etc/ossec.conf")
text = conf.read_text(errors="ignore")
pattern = re.compile(r"(<integration>\s*.*?<name>\s*custom-wazuh_iris\.py\s*</name>.*?<hook_url>).*?(</hook_url>.*?</integration>)", re.S)
def repl(match):
    return match.group(1) + url + match.group(2)
text, count = pattern.subn(repl, text, count=1)
if count == 0:
    raise SystemExit("[ERROR] Could not find custom-wazuh_iris.py hook_url in /var/ossec/etc/ossec.conf")
conf.write_text(text)
PYCONF
  ' sh "$working_url"

  fragment_path="$DIR/integrations/wazuh/local-container/20-iris-integration.xml"
  if [ -f "$fragment_path" ] && have python3; then
    python3 - "$fragment_path" "$working_url" <<'PYFRAG'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
url = sys.argv[2]
text = path.read_text(errors="ignore")
text = re.sub(r"(<hook_url>).*?(</hook_url>)", lambda m: m.group(1) + url + m.group(2), text, count=1, flags=re.S)
path.write_text(text)
PYFRAG
  fi
}

default_wazuh_dashboard_url() {
  load_env
  if have docker; then
    dash=$(docker ps --format '{{.Names}}' | awk '/^wazuh-dashboard-/ {print; exit}' || true)
    [ -n "$dash" ] || dash=$(docker ps --format '{{.Names}}' | awk '/^modular-wazuh-dashboard$/ {print; exit}' || true)
    [ -n "$dash" ] || dash=$(docker ps --format '{{.Names}}' | awk '/^wazuh-dashboard$/ {print; exit}' || true)
    [ -n "$dash" ] || dash=$(docker ps --format '{{.Names}}' | awk 'tolower($0) ~ /wazuh/ && tolower($0) ~ /dashboard/ {print; exit}' || true)
    if [ -n "$dash" ]; then
      port=$(docker port "$dash" 5601/tcp 2>/dev/null | awk -F: 'NR==1 {print $NF}' || true)
      if [ -n "$port" ]; then
        printf 'https://%s:%s/app/wz-home\n' "${PUBLIC_HOST:-localhost}" "$port"
        return 0
      fi
    fi
  fi
  printf '%s\n' "https://wazuh.example/app/wz-home"
}

generate_wazuh_remote_bundle() {
  load_env
  ensure_wazuh_markdown_ui_patch "remote Wazuh manager bundle generation" || return 1

  bundle_root="$DIR/integrations/wazuh"
  ts=$(date +%Y%m%d_%H%M%S)
  bundle_dir="$bundle_root/remote-bundle-$ts"
  mkdir -p "$bundle_dir"

  customer_id=$(prompt_default "IRIS customer ID" "1")
  min_level=$(prompt_default "Minimum Wazuh alert level to forward" "7")
  case "$customer_id" in *[!0-9]*|"") die "IRIS customer ID must be numeric." ;; esac
  case "$min_level" in *[!0-9]*|"") die "Minimum Wazuh alert level must be numeric." ;; esac
  api_key=$(detect_iris_api_key || true)
  [ -n "$api_key" ] || die "Could not detect an IRIS API key from .env, saved credentials, or the running IRIS app container."

  iris_hook_url=$(prompt_default "IRIS hook URL reachable from Wazuh" "$(default_iris_hook_url)")
  dashboard_url=$(prompt_default "Wazuh dashboard source link" "$(default_wazuh_dashboard_url)")

  script_path="$bundle_dir/custom-wazuh_iris.py"
  fragment_path="$bundle_dir/20-iris-integration.xml"
  env_path="$bundle_dir/wazuh-iris.env"
  installer_path="$bundle_dir/install_on_wazuh_manager.sh"
  test_path="$bundle_dir/send_test_alert.sh"

  write_wazuh_iris_script "$script_path" "$customer_id" "$dashboard_url"
  python3 -m py_compile "$script_path"

  cat > "$fragment_path" <<EOF
<!-- IRIS integration: forward Wazuh alerts to DFIR-IRIS -->
<integration>
  <name>custom-wazuh_iris.py</name>
  <hook_url>${iris_hook_url}</hook_url>
  <level>${min_level}</level>
  <api_key>${api_key}</api_key>
  <alert_format>json</alert_format>
</integration>
EOF

  cat > "$env_path" <<EOF
IRIS_EXTERNAL_URL=${IRIS_EXTERNAL_URL}
IRIS_HOOK_URL=${iris_hook_url}
IRIS_API_KEY=${api_key}
IRIS_CUSTOMER_ID=${customer_id}
WAZUH_MIN_LEVEL=${min_level}
WAZUH_DASHBOARD_URL=${dashboard_url}
OSSEC_DIR=/var/ossec
OSSEC_CONF=/var/ossec/etc/ossec.conf
INTEGRATIONS_DIR=/var/ossec/integrations
EOF
  chmod 600 "$env_path" "$fragment_path"

  cat > "$installer_path" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$DIR"
[ "$(id -u)" -eq 0 ] || { echo "[ERROR] Run as root on the Wazuh manager."; exit 1; }
set -a
. "$DIR/wazuh-iris.env"
set +a
OSSEC_DIR=${OSSEC_DIR:-/var/ossec}
OSSEC_CONF=${OSSEC_CONF:-$OSSEC_DIR/etc/ossec.conf}
INTEGRATIONS_DIR=${INTEGRATIONS_DIR:-$OSSEC_DIR/integrations}
[ -d "$OSSEC_DIR" ] || { echo "[ERROR] Missing $OSSEC_DIR"; exit 1; }
[ -f "$OSSEC_CONF" ] || { echo "[ERROR] Missing $OSSEC_CONF"; exit 1; }
mkdir -p "$INTEGRATIONS_DIR"
install -m 750 "$DIR/custom-wazuh_iris.py" "$INTEGRATIONS_DIR/custom-wazuh_iris.py"
if getent group wazuh >/dev/null 2>&1; then
  chown root:wazuh "$INTEGRATIONS_DIR/custom-wazuh_iris.py" || true
else
  chown root:root "$INTEGRATIONS_DIR/custom-wazuh_iris.py" || true
fi
py=/var/ossec/framework/python/bin/python3
[ -x "$py" ] || py=$(command -v python3 || true)
[ -n "$py" ] || { echo "[ERROR] python3 is required on the Wazuh manager."; exit 1; }
"$py" -m py_compile "$INTEGRATIONS_DIR/custom-wazuh_iris.py"
backup="${OSSEC_CONF}.backup-before-iris-$(date +%Y%m%d_%H%M%S)"
cp "$OSSEC_CONF" "$backup"
"$py" - "$OSSEC_CONF" "$DIR/20-iris-integration.xml" <<'PYCONF'
from pathlib import Path
import re
import sys

conf = Path(sys.argv[1])
fragment = Path(sys.argv[2]).read_text().strip()
text = conf.read_text(errors="ignore")
pattern = re.compile(r"\n\s*<integration>\s*.*?<name>\s*custom-wazuh_iris\.py\s*</name>.*?</integration>\s*", re.S)
if pattern.search(text):
    text = pattern.sub("\n\n" + fragment + "\n\n", text, count=1)
else:
    if "</ossec_config>" not in text:
        raise SystemExit("[ERROR] Could not find </ossec_config>")
    text = text.replace("</ossec_config>", "\n\n" + fragment + "\n\n</ossec_config>", 1)
conf.write_text(text)
PYCONF
echo "[INFO] Wazuh to IRIS integration installed or updated. Backup: $backup"
EOF
  chmod 750 "$installer_path"

  cat > "$test_path" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$DIR"
set -a
. "$DIR/wazuh-iris.env"
set +a
test_file="/tmp/wazuh-iris-universal-test-alert.json"
test_id="manual-wazuh-iris-universal-$(date +%s)"
cat > "$test_file" <<JSON
{"id":"${test_id}","timestamp":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","rule":{"id":"999999","level":10,"description":"Universal Wazuh to IRIS integration test","groups":["manual_test","integration_test"],"mitre":{"id":["T0000"],"tactic":["Test"],"technique":["Manual test"]}},"agent":{"id":"000","name":"wazuh-manager","ip":"127.0.0.1"},"manager":{"name":"wazuh-manager"},"location":"manual-test","data":{"srcip":"203.0.113.50","srcuser":"admin","action":"manual-test"},"full_log":"Manual universal test alert generated for IRIS integration validation."}
JSON
py=/var/ossec/framework/python/bin/python3
[ -x "$py" ] || py=$(command -v python3 || true)
[ -n "$py" ] || { echo "[ERROR] python3 is required on the Wazuh manager."; exit 1; }
"$py" "$DIR/custom-wazuh_iris.py" "$test_file" "$IRIS_API_KEY" "$IRIS_HOOK_URL"
echo "[INFO] Sent test alert: $test_id"
EOF
  chmod 750 "$test_path"

  printf '\n[INFO] Wazuh remote bundle generated:\n  %s\n' "$bundle_dir"
  printf '\nCopy this directory to the Wazuh manager, then run as root:\n  ./install_on_wazuh_manager.sh\n'
}

install_wazuh_local_container() {
  load_env
  ensure_wazuh_markdown_ui_patch "local Wazuh container integration" || return 1

  wazuh_mode=$(choose_wazuh_topology_mode "lab-single-node")
  if [ "$wazuh_mode" = "opencti-only" ]; then
    info "opencti-only mode selected. No Wazuh changes will be made."
    return 0
  fi
  show_wazuh_topology
  mapfile -t containers < <(select_wazuh_manager_containers "$wazuh_mode")

  validated_containers=()
  seen_containers=""
  for container in "${containers[@]}"; do
    [ -n "$container" ] || continue
    case "
$seen_containers
" in
      *"
$container
"*) continue ;;
    esac
    validate_wazuh_manager_container "$container" || return 1
    validated_containers+=("$container")
    seen_containers="${seen_containers}
$container"
  done
  [ "${#validated_containers[@]}" -gt 0 ] || die "No Wazuh manager container selected."
  containers=("${validated_containers[@]}")

  customer_id=$(prompt_default "IRIS customer ID" "1")
  min_level=$(prompt_default "Minimum Wazuh alert level to forward" "7")
  case "$customer_id" in *[!0-9]*|"") die "IRIS customer ID must be numeric." ;; esac
  case "$min_level" in *[!0-9]*|"") die "Minimum Wazuh alert level must be numeric." ;; esac
  api_key=$(detect_iris_api_key || true)
  [ -n "$api_key" ] || die "Could not detect an IRIS API key from .env, saved credentials, or the running IRIS app container."

  iris_hook_url=$(prompt_default "IRIS hook URL reachable from the Wazuh container" "$(default_iris_container_hook_url)")
  dashboard_url=$(prompt_default "Wazuh dashboard source link" "$(default_wazuh_dashboard_url)")

  work_dir="$DIR/integrations/wazuh/local-container"
  mkdir -p "$work_dir"
  script_path="$work_dir/custom-wazuh_iris.py"
  fragment_path="$work_dir/20-iris-integration.xml"

  write_wazuh_iris_script "$script_path" "$customer_id" "$dashboard_url"
  python3 -m py_compile "$script_path"

  cat > "$fragment_path" <<EOF
<!-- IRIS integration: forward Wazuh alerts to DFIR-IRIS -->
<integration>
  <name>custom-wazuh_iris.py</name>
  <hook_url>${iris_hook_url}</hook_url>
  <level>${min_level}</level>
  <api_key>${api_key}</api_key>
  <alert_format>json</alert_format>
</integration>
EOF
  chmod 600 "$fragment_path"

  if ! confirm_wazuh_manager_targets "${containers[@]}"; then
    die "Cancelled Wazuh manager installation."
  fi

  for container in "${containers[@]}"; do
    validate_wazuh_manager_container "$container" || return 1
    connect_wazuh_container_to_iris_network "$container"

    info "Installing Wazuh integration into manager container: $container"
    docker exec "$container" sh -lc '
      set -e
      mkdir -p /var/ossec/integrations
      if [ -f /var/ossec/integrations/custom-wazuh_iris.py ]; then
        cp /var/ossec/integrations/custom-wazuh_iris.py "/var/ossec/integrations/custom-wazuh_iris.py.backup-before-iris-$(date +%Y%m%d_%H%M%S)"
      fi
    '
    docker cp "$script_path" "$container:/var/ossec/integrations/custom-wazuh_iris.py"
    docker cp "$fragment_path" "$container:/tmp/20-iris-integration.xml"
    docker exec "$container" sh -lc '
      set -e
      chmod 750 /var/ossec/integrations/custom-wazuh_iris.py
      if getent group wazuh >/dev/null 2>&1; then chown root:wazuh /var/ossec/integrations/custom-wazuh_iris.py || true; fi
      py=/var/ossec/framework/python/bin/python3
      [ -x "$py" ] || py=$(command -v python3 || true)
      [ -n "$py" ] || { echo "[ERROR] python3 is required inside the Wazuh manager container."; exit 1; }
      "$py" -m py_compile /var/ossec/integrations/custom-wazuh_iris.py
      conf=/var/ossec/etc/ossec.conf
      [ -f "$conf" ] || { echo "[ERROR] Missing $conf"; exit 1; }
      backup="$conf.backup-before-iris-$(date +%Y%m%d_%H%M%S)"
      cp "$conf" "$backup"
      "$py" - "$conf" /tmp/20-iris-integration.xml <<'"'"'PYCONF'"'"'
from pathlib import Path
import re
import sys

conf = Path(sys.argv[1])
fragment = Path(sys.argv[2]).read_text().strip()
text = conf.read_text(errors="ignore")
pattern = re.compile(r"\n\s*<integration>\s*.*?<name>\s*custom-wazuh_iris\.py\s*</name>.*?</integration>\s*", re.S)
if pattern.search(text):
    text = pattern.sub("\n\n" + fragment + "\n\n", text, count=1)
else:
    if "</ossec_config>" not in text:
        raise SystemExit("[ERROR] Could not find </ossec_config>")
    text = text.replace("</ossec_config>", "\n\n" + fragment + "\n\n</ossec_config>", 1)
conf.write_text(text)
PYCONF
      echo "[INFO] Wazuh to IRIS integration installed or updated. Backup: $backup"
    '

    if prompt_yes_no "Restart Wazuh services inside $container now?"; then
      if ! docker exec "$container" /var/ossec/bin/wazuh-control restart; then
        warn "Wazuh restart failed for $container. Integration files were installed; restart that Wazuh manager manually after reviewing container logs."
      fi
    else
      warn "Restart skipped for $container. Wazuh will not load the integration until that manager is restarted."
    fi

    if prompt_yes_no "Send a manual Wazuh test alert from $container to IRIS now?"; then
      if ! send_wazuh_container_test_alert "$container" "$iris_hook_url"; then
        warn "Manual Wazuh container test failed for $container, but integration files were installed. Review the diagnostics above and rerun ./setup.sh wazuh-test or this menu option after fixing reachability/API settings."
      fi
    fi
  done

  info "Local Wazuh container integration finished."
}

rollback_wazuh_local_container() {
  load_env
  wazuh_mode=$(choose_wazuh_topology_mode "lab-single-node")
  if [ "$wazuh_mode" = "opencti-only" ]; then
    info "opencti-only mode selected. No Wazuh changes will be made."
    return 0
  fi
  show_wazuh_topology
  mapfile -t containers < <(select_wazuh_manager_containers "$wazuh_mode")

  validated_containers=()
  seen_containers=""
  for container in "${containers[@]}"; do
    [ -n "$container" ] || continue
    case "
$seen_containers
" in
      *"
$container
"*) continue ;;
    esac
    validate_wazuh_manager_container "$container" || return 1
    validated_containers+=("$container")
    seen_containers="${seen_containers}
$container"
  done
  [ "${#validated_containers[@]}" -gt 0 ] || die "No Wazuh manager container selected."
  containers=("${validated_containers[@]}")

  printf '\nSelected Wazuh manager container rollback target(s):\n' >&2
  for container in "${containers[@]}"; do
    printf '  - %s\n' "$container" >&2
  done
  printf '\nRollback will restore the latest /var/ossec/etc/ossec.conf.backup-before-iris-* file when available.\n' >&2
  printf 'It will restore the latest custom-wazuh_iris.py backup when available; otherwise it will remove the custom script.\n' >&2
  printf 'Dashboard and indexer containers will not be modified.\n' >&2
  if ! prompt_yes_no "Proceed with Wazuh manager rollback for the selected container(s)?" >&2; then
    die "Cancelled Wazuh rollback."
  fi

  for container in "${containers[@]}"; do
    validate_wazuh_manager_container "$container" || return 1
    info "Rolling back Wazuh integration on manager container: $container"
    docker exec "$container" sh -lc '
      set -e
      conf=/var/ossec/etc/ossec.conf
      current_backup="$conf.backup-before-iris-rollback-$(date +%Y%m%d_%H%M%S)"
      latest_conf=$(ls -t "$conf".backup-before-iris-* 2>/dev/null | grep -v "rollback" | head -1 || true)
      if [ -n "$latest_conf" ]; then
        cp "$conf" "$current_backup"
        cp "$latest_conf" "$conf"
        echo "[INFO] Restored $conf from $latest_conf. Current file backup: $current_backup"
      else
        echo "[WARN] No ossec.conf.backup-before-iris-* file found; ossec.conf was not changed."
      fi

      script=/var/ossec/integrations/custom-wazuh_iris.py
      latest_script=$(ls -t "$script".backup-before-iris-* 2>/dev/null | head -1 || true)
      if [ -n "$latest_script" ]; then
        cp "$latest_script" "$script"
        chmod 750 "$script"
        if getent group wazuh >/dev/null 2>&1; then chown root:wazuh "$script" || true; fi
        echo "[INFO] Restored $script from $latest_script"
      elif [ -f "$script" ]; then
        rm -f "$script"
        echo "[INFO] Removed $script because no previous script backup was found."
      else
        echo "[INFO] No custom Wazuh IRIS script found to roll back."
      fi
    '

    if prompt_yes_no "Restart Wazuh services inside $container now after rollback?"; then
      if ! docker exec "$container" /var/ossec/bin/wazuh-control restart; then
        warn "Wazuh restart failed for $container. Review container logs and restart manually."
      fi
    else
      warn "Restart skipped for $container. Rollback changes may not take effect until that manager is restarted."
    fi
  done

  info "Local Wazuh manager rollback finished."
}

send_wazuh_container_test_alert() {
  container=$1
  iris_hook_url=$2
  api_key=$(detect_iris_api_key || true)
  if [ -z "$api_key" ]; then
    warn "Could not detect an IRIS API key from .env, saved credentials, or the running IRIS app container."
    return 1
  fi

  work_dir="$DIR/integrations/wazuh/local-container"
  mkdir -p "$work_dir"
  test_path="$work_dir/container-test-alert.json"
  log_path="$work_dir/last-container-test.log"
  test_id="manual-wazuh-container-iris-$(date +%s)"

  cat > "$test_path" <<EOF
{"id":"${test_id}","timestamp":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","rule":{"id":"999999","level":10,"description":"Manual Wazuh container to IRIS integration test","groups":["manual_test","integration_test"],"mitre":{"id":["T0000"],"tactic":["Test"],"technique":["Manual test"]}},"agent":{"id":"000","name":"wazuh-manager","ip":"127.0.0.1"},"manager":{"name":"wazuh-manager"},"location":"manual-test","data":{"srcip":"203.0.113.50","srcuser":"admin","action":"manual-test","path":"container-runtime"},"full_log":"Manual test alert generated by setup.sh from inside the Wazuh manager container."}
EOF

  docker cp "$test_path" "$container:/tmp/wazuh-iris-container-test-alert.json" || {
    warn "Could not copy the test alert into the Wazuh manager container."
    return 1
  }

  : >"$log_path"
  success=0
  working_url=""
  repaired_gateway=0

  while IFS= read -r candidate_url; do
    [ -n "$candidate_url" ] || continue
    info "Sending manual test alert from Wazuh container using: $candidate_url"
    {
      printf '\n==== Attempt: %s ====\n' "$candidate_url"
      docker exec "$container" sh -lc '
        py=/var/ossec/framework/python/bin/python3
        [ -x "$py" ] || py=$(command -v python3 || true)
        [ -n "$py" ] || { echo "[ERROR] python3 is required inside the Wazuh manager container."; exit 1; }
        WAZUH_IRIS_LOG_STDERR=1 "$py" /var/ossec/integrations/custom-wazuh_iris.py /tmp/wazuh-iris-container-test-alert.json "$1" "$2"
      ' sh "$api_key" "$candidate_url"
    } >>"$log_path" 2>&1 && {
      success=1
      working_url=$candidate_url
      break
    }

    warn "Attempt failed for Wazuh container hook URL: $candidate_url"
    docker exec "$container" sh -lc 'if [ -f /var/ossec/logs/integrations.log ]; then echo "---- Wazuh integrations.log tail ----"; tail -n 30 /var/ossec/logs/integrations.log; fi' >>"$log_path" 2>/dev/null || true
    tail -n 20 "$log_path" | sed 's/^/  /' >&2 || true

    if [ "$repaired_gateway" -eq 0 ] && iris_gateway_failure_seen "$log_path"; then
      repaired_gateway=1
      if repair_iris_gateway_if_needed "$log_path"; then
        info "Retrying after IRIS gateway recovery: $candidate_url"
        {
          printf '\n==== Retry after IRIS recovery: %s ====\n' "$candidate_url"
          docker exec "$container" sh -lc '
            py=/var/ossec/framework/python/bin/python3
            [ -x "$py" ] || py=$(command -v python3 || true)
            [ -n "$py" ] || { echo "[ERROR] python3 is required inside the Wazuh manager container."; exit 1; }
            WAZUH_IRIS_LOG_STDERR=1 "$py" /var/ossec/integrations/custom-wazuh_iris.py /tmp/wazuh-iris-container-test-alert.json "$1" "$2"
          ' sh "$api_key" "$candidate_url"
        } >>"$log_path" 2>&1 && {
          success=1
          working_url=$candidate_url
          break
        }
      fi
    fi
  done <<EOF
$(iris_container_hook_url_candidates "$iris_hook_url")
EOF

  if [ "$success" -eq 1 ]; then
    info "Manual Wazuh container test alert sent. Open IRIS > Alerts and look for: $test_id"
    if [ "$working_url" != "$iris_hook_url" ]; then
      warn "The original hook URL failed, but a working IRIS URL was found: $working_url"
      if update_wazuh_container_hook_url "$container" "$working_url"; then
        info "Updated Wazuh ossec.conf hook_url to the working IRIS URL."
        if prompt_yes_no "Restart Wazuh services inside $container now to load the working hook URL?"; then
          docker exec "$container" /var/ossec/bin/wazuh-control restart >/dev/null 2>&1 || warn "Wazuh restart after hook URL update failed. Restart Wazuh manually before relying on the integration."
        else
          warn "Restart skipped for $container. Restart that Wazuh manager manually before relying on the updated hook URL."
        fi
      else
        warn "Could not update Wazuh hook_url automatically. Set it manually to: $working_url"
      fi
    fi
    return 0
  fi

  warn "Manual Wazuh container test failed after trying available IRIS URLs. Log: $log_path"
  docker exec "$container" sh -lc 'if [ -f /var/ossec/logs/integrations.log ]; then tail -n 40 /var/ossec/logs/integrations.log; fi' >>"$log_path" 2>/dev/null || true
  tail -n 60 "$log_path" | sed 's/^/  /' >&2 || true
  return 1
}

send_wazuh_test_alert() {
  load_env
  ensure_wazuh_markdown_ui_patch "manual Wazuh test alert" || return 1

  iris_hook_url=${1:-}
  dashboard_url=${2:-}
  customer_id=${3:-}

  [ -n "$iris_hook_url" ] || iris_hook_url=$(prompt_default "IRIS hook URL reachable from this host" "$(default_iris_hook_url)")
  [ -n "$dashboard_url" ] || dashboard_url=$(prompt_default "Wazuh dashboard source link" "$(default_wazuh_dashboard_url)")
  [ -n "$customer_id" ] || customer_id=$(prompt_default "IRIS customer ID" "1")
  api_key=$(detect_iris_api_key || true)
  if [ -z "$api_key" ]; then
    warn "Could not detect an IRIS API key from .env, saved credentials, or the running IRIS app container."
    return 1
  fi

  work_dir="$DIR/integrations/wazuh/tester"
  mkdir -p "$work_dir"
  script_path="$work_dir/custom-wazuh_iris.py"
  test_path="$work_dir/test-alert.json"
  log_path="$work_dir/last-test.log"
  test_id="manual-wazuh-iris-$(date +%s)"

  write_wazuh_iris_script "$script_path" "$customer_id" "$dashboard_url"
  python3 -m py_compile "$script_path"

  cat > "$test_path" <<EOF
{"id":"${test_id}","timestamp":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","rule":{"id":"999999","level":10,"description":"Manual Wazuh to IRIS integration test","groups":["manual_test","integration_test"],"mitre":{"id":["T0000"],"tactic":["Test"],"technique":["Manual test"]}},"agent":{"id":"000","name":"wazuh-manager","ip":"127.0.0.1"},"manager":{"name":"wazuh-manager"},"location":"manual-test","data":{"srcip":"203.0.113.50","srcuser":"admin","action":"manual-test"},"full_log":"Manual test alert generated by setup.sh."}
EOF

  success=0
  while IFS= read -r candidate_url; do
    [ -n "$candidate_url" ] || continue
    info "Trying IRIS hook URL: $candidate_url"
    if python3 "$script_path" "$test_path" "$api_key" "$candidate_url" >"$log_path" 2>&1; then
      info "Manual test alert sent. Open IRIS > Alerts and look for: $test_id"
      success=1
      break
    fi
    warn "Attempt failed for: $candidate_url"
    sed 's/^/  /' "$log_path" >&2 || true
    if iris_gateway_failure_seen "$log_path"; then
      if repair_iris_gateway_if_needed "$log_path"; then
        info "Retrying IRIS hook URL after gateway recovery: $candidate_url"
        if python3 "$script_path" "$test_path" "$api_key" "$candidate_url" >"$log_path" 2>&1; then
          info "Manual test alert sent. Open IRIS > Alerts and look for: $test_id"
          success=1
          break
        fi
        warn "Retry failed for: $candidate_url"
        sed 's/^/  /' "$log_path" >&2 || true
      fi
    fi
  done <<EOF
$(iris_hook_url_candidates "$iris_hook_url")
EOF

  if [ "$success" -eq 0 ]; then
    warn "Manual test failed after trying available IRIS hook URLs. Last log: $log_path"
    return 1
  fi
}

wazuh_markdown_patch_present() {
  iris_container_check
  docker exec -i iriswebapp_app python3 - <<'PYCHECK' >/dev/null 2>&1
from pathlib import Path

alerts = Path("/iriswebapp/app/static/assets/js/iris/alerts.js")
case_summary = Path("/iriswebapp/app/static/assets/js/iris/case.summary.js")
if not alerts.exists():
    raise SystemExit(1)

alerts_text = alerts.read_text(errors="ignore")
alerts_ok = (
    "IRIS_WAZUH_MARKDOWN_RENDER_START" in alerts_text
    and "renderAlertMarkdown" in alerts_text
)

case_ok = True
if case_summary.exists():
    case_text = case_summary.read_text(errors="ignore")
    case_ok = "IRIS_WAZUH_MARKDOWN_CASE_STYLE_START" in case_text

raise SystemExit(0 if alerts_ok and case_ok else 1)
PYCHECK
}

ensure_wazuh_markdown_ui_patch() {
  reason=${1:-Wazuh integration}
  load_env
  if ! ensure_iris_app_ready "$reason"; then
    return 1
  fi

  if wazuh_markdown_patch_present; then
    info "Required Wazuh markdown UI patch is already applied."
    return 0
  fi

  info "Applying required Wazuh markdown UI patch for $reason."
  if ! apply_wazuh_markdown_patch; then
    warn "Required Wazuh markdown UI patch failed."
    return 1
  fi
  if ! ensure_iris_app_ready "Wazuh markdown UI patch restart"; then
    return 1
  fi
  if ! wazuh_markdown_patch_present; then
    warn "Wazuh markdown UI patch did not verify after applying."
    return 1
  fi
  info "Required Wazuh markdown UI patch verified."
}

apply_wazuh_markdown_patch() {
  load_env
  iris_container_check

  tmp_py="/tmp/apply_wazuh_markdown_patch.py"
  cat > "$tmp_py" <<'PYFRONT'
from pathlib import Path
from datetime import datetime
import re
import shutil

ALERTS = Path("/iriswebapp/app/static/assets/js/iris/alerts.js")
CASE_SUMMARY = Path("/iriswebapp/app/static/assets/js/iris/case.summary.js")
START = "/* IRIS_WAZUH_MARKDOWN_RENDER_START */"
END = "/* IRIS_WAZUH_MARKDOWN_RENDER_END */"
CASE_START = "/* IRIS_WAZUH_MARKDOWN_CASE_STYLE_START */"
CASE_END = "/* IRIS_WAZUH_MARKDOWN_CASE_STYLE_END */"


def backup(path):
    stamp = datetime.now().strftime("%Y%m%d%H%M%S")
    dst = path.with_name(path.name + ".backup-wazuh-md-" + stamp)
    shutil.copy2(path, dst)
    print(f"[INFO] Backup: {dst}")


def remove_between(text, start, end):
    while start in text and end in text:
        a = text.index(start)
        b = text.index(end) + len(end)
        text = text[:a] + "\n" + text[b:]
    return text


RENDER_BLOCK = r'''
/* IRIS_WAZUH_MARKDOWN_RENDER_START */
function irisWazuhMdEscape(value) {
    return String(value ?? '')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
}

function irisWazuhMdInline(value) {
    return irisWazuhMdEscape(value)
        .replace(/`([^`]+)`/g, '<code>$1</code>')
        .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
}

function irisWazuhMdIsSeparator(line) {
    return /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)+\|?\s*$/.test(line);
}

function irisWazuhMdSplitRow(line) {
    let clean = String(line || '').trim();
    if (clean.startsWith('|')) clean = clean.slice(1);
    if (clean.endsWith('|')) clean = clean.slice(0, -1);
    return clean.split('|').map(cell => cell.trim().replaceAll('<br>', '\n'));
}

function irisWazuhMdRenderTable(lines, startIndex) {
    const header = irisWazuhMdSplitRow(lines[startIndex]);
    const rows = [];
    let i = startIndex + 2;
    while (i < lines.length && lines[i].trim().startsWith('|')) {
        if (!irisWazuhMdIsSeparator(lines[i])) rows.push(irisWazuhMdSplitRow(lines[i]));
        i++;
    }
    let html = '<div class="iris-wazuh-md-table-wrap"><table class="iris-wazuh-md-table"><thead><tr>';
    header.forEach(cell => { html += '<th>' + irisWazuhMdInline(cell) + '</th>'; });
    html += '</tr></thead><tbody>';
    rows.forEach(row => {
        html += '<tr>';
        header.forEach((_, idx) => { html += '<td>' + irisWazuhMdInline(row[idx] || '').replaceAll('\n', '<br>') + '</td>'; });
        html += '</tr>';
    });
    html += '</tbody></table></div>';
    return {html: html, nextIndex: i};
}

function irisWazuhInstallMarkdownStyle() {
    if (document.getElementById('iris-wazuh-md-style')) return;
    const style = document.createElement('style');
    style.id = 'iris-wazuh-md-style';
    style.textContent = `
        .iris-wazuh-md-rendered{width:100%!important;max-width:none!important;color:#101828;font-size:14px;line-height:1.55}
        .iris-wazuh-md-rendered h2{position:relative;margin:24px 0 12px;padding:0 0 9px 14px;border-bottom:1px solid #e4e7ec;color:#101828;font-size:17px;font-weight:800}
        .iris-wazuh-md-rendered h2:before{content:"";position:absolute;left:0;top:2px;width:4px;height:20px;border-radius:999px;background:#1572e8}
        .iris-wazuh-md-rendered p{margin:8px 0 12px;color:#344054}
        .iris-wazuh-md-table-wrap{width:100%!important;overflow-x:auto;margin:10px 0 22px;border:1px solid #d0d5dd;border-radius:10px;background:#fff;box-shadow:0 4px 14px rgba(16,24,40,.04)}
        .iris-wazuh-md-table{width:100%!important;min-width:640px;border-collapse:separate;border-spacing:0;table-layout:fixed!important;margin:0;background:#fff}
        .iris-wazuh-md-table th{padding:11px 14px;background:#f8fafc;color:#344054;font-size:12px;font-weight:800;text-transform:uppercase;letter-spacing:.045em;border-bottom:1px solid #d0d5dd;text-align:left}
        .iris-wazuh-md-table td{padding:12px 14px;border-bottom:1px solid #eaecf0;color:#101828;font-size:14px;vertical-align:middle;word-break:break-word;overflow-wrap:anywhere}
        .iris-wazuh-md-table tr:nth-child(even) td{background:#fcfcfd}
        .iris-wazuh-md-table tr:last-child td{border-bottom:0}
        .iris-wazuh-md-table th:first-child,.iris-wazuh-md-table td:first-child{width:260px!important;color:#344054;font-weight:700;background:#f8fafc;border-right:1px solid #eaecf0}
        .iris-wazuh-md-rendered code{display:inline-block;padding:2px 6px;border-radius:6px;background:#f2f4f7;color:#344054;font-size:12px;border:1px solid #e4e7ec}
        .iris-wazuh-md-rendered pre{margin:8px 0 18px;padding:12px 14px;border-radius:10px;border:1px solid #1e293b;background:#0f172a;color:#e5e7eb;overflow-x:auto;white-space:pre-wrap;word-break:break-word;font-size:12px;line-height:1.5}
    `;
    document.head.appendChild(style);
}

function renderAlertMarkdown(markdownText) {
    irisWazuhInstallMarkdownStyle();
    const lines = String(markdownText || 'No description provided').replaceAll('\r\n', '\n').replaceAll('\r', '\n').split('\n');
    let html = '<div class="iris-wazuh-md-rendered">';
    let i = 0;
    let inCode = false;
    let codeLines = [];
    while (i < lines.length) {
        const line = lines[i];
        const trimmed = line.trim();
        if (trimmed.startsWith('```')) {
            if (!inCode) {
                inCode = true;
                codeLines = [];
            } else {
                html += '<pre>' + irisWazuhMdEscape(codeLines.join('\n')) + '</pre>';
                inCode = false;
            }
            i++;
            continue;
        }
        if (inCode) {
            codeLines.push(line);
            i++;
            continue;
        }
        if (trimmed === '') { i++; continue; }
        if (i + 1 < lines.length && trimmed.startsWith('|') && irisWazuhMdIsSeparator(lines[i + 1])) {
            const rendered = irisWazuhMdRenderTable(lines, i);
            html += rendered.html;
            i = rendered.nextIndex;
            continue;
        }
        if (trimmed.startsWith('## ')) html += '<h2>' + irisWazuhMdInline(trimmed.slice(3)) + '</h2>';
        else if (trimmed.startsWith('# ')) html += '<h2>' + irisWazuhMdInline(trimmed.slice(2)) + '</h2>';
        else html += '<p>' + irisWazuhMdInline(trimmed) + '</p>';
        i++;
    }
    if (inCode) html += '<pre>' + irisWazuhMdEscape(codeLines.join('\n')) + '</pre>';
    html += '</div>';
    return html;
}
/* IRIS_WAZUH_MARKDOWN_RENDER_END */
'''


CASE_BLOCK = r'''
/* IRIS_WAZUH_MARKDOWN_CASE_STYLE_START */
(function () {
    function installStyle() {
        if (document.getElementById('iris-wazuh-case-md-style')) return;
        const style = document.createElement('style');
        style.id = 'iris-wazuh-case-md-style';
        style.textContent = `
            #editor_summary table:not(.dataTable),#case_summary_card table:not(.dataTable){width:100%!important;min-width:640px!important;table-layout:fixed!important;border-collapse:separate!important;border-spacing:0!important;margin:10px 0 24px!important;background:#fff!important;border:1px solid #d0d5dd!important;border-radius:10px!important;overflow:hidden!important}
            #editor_summary table:not(.dataTable) th,#case_summary_card table:not(.dataTable) th{padding:11px 14px!important;background:#f8fafc!important;color:#344054!important;font-size:12px!important;font-weight:800!important;text-transform:uppercase!important;border-bottom:1px solid #d0d5dd!important;text-align:left!important}
            #editor_summary table:not(.dataTable) td,#case_summary_card table:not(.dataTable) td{padding:12px 14px!important;border-bottom:1px solid #eaecf0!important;color:#101828!important;font-size:14px!important;line-height:1.55!important;vertical-align:middle!important;word-break:break-word!important;overflow-wrap:anywhere!important}
            #editor_summary pre,#case_summary_card pre{margin:8px 0 18px!important;padding:12px 14px!important;border-radius:10px!important;border:1px solid #1e293b!important;background:#0f172a!important;color:#e5e7eb!important;overflow-x:auto!important;white-space:pre-wrap!important;word-break:break-word!important;font-size:12px!important;line-height:1.5!important}
        `;
        document.head.appendChild(style);
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', installStyle, {once: true});
    else installStyle();
    window.addEventListener('load', installStyle, {once: true});
})();
/* IRIS_WAZUH_MARKDOWN_CASE_STYLE_END */
'''


def patch_alerts():
    if not ALERTS.exists():
        raise SystemExit(f"[ERROR] Missing {ALERTS}")
    text = ALERTS.read_text(errors="ignore")
    backup(ALERTS)
    text = remove_between(text, START, END)
    text = RENDER_BLOCK + "\n\n" + text
    patterns = [
        (r"\$\{alert\.alert_description\.replaceAll\([^\}]+?\)\}", "${renderAlertMarkdown(alert.alert_description)}"),
        (r"\$\{filterXSS\(alert\.alert_description\)\}", "${renderAlertMarkdown(alert.alert_description)}"),
        (r"\$\{alert\.alert_description\s*\|\|\s*['\"]No description provided['\"]\}", "${renderAlertMarkdown(alert.alert_description)}"),
        (r"\$\{alert\.alert_description\}", "${renderAlertMarkdown(alert.alert_description)}"),
    ]
    changed = False
    for pattern, repl in patterns:
        new_text = re.sub(pattern, repl, text, flags=re.S)
        if new_text != text:
            text = new_text
            changed = True
    if not changed and "renderAlertMarkdown(alert.alert_description)" not in text:
        raise SystemExit("[ERROR] Could not find alert.alert_description renderer in alerts.js")
    ALERTS.write_text(text)
    print(f"[INFO] Patched {ALERTS}")


def patch_case_summary():
    if not CASE_SUMMARY.exists():
        print(f"[WARN] Missing {CASE_SUMMARY}. Skipping case summary style.")
        return
    text = CASE_SUMMARY.read_text(errors="ignore")
    backup(CASE_SUMMARY)
    text = remove_between(text, CASE_START, CASE_END).rstrip() + "\n\n" + CASE_BLOCK + "\n"
    CASE_SUMMARY.write_text(text)
    print(f"[INFO] Patched {CASE_SUMMARY}")


patch_alerts()
patch_case_summary()
print("[INFO] Wazuh alert markdown UI patch applied.")
PYFRONT

  docker cp "$tmp_py" iriswebapp_app:/tmp/apply_wazuh_markdown_patch.py
  docker exec iriswebapp_app python3 /tmp/apply_wazuh_markdown_patch.py
  docker restart iriswebapp_app iriswebapp_nginx >/dev/null
  info "Wazuh markdown UI patch applied and IRIS app/nginx restarted."
}

rollback_wazuh_markdown_patch() {
  iris_container_check

  tmp_py="/tmp/rollback_wazuh_markdown_patch.py"
  cat > "$tmp_py" <<'PYROLL'
from pathlib import Path

targets = [
    Path("/iriswebapp/app/static/assets/js/iris/alerts.js"),
    Path("/iriswebapp/app/static/assets/js/iris/case.summary.js"),
]

for path in targets:
    if not path.exists():
        print(f"[WARN] Missing {path}")
        continue
    backups = sorted(path.parent.glob(path.name + ".backup-wazuh-md-*"))
    if backups:
        original = backups[0]
        path.write_bytes(original.read_bytes())
        print(f"[INFO] Restored {path} from {original}")
    else:
        text = path.read_text(errors="ignore")
        for start, end in [
            ("/* IRIS_WAZUH_MARKDOWN_RENDER_START */", "/* IRIS_WAZUH_MARKDOWN_RENDER_END */"),
            ("/* IRIS_WAZUH_MARKDOWN_CASE_STYLE_START */", "/* IRIS_WAZUH_MARKDOWN_CASE_STYLE_END */"),
        ]:
            while start in text and end in text:
                a = text.index(start)
                b = text.index(end) + len(end)
                text = text[:a] + "\n" + text[b:]
        path.write_text(text)
        print(f"[INFO] Removed markdown markers from {path}")
PYROLL

  docker cp "$tmp_py" iriswebapp_app:/tmp/rollback_wazuh_markdown_patch.py
  docker exec iriswebapp_app python3 /tmp/rollback_wazuh_markdown_patch.py
  docker restart iriswebapp_app iriswebapp_nginx >/dev/null
  info "Wazuh markdown UI patch rollback completed and IRIS app/nginx restarted."
}

OPENCTI_BRIDGE_DIR="/opt/opencti-iris-bridge"
OPENCTI_STAGING_DIR="$OPENCTI_BRIDGE_DIR/.staging"
OPENCTI_ENV_DIR="/etc/opencti-iris-bridge"
OPENCTI_ENV_FILE="$OPENCTI_ENV_DIR/opencti-iris-bridge.env"
OPENCTI_ENV_PENDING="$OPENCTI_ENV_DIR/opencti-iris-bridge.env.pending"
OPENCTI_CONTROL_ENV="$OPENCTI_ENV_DIR/control-api.env"
OPENCTI_CONTROL_PENDING="$OPENCTI_ENV_DIR/control-api.env.pending"
OPENCTI_STATE_DIR="/var/lib/opencti-iris-bridge"
OPENCTI_STATE_DB="$OPENCTI_STATE_DIR/state.sqlite3"
OPENCTI_WATCHLIST="$OPENCTI_STATE_DIR/enabled_cases.json"
OPENCTI_ACTIVATION_STATUS="$OPENCTI_STATE_DIR/activation-status.json"
OPENCTI_LOG_DIR="/var/log/opencti-iris-bridge"
OPENCTI_BRIDGE_LOG="$OPENCTI_LOG_DIR/bridge.log"
OPENCTI_REPORT_TXT="$OPENCTI_LOG_DIR/install-report.txt"
OPENCTI_REPORT_JSON="$OPENCTI_LOG_DIR/install-report.json"
OPENCTI_CAPABILITIES="$OPENCTI_STATE_DIR/opencti-capabilities.json"
OPENCTI_LAST_PREFLIGHT="$OPENCTI_STATE_DIR/last-preflight.json"
OPENCTI_LAST_DRY_RUN="$OPENCTI_STATE_DIR/last-dry-run.json"
OPENCTI_LAST_LIVE_WRITE="$OPENCTI_STATE_DIR/last-live-write.json"
OPENCTI_CORE_DIR="$OPENCTI_BRIDGE_DIR/opencti_iris_bridge_core"
OPENCTI_SERVICE_USER="opencti-iris-bridge"
OPENCTI_CORE="$OPENCTI_BRIDGE_DIR/opencti_iris_bridge.py"
OPENCTI_RUNNER="$OPENCTI_BRIDGE_DIR/opencti_iris_bridge_runner.py"
OPENCTI_API="$OPENCTI_BRIDGE_DIR/opencti_iris_bridge_control_api.py"
OPENCTI_BRIDGE_VERSION="2.0.0"
OPENCTI_REQUIRED_RUNNER_FLAGS="
--env-file
--preflight
--component
--once
--dry-run
--state-check
--state-migrate
--case-id
--ioc-id
--force
--list-enabled
--enable-case
--disable-case
--clear-enabled
--version
"

opencti_require_root() {
  [ "$(id -u)" -eq 0 ] || die "Run this OpenCTI bridge action as root or with sudo."
}

opencti_env_value() {
  key=$1
  file=${2:-$OPENCTI_ENV_FILE}
  [ -f "$file" ] || return 1
  awk -v k="$key" 'BEGIN { FS="=" } $1 == k { sub(/^[^=]*=/, ""); print; exit }' "$file"
}

opencti_prompt_secret() {
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

opencti_random_token() {
  if have openssl; then
    openssl rand -hex 32
  else
    python3 - <<'PYTOKEN'
import secrets
print(secrets.token_hex(32))
PYTOKEN
  fi
}

opencti_default_iris_url() {
  load_env
  if [ -n "${IRIS_EXTERNAL_URL:-}" ]; then
    printf '%s\n' "${IRIS_EXTERNAL_URL%/}"
    return 0
  fi
  if port=$(detect_iris_nginx_port 2>/dev/null); then
    printf 'https://127.0.0.1:%s\n' "$port"
    return 0
  fi
  printf 'https://127.0.0.1:%s\n' "${INTERFACE_HTTPS_PORT:-443}"
}

opencti_url_host() {
  python3 - "$1" <<'PY'
import sys
from urllib.parse import urlsplit

value = (sys.argv[1] if len(sys.argv) > 1 else "").strip()
if not value:
    raise SystemExit(1)
parsed = urlsplit(value if "://" in value else "//" + value)
host = parsed.hostname or ""
if not host:
    raise SystemExit(1)
print(host)
PY
}

opencti_is_usable_bind_host() {
  case "${1:-}" in
    ""|localhost|localhost.localdomain|127.*|0.0.0.0|::1)
      return 1
      ;;
  esac
  return 0
}

opencti_resolve_ipv4() {
  host=${1:-}
  [ -n "$host" ] || return 1
  case "$host" in
    *[!0-9.]*)
      if have getent; then
        getent ahostsv4 "$host" 2>/dev/null | awk '{print $1; exit}'
      else
        return 1
      fi
      ;;
    *)
      printf '%s\n' "$host"
      ;;
  esac
}

opencti_detect_iris_host_ip() {
  load_env
  candidates=""
  if [ -n "${PUBLIC_HOST:-}" ]; then
    candidates="${candidates}${PUBLIC_HOST}
"
  fi
  if [ -n "${IRIS_EXTERNAL_URL:-}" ]; then
    host=$(opencti_url_host "$IRIS_EXTERNAL_URL" 2>/dev/null || true)
    [ -n "$host" ] && candidates="${candidates}${host}
"
  fi
  if [ -f "$OPENCTI_ENV_FILE" ]; then
    iris_url=$(opencti_env_value IRIS_URL "$OPENCTI_ENV_FILE" 2>/dev/null || true)
    if [ -n "$iris_url" ]; then
      host=$(opencti_url_host "$iris_url" 2>/dev/null || true)
      [ -n "$host" ] && candidates="${candidates}${host}
"
    fi
  fi
  if have hostname; then
    for ip in $(hostname -I 2>/dev/null || true); do
      candidates="${candidates}${ip}
"
    done
  fi
  if have ip; then
    route_ip=$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}' || true)
    [ -n "$route_ip" ] && candidates="${candidates}${route_ip}
"
  fi
  if [ -f "$OPENCTI_CONTROL_ENV" ]; then
    current_bind=$(opencti_env_value CONTROL_BIND_HOST "$OPENCTI_CONTROL_ENV" 2>/dev/null || true)
    [ -n "$current_bind" ] && candidates="${candidates}${current_bind}
"
  fi

  printf '%s' "$candidates" | while IFS= read -r candidate; do
    [ -n "$candidate" ] || continue
    resolved=$(opencti_resolve_ipv4 "$candidate" | head -n 1 || true)
    if opencti_is_usable_bind_host "$resolved"; then
      printf '%s\n' "$resolved"
      return 0
    fi
  done
}

opencti_default_iris_token() {
  detect_iris_api_key || true
}

opencti_validate_uint() {
  label=$1
  value=$2
  case "$value" in
    *[!0-9]*|"") die "$label must be a positive integer or zero." ;;
  esac
}

opencti_prepare_dirs() {
  opencti_require_root
  mkdir -p "$OPENCTI_BRIDGE_DIR" "$OPENCTI_ENV_DIR" "$OPENCTI_STATE_DIR" "$OPENCTI_LOG_DIR"
  touch "$OPENCTI_BRIDGE_LOG"
  chmod 750 "$OPENCTI_BRIDGE_DIR" "$OPENCTI_ENV_DIR" "$OPENCTI_STATE_DIR" "$OPENCTI_LOG_DIR"
  chmod 640 "$OPENCTI_BRIDGE_LOG"
}

opencti_service_group() {
  id -gn "$OPENCTI_SERVICE_USER" 2>/dev/null || printf '%s\n' "$OPENCTI_SERVICE_USER"
}

opencti_fix_env_permissions() {
  opencti_require_root
  service_group=""
  mkdir -p "$OPENCTI_ENV_DIR"
  chmod 750 "$OPENCTI_ENV_DIR"
  if id "$OPENCTI_SERVICE_USER" >/dev/null 2>&1; then
    service_group=$(opencti_service_group)
    chown root:"$service_group" "$OPENCTI_ENV_DIR"
    for file in "$OPENCTI_ENV_FILE" "$OPENCTI_CONTROL_ENV"; do
      if [ -f "$file" ]; then
        chown root:"$service_group" "$file"
        chmod 640 "$file"
      fi
    done
  else
    for file in "$OPENCTI_ENV_FILE" "$OPENCTI_CONTROL_ENV"; do
      [ -f "$file" ] && chmod 600 "$file"
    done
  fi
}

opencti_fix_bridge_permissions() {
  opencti_require_root
  service_group=""
  mkdir -p "$OPENCTI_STATE_DIR" "$OPENCTI_LOG_DIR"
  touch "$OPENCTI_BRIDGE_LOG"
  chmod 750 "$OPENCTI_STATE_DIR" "$OPENCTI_LOG_DIR"
  chmod 640 "$OPENCTI_BRIDGE_LOG"
  opencti_fix_env_permissions
  if id "$OPENCTI_SERVICE_USER" >/dev/null 2>&1; then
    service_group=$(opencti_service_group)
    chown -R "$OPENCTI_SERVICE_USER:$service_group" "$OPENCTI_STATE_DIR" "$OPENCTI_LOG_DIR"
    chown "$OPENCTI_SERVICE_USER:$service_group" "$OPENCTI_BRIDGE_LOG"
  fi
}

opencti_auto_confirm_enabled() {
  case "${OPENCTI_AUTO_CONFIRM:-false}" in
    true|TRUE|yes|YES|1|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

opencti_backup_file() {
  file=$1
  [ -e "$file" ] || return 0
  backup="${file}.backup-$(date +%Y%m%d_%H%M%S)"
  cp -a "$file" "$backup"
  info "Backup created: $backup"
}

opencti_url_scheme() {
  case "${1:-}" in
    http://*) printf 'http\n' ;;
    https://*) printf 'https\n' ;;
    *) printf '\n' ;;
  esac
}

opencti_prompt_optional() {
  label=$1
  value=""
  printf '\n%s\n' "$label" >&2
  printf 'Press Enter to leave blank, or type a value: ' >&2
  IFS= read -r value || die "Input stream closed."
  printf '%s\n' "$value"
}

opencti_set_env_key() {
  file=$1
  key=$2
  value=$3
  [ -f "$file" ] || return 0
  tmp="${file}.tmp.$$"
  awk -v k="$key" -v v="$value" 'BEGIN { done=0 } $0 ~ "^" k "=" { print k "=" v; done=1; next } { print } END { if (!done) print k "=" v }' "$file" >"$tmp"
  cat "$tmp" >"$file"
  rm -f "$tmp"
  chmod 600 "$file" 2>/dev/null || true
  opencti_fix_env_permissions 2>/dev/null || true
}

opencti_force_safe_env() {
  file=$1
  reason=${2:-validation_failed}
  [ -f "$file" ] || return 0
  opencti_set_env_key "$file" "DRY_RUN" "true"
  opencti_set_env_key "$file" "UPDATE_IRIS_IOC" "false"
  opencti_set_env_key "$file" "ADD_CASE_NOTE" "false"
  opencti_set_env_key "$file" "ACTIVATION_STATUS" "blocked"
  opencti_set_env_key "$file" "BLOCK_REASON" "$reason"
}

opencti_write_activation_status() {
  status=$1
  reason=${2:-}
  opencti_prepare_dirs
  python3 - "$OPENCTI_ACTIVATION_STATUS" "$status" "$reason" <<'PY'
import json
import sys
from datetime import datetime, timezone
path, status, reason = sys.argv[1:4]
with open(path, "w", encoding="utf-8") as fh:
    json.dump({"timestamp": datetime.now(timezone.utc).isoformat(), "status": status, "reason": reason}, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
  chmod 640 "$OPENCTI_ACTIVATION_STATUS" 2>/dev/null || true
}

opencti_mark_activation_blocked() {
  reason=${1:-validation_failed}
  opencti_write_activation_status "blocked" "$reason"
  if have systemctl; then
    systemctl disable --now opencti-iris-bridge.timer >/dev/null 2>&1 || true
  fi
}

opencti_mark_activation_ready() {
  opencti_write_activation_status "ready" ""
  [ -f "$OPENCTI_ENV_FILE" ] && {
    opencti_set_env_key "$OPENCTI_ENV_FILE" "ACTIVATION_STATUS" "ready"
    opencti_set_env_key "$OPENCTI_ENV_FILE" "BLOCK_REASON" ""
  }
  return 0
}

opencti_print_ssl_failure_hint() {
  output=$1
  if printf '%s\n' "$output" | grep -q 'ssl_certificate_verify_failed' && printf '%s\n' "$output" | grep -qi '"component": "iris"\|"component": "both"'; then
    printf '\nIRIS SSL verification failed.\n\n' >&2
    printf 'Your IRIS URL uses HTTPS:\n' >&2
    iris_url=$(opencti_env_value IRIS_URL "$OPENCTI_ENV_PENDING" 2>/dev/null || opencti_env_value IRIS_URL "$OPENCTI_ENV_FILE" 2>/dev/null || true)
    printf '  %s\n\n' "${iris_url:-unknown}" >&2
    printf 'The certificate appears to be self-signed.\n\n' >&2
    printf 'For lab/self-signed IRIS deployments, reconfigure and choose:\n' >&2
    printf '  Enable IRIS SSL certificate verification? No\n\n' >&2
    printf 'For production, install a trusted certificate or provide an IRIS CA bundle.\n' >&2
  fi
}

opencti_write_report() {
  status=${1:-unknown}
  opencti_prepare_dirs
  opencti_url=$(opencti_env_value OPENCTI_URL 2>/dev/null || true)
  iris_url=$(opencti_env_value IRIS_URL 2>/dev/null || true)
  timer_state="disabled"
  if have systemctl && systemctl is-enabled opencti-iris-bridge.timer >/dev/null 2>&1; then
    timer_state="enabled"
  fi
  {
    printf 'OpenCTI <-> IRIS bridge install report\n'
    printf 'Generated: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'Status: %s\n' "$status"
    printf 'IRIS URL: %s\n' "$iris_url"
    printf 'OpenCTI URL: %s\n' "$opencti_url"
    printf 'Timer: %s\n' "$timer_state"
    printf 'Bridge directory: %s\n' "$OPENCTI_BRIDGE_DIR"
    printf 'Env file: %s\n' "$OPENCTI_ENV_FILE"
    printf 'Control API env: %s\n' "$OPENCTI_CONTROL_ENV"
    printf 'State DB: %s\n' "$OPENCTI_STATE_DB"
    printf 'Log: %s\n' "$OPENCTI_BRIDGE_LOG"
    printf '\nNext steps:\n'
    printf '  - ./setup.sh opencti-preflight\n'
    printf '  - ./setup.sh opencti-install\n'
    printf '  - ./setup.sh opencti-dry-run\n'
    printf '  - ./setup.sh opencti-enable-timer\n'
  } >"$OPENCTI_REPORT_TXT"
  python3 - "$status" "$iris_url" "$opencti_url" "$timer_state" "$OPENCTI_BRIDGE_DIR" "$OPENCTI_ENV_FILE" "$OPENCTI_STATE_DB" <<'PYREPORT' >"$OPENCTI_REPORT_JSON"
import json
import sys
from datetime import datetime, timezone
status, iris_url, opencti_url, timer_state, bridge_dir, env_file, state_db = sys.argv[1:8]
print(json.dumps({
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "status": status,
    "iris_url": iris_url,
    "opencti_url": opencti_url,
    "timer": timer_state,
    "paths": {
        "bridge_dir": bridge_dir,
        "env_file": env_file,
        "state_db": state_db,
    },
}, indent=2))
PYREPORT
  chmod 640 "$OPENCTI_REPORT_TXT" "$OPENCTI_REPORT_JSON"
}

opencti_configure_bridge() {
  opencti_require_root
  opencti_url=""
  opencti_token=""
  iris_url=""
  iris_token=""
  iris_case_ids=""
  poll_minutes="30"
  reenrich_hours="24"
  max_cases="500"
  max_iocs_per_case="500"
  min_score="0"
  min_confidence="0"
  control_bind_host=$(opencti_detect_iris_host_ip 2>/dev/null || true)
  [ -n "$control_bind_host" ] || control_bind_host="127.0.0.1"
  control_bind_port="9097"
  dry_run="false"
  update_iris_ioc="true"
  add_case_note="true"
  opencti_verify_ssl="true"
  opencti_ca_bundle=""
  iris_verify_ssl="false"
  iris_ca_bundle=""
  non_interactive="false"

  while [ "$#" -gt 0 ]; do
    case "$1" in
      --opencti-url) opencti_url=${2:-}; shift 2 ;;
      --opencti-token) opencti_token=${2:-}; shift 2 ;;
      --iris-url) iris_url=${2:-}; shift 2 ;;
      --iris-token) iris_token=${2:-}; shift 2 ;;
      --case-ids) iris_case_ids=${2:-}; shift 2 ;;
      --poll-minutes) poll_minutes=${2:-}; shift 2 ;;
      --reenrich-hours) reenrich_hours=${2:-}; shift 2 ;;
      --max-cases) max_cases=${2:-}; shift 2 ;;
      --max-iocs-per-case) max_iocs_per_case=${2:-}; shift 2 ;;
      --min-score) min_score=${2:-}; shift 2 ;;
      --min-confidence) min_confidence=${2:-}; shift 2 ;;
      --control-bind-host) control_bind_host=${2:-}; shift 2 ;;
      --control-bind-port) control_bind_port=${2:-}; shift 2 ;;
      --opencti-verify-ssl) opencti_verify_ssl="true"; shift ;;
      --opencti-no-verify-ssl) opencti_verify_ssl="false"; shift ;;
      --opencti-ca-bundle) opencti_ca_bundle=${2:-}; shift 2 ;;
      --iris-verify-ssl) iris_verify_ssl="true"; shift ;;
      --iris-no-verify-ssl) iris_verify_ssl="false"; shift ;;
      --iris-ca-bundle) iris_ca_bundle=${2:-}; iris_verify_ssl="true"; shift 2 ;;
      --update-iris-ioc) update_iris_ioc="true"; shift ;;
      --add-case-note) add_case_note="true"; shift ;;
      --live-write) dry_run="false"; shift ;;
      --dry-run) dry_run="true"; shift ;;
      --non-interactive) non_interactive="true"; shift ;;
      *) die "Unknown opencti-configure option: $1" ;;
    esac
  done

  if [ "$non_interactive" != "true" ]; then
    printf '\nThis option requires an existing deployed and configured OpenCTI instance.\n'
    printf 'OpenCTI will not be installed by this script. You must provide the URL and API token for an existing OpenCTI deployment.\n'
    [ -n "$opencti_url" ] || opencti_url=$(prompt_default "OpenCTI URL" "https://opencti.company.local")
    [ -n "$opencti_token" ] || opencti_token=$(opencti_prompt_secret "OpenCTI API token")
    [ -n "$iris_url" ] || iris_url=$(prompt_default "IRIS URL" "$(opencti_default_iris_url)")
    detected_iris_token=$(opencti_default_iris_token || true)
    if [ -z "$iris_token" ] && [ -n "$detected_iris_token" ]; then
      if prompt_yes_no "Use the detected IRIS admin API key from this deployment?"; then
        iris_token=$detected_iris_token
      fi
    fi
    [ -n "$iris_token" ] || iris_token=$(opencti_prompt_secret "IRIS API token")
    poll_minutes=$(prompt_default "Bridge poll interval in minutes" "$poll_minutes")
    max_cases=$(prompt_default "Maximum open IRIS cases per run" "$max_cases")
    max_iocs_per_case=$(prompt_default "Maximum IOCs per case per run" "$max_iocs_per_case")
    reenrich_hours=$(prompt_default "Re-enrich unchanged IOCs after this many hours" "$reenrich_hours")
    min_score=$(prompt_default "Minimum OpenCTI score" "$min_score")
    min_confidence=$(prompt_default "Minimum OpenCTI confidence" "$min_confidence")
    control_bind_host=$(prompt_default "Bridge control API bind host" "$control_bind_host")
    control_bind_port=$(prompt_default "Bridge control API bind port" "$control_bind_port")
    opencti_scheme=$(opencti_url_scheme "$opencti_url")
    if [ "$opencti_scheme" = "http" ]; then
      opencti_verify_ssl="false"
      info "OpenCTI URL uses HTTP; OpenCTI SSL verification is not applicable and will be disabled."
    elif [ "$opencti_scheme" = "https" ]; then
      if prompt_yes_no "Enable OpenCTI SSL certificate verification?"; then
        opencti_verify_ssl="true"
        opencti_ca_bundle=$(opencti_prompt_optional "Optional OpenCTI CA bundle path for private/self-signed CAs")
      else
        opencti_verify_ssl="false"
        opencti_ca_bundle=""
      fi
    fi
    iris_scheme=$(opencti_url_scheme "$iris_url")
    if [ "$iris_scheme" = "http" ]; then
      iris_verify_ssl="false"
      info "IRIS URL uses HTTP; IRIS SSL verification is not applicable and will be disabled."
    elif [ "$iris_scheme" = "https" ]; then
      printf '\nYour IRIS URL uses HTTPS. If this IRIS deployment uses a self-signed certificate, choose No for SSL verification unless you have installed the CA certificate.\n'
      if prompt_yes_no "Enable IRIS SSL certificate verification?"; then
        iris_verify_ssl="true"
        iris_ca_bundle=$(opencti_prompt_optional "Optional IRIS CA bundle path for production/private CAs")
      else
        iris_verify_ssl="false"
        iris_ca_bundle=""
      fi
    fi
    if prompt_yes_no "Enable live IRIS IOC table updates?"; then
      update_iris_ioc="true"
    else
      update_iris_ioc="false"
    fi
    if prompt_yes_no "Enable Markdown case notes in IRIS?"; then
      add_case_note="true"
    else
      add_case_note="false"
    fi
    if prompt_yes_no "Enable scheduled live-write automation so the timer updates IRIS IOC descriptions and notes?"; then
      dry_run="false"
      warn "Scheduled live-write mode selected. IRIS writes are limited by the update/note options above."
    else
      dry_run="true"
      warn "Scheduled dry-run mode selected. The timer will not update IRIS until DRY_RUN=false is configured."
    fi
  fi

  [ -n "$opencti_url" ] || die "Missing OpenCTI URL."
  [ -n "$opencti_token" ] || die "Missing OpenCTI API token."
  [ -n "$iris_url" ] || die "Missing IRIS URL."
  [ -n "$iris_token" ] || die "Missing IRIS API token."
  if [ "$(opencti_url_scheme "$opencti_url")" = "http" ]; then
    opencti_verify_ssl="false"
    opencti_ca_bundle=""
  fi
  if [ "$(opencti_url_scheme "$iris_url")" = "http" ]; then
    iris_verify_ssl="false"
    iris_ca_bundle=""
  fi
  if [ -n "$opencti_ca_bundle" ]; then
    [ -f "$opencti_ca_bundle" ] || die "OpenCTI CA bundle file does not exist: $opencti_ca_bundle"
    opencti_verify_ssl="true"
  fi
  if [ -n "$iris_ca_bundle" ]; then
    [ -f "$iris_ca_bundle" ] || die "IRIS CA bundle file does not exist: $iris_ca_bundle"
    iris_verify_ssl="true"
  fi
  opencti_validate_uint "poll minutes" "$poll_minutes"
  opencti_validate_uint "reenrich hours" "$reenrich_hours"
  opencti_validate_uint "max cases" "$max_cases"
  opencti_validate_uint "max IOCs per case" "$max_iocs_per_case"
  opencti_validate_uint "minimum score" "$min_score"
  opencti_validate_uint "minimum confidence" "$min_confidence"
  opencti_validate_uint "control bind port" "$control_bind_port"

  opencti_prepare_dirs
  opencti_fix_bridge_permissions
  control_token=$(opencti_env_value CONTROL_TOKEN "$OPENCTI_CONTROL_ENV" 2>/dev/null || true)
  [ -n "$control_token" ] || control_token=$(opencti_env_value CONTROL_TOKEN "$OPENCTI_CONTROL_PENDING" 2>/dev/null || true)
  [ -n "$control_token" ] || control_token=$(opencti_random_token)

  cat >"$OPENCTI_ENV_PENDING" <<EOFOPENCTIENV
OPENCTI_URL=${opencti_url%/}
OPENCTI_TOKEN=${opencti_token}
OPENCTI_VERIFY_SSL=${opencti_verify_ssl}
OPENCTI_CA_BUNDLE=${opencti_ca_bundle}
IRIS_URL=${iris_url%/}
IRIS_TOKEN=${iris_token}
IRIS_VERIFY_SSL=${iris_verify_ssl}
IRIS_CA_BUNDLE=${iris_ca_bundle}
IRIS_CASE_IDS=${iris_case_ids}
POLL_MINUTES=${poll_minutes}
MAX_CASES=${max_cases}
MAX_IOCS_PER_CASE=${max_iocs_per_case}
REENRICH_HOURS=${reenrich_hours}
MIN_SCORE=${min_score}
MIN_CONFIDENCE=${min_confidence}
DEFAULT_IRIS_TLP_ID=2
UPDATE_IRIS_IOC=${update_iris_ioc}
ADD_CASE_NOTE=${add_case_note}
NOTE_DIR_NAME=OpenCTI Enrichment
DRY_RUN=${dry_run}
STATE_DB=${OPENCTI_STATE_DB}
WATCHLIST=${OPENCTI_WATCHLIST}
RUN_LOG=${OPENCTI_BRIDGE_LOG}
CAPABILITIES_FILE=${OPENCTI_CAPABILITIES}
LAST_PREFLIGHT_FILE=${OPENCTI_LAST_PREFLIGHT}
LAST_DRY_RUN_FILE=${OPENCTI_LAST_DRY_RUN}
LAST_LIVE_WRITE_FILE=${OPENCTI_LAST_LIVE_WRITE}
ACTIVATION_STATUS=pending
BLOCK_REASON=not_validated
EOFOPENCTIENV

  cat >"$OPENCTI_CONTROL_PENDING" <<EOFCONTROLENV
CONTROL_BIND_HOST=${control_bind_host}
CONTROL_BIND_PORT=${control_bind_port}
CONTROL_TOKEN=${control_token}
CONTROL_TIMEOUT=900
OPENCTI_IRIS_RUNNER=${OPENCTI_RUNNER}
BRIDGE_ENV_FILE=${OPENCTI_ENV_FILE}
EOFCONTROLENV

  chmod 600 "$OPENCTI_ENV_PENDING" "$OPENCTI_CONTROL_PENDING"
  opencti_fix_env_permissions 2>/dev/null || true
  opencti_write_activation_status "pending" "pending_validation"
  info "OpenCTI bridge configuration written to pending env files. Active config will not change until validation and dry-run pass."

  if ! opencti_install_bridge_service; then
    warn "Pending configuration validation or bridge bootstrap failed. Active configuration and production bridge files were left untouched."
    return 1
  fi
  opencti_write_report "configured-installed-validated-dry-run-passed"
  info "OpenCTI bridge configuration and staged bridge code were promoted after successful staged validation and dry-run."
}

opencti_require_env() {
  [ -f "$OPENCTI_ENV_FILE" ] || die "Missing $OPENCTI_ENV_FILE. Run ./setup.sh opencti-configure first."
  [ -f "$OPENCTI_CONTROL_ENV" ] || die "Missing $OPENCTI_CONTROL_ENV. Run ./setup.sh opencti-configure first."
  [ -n "$(opencti_env_value OPENCTI_URL 2>/dev/null || true)" ] || die "OPENCTI_URL is missing in $OPENCTI_ENV_FILE."
  [ -n "$(opencti_env_value OPENCTI_TOKEN 2>/dev/null || true)" ] || die "OPENCTI_TOKEN is missing in $OPENCTI_ENV_FILE."
  [ -n "$(opencti_env_value IRIS_URL 2>/dev/null || true)" ] || die "IRIS_URL is missing in $OPENCTI_ENV_FILE."
  [ -n "$(opencti_env_value IRIS_TOKEN 2>/dev/null || true)" ] || die "IRIS_TOKEN is missing in $OPENCTI_ENV_FILE."
}

opencti_require_env_file() {
  env_file=${1:-$OPENCTI_ENV_FILE}
  [ -f "$env_file" ] || die "Missing OpenCTI bridge env file: $env_file"
  [ -n "$(opencti_env_value OPENCTI_URL "$env_file" 2>/dev/null || true)" ] || die "OPENCTI_URL is missing in $env_file."
  [ -n "$(opencti_env_value OPENCTI_TOKEN "$env_file" 2>/dev/null || true)" ] || die "OPENCTI_TOKEN is missing in $env_file."
  [ -n "$(opencti_env_value IRIS_URL "$env_file" 2>/dev/null || true)" ] || die "IRIS_URL is missing in $env_file."
  [ -n "$(opencti_env_value IRIS_TOKEN "$env_file" 2>/dev/null || true)" ] || die "IRIS_TOKEN is missing in $env_file."
}

opencti_detect_pkg_manager() {
  if have apt-get; then printf 'apt\n'
  elif have dnf; then printf 'dnf\n'
  elif have yum; then printf 'yum\n'
  elif have pacman; then printf 'pacman\n'
  elif have zypper; then printf 'zypper\n'
  elif have apk; then printf 'apk\n'
  elif have microdnf; then printf 'microdnf\n'
  else return 1
  fi
}

opencti_install_host_tools() {
  missing=""
  have python3 || missing="$missing python3"
  have curl || missing="$missing curl"
  [ -z "$missing" ] && return 0
  opencti_require_root
  pm=$(opencti_detect_pkg_manager || true)
  [ -n "$pm" ] || die "Missing required tools:$missing and no supported package manager was detected."
  warn "Missing required tools:$missing"
  info "Attempting to install missing OpenCTI bridge host tools using $pm."
  case "$pm" in
    apt) apt-get update && env DEBIAN_FRONTEND=noninteractive apt-get install -y python3 curl ;;
    dnf) dnf install -y python3 curl ;;
    yum) yum install -y python3 curl ;;
    pacman) pacman -Sy --needed --noconfirm python curl ;;
    zypper) zypper --non-interactive install python3 curl ;;
    apk) apk add --no-cache python3 curl ;;
    microdnf) microdnf install -y python3 curl ;;
  esac
}

opencti_port_available() {
  host=$1
  port=$2
  python3 - "$host" "$port" <<'PYPORT'
import socket
import sys
host, port = sys.argv[1], int(sys.argv[2])
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind((host, port))
except OSError:
    raise SystemExit(1)
finally:
    s.close()
PYPORT
}

opencti_host_preflight() {
  control_env=${1:-$OPENCTI_CONTROL_ENV}
  opencti_install_host_tools
  failed=0
  have python3 || { warn "fatal: python3 is missing."; failed=1; }
  python3 - <<'PYCHECK' >/dev/null 2>&1 || { warn "fatal: python3 sqlite3/ssl/urllib modules are unavailable."; failed=1; }
import sqlite3, ssl, urllib.request
PYCHECK
  have curl || { warn "fatal: curl is missing."; failed=1; }
  have systemctl || { warn "fatal: systemctl is missing; systemd services cannot be installed."; failed=1; }
  [ -d /run/systemd/system ] || { warn "fatal: systemd does not appear to be running on this host."; failed=1; }
  opencti_prepare_dirs
  df -Pk "$OPENCTI_STATE_DIR" "$OPENCTI_LOG_DIR" 2>/dev/null | awk 'NR>1 && $4 < 10240 {bad=1} END {exit bad ? 1 : 0}' || { warn "fatal: less than 10 MB free for bridge state/logs."; failed=1; }
  bind_host=$(opencti_env_value CONTROL_BIND_HOST "$control_env" 2>/dev/null || printf '127.0.0.1')
  bind_port=$(opencti_env_value CONTROL_BIND_PORT "$control_env" 2>/dev/null || printf '9097')
  if ! opencti_port_available "$bind_host" "$bind_port"; then
    if have systemctl && systemctl is-active opencti-iris-bridge-api.service >/dev/null 2>&1; then
      warn "control API port $bind_host:$bind_port is already used by the existing bridge API service; update will restart it."
    else
      warn "fatal: control API port is already in use: $bind_host:$bind_port"
      failed=1
    fi
  fi
  [ "$failed" -eq 0 ] || return 1
  info "OpenCTI bridge host preflight passed."
}

opencti_python_api_check() {
  mode=$1
  opencti_require_env
  python3 - "$mode" "$OPENCTI_ENV_FILE" <<'PYCHECK'
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

mode, env_file = sys.argv[1:3]

def load_env(path):
    env = {}
    with open(path, encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            env[key] = value
    return env

env = load_env(env_file)

def as_bool(name, default=False):
    return str(env.get(name, str(default))).lower() in {"1", "true", "yes", "on"}

def ctx(verify):
    return None if verify else ssl._create_unverified_context()

def request_json(method, url, token, payload=None, verify=True, params=None):
    if params:
        url += "?" + urllib.parse.urlencode({k: v for k, v in params.items() if v not in [None, ""]})
    data = None
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json", "User-Agent": "iris-opencti-bridge-preflight"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    last_error = None
    for attempt in range(1, 4):
        try:
            with urllib.request.urlopen(req, timeout=30, context=ctx(verify)) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                return {"status": resp.status, "json": json.loads(body) if body.strip() else {}, "body": body[:500]}
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            if exc.code in {429, 500, 502, 503, 504} and attempt < 3:
                time.sleep(attempt * 2)
                continue
            raise RuntimeError(f"HTTP {exc.code} for {url}: {body[:500]}")
        except urllib.error.URLError as exc:
            last_error = exc
            if attempt < 3:
                time.sleep(attempt * 2)
                continue
            raise RuntimeError(f"Connection failed for {url}: {exc}") from exc
    raise RuntimeError(str(last_error))

def gql(query, variables=None):
    url = env["OPENCTI_URL"].rstrip("/") + "/graphql"
    result = request_json("POST", url, env["OPENCTI_TOKEN"], {"query": query, "variables": variables or {}}, as_bool("OPENCTI_VERIFY_SSL", True))
    payload = result["json"]
    if payload.get("errors"):
        raise RuntimeError(json.dumps(payload["errors"])[:1000])
    return payload.get("data") or {}

def check_iris():
    base = env["IRIS_URL"].rstrip("/")
    verify = as_bool("IRIS_VERIFY_SSL", False)
    result = {"target": base, "case_list": False, "ioc_list": "not_tested_no_case_id", "warnings": []}
    request_json("GET", base + "/manage/cases/filter", env["IRIS_TOKEN"], verify=verify, params={"page": 1, "per_page": 1, "sort": "desc"})
    result["case_list"] = True
    case_ids = [x.strip() for x in env.get("IRIS_CASE_IDS", "").split(",") if x.strip()]
    if case_ids:
        request_json("GET", base + "/case/ioc/list", env["IRIS_TOKEN"], verify=verify, params={"cid": case_ids[0]})
        result["ioc_list"] = True
    if as_bool("ADD_CASE_NOTE", False):
        if case_ids:
            request_json("GET", base + "/case/notes/directories/filter", env["IRIS_TOKEN"], verify=verify, params={"cid": case_ids[0]})
            result["note_directory"] = True
        else:
            result["warnings"].append("case notes enabled but no IRIS_CASE_IDS were configured for note-directory validation")
    return result

def check_opencti():
    result = {"target": env["OPENCTI_URL"].rstrip("/"), "basic": False, "indicator_query": False, "observable_query": False, "enhanced_query": False, "fallback_query": False, "warnings": []}
    data = gql("query { __typename }")
    result["basic"] = True
    try:
        about = gql("query { about { version } }")
        result["version"] = (((about.get("about") or {}).get("version")) or "")
    except Exception as exc:
        result["warnings"].append("OpenCTI version query unsupported: " + str(exc)[:160])
    gql("query { indicators(first: 1) { edges { node { id entity_type name pattern x_opencti_score confidence } } } }")
    result["indicator_query"] = True
    gql("query { stixCyberObservables(first: 1) { edges { node { id entity_type observable_value } } } }")
    result["observable_query"] = True
    try:
        gql("query { indicators(first: 1) { edges { node { id entity_type name pattern x_opencti_score confidence objectMarking { edges { node { definition } } } createdBy { name } } } } }")
        result["enhanced_query"] = True
    except Exception as exc:
        result["warnings"].append("enhanced enrichment query unsupported, confirming fallback: " + str(exc)[:160])
        gql("query { indicators(first: 1) { edges { node { id name pattern x_opencti_score confidence } } } }")
        result["fallback_query"] = True
    return result

try:
    if mode == "iris":
        output = check_iris()
    elif mode == "opencti":
        output = check_opencti()
    else:
        output = {"iris": check_iris(), "opencti": check_opencti()}
    print(json.dumps({"status": "ok", "result": output}, indent=2))
except Exception as exc:
    print(json.dumps({"status": "error", "error": str(exc)}, indent=2), file=sys.stderr)
    raise SystemExit(1)
PYCHECK
}

opencti_test_iris_api() {
  opencti_python_api_check iris
}

opencti_test_opencti_api() {
  opencti_python_api_check opencti
}

opencti_bridge_preflight() {
  opencti_require_env
  if ! opencti_host_preflight "$control_env"; then
    opencti_mark_activation_blocked "host_preflight_failed"
    return 1
  fi
  info "Testing IRIS API connection."
  opencti_test_iris_api || return 1
  info "Testing OpenCTI API and GraphQL capabilities."
  opencti_test_opencti_api || return 1
  opencti_write_report "preflight-passed"
  info "OpenCTI bridge preflight passed."
}

opencti_ensure_service_user() {
  opencti_require_root
  if id "$OPENCTI_SERVICE_USER" >/dev/null 2>&1; then
    :
  elif have useradd; then
    useradd --system --home-dir "$OPENCTI_BRIDGE_DIR" --shell /usr/sbin/nologin "$OPENCTI_SERVICE_USER"
  elif have adduser; then
    adduser -S -H -h "$OPENCTI_BRIDGE_DIR" -s /sbin/nologin "$OPENCTI_SERVICE_USER"
  else
    die "Cannot create service user $OPENCTI_SERVICE_USER: useradd/adduser not found."
  fi
  service_group=$(opencti_service_group)
  chown -R "$OPENCTI_SERVICE_USER:$service_group" "$OPENCTI_BRIDGE_DIR" "$OPENCTI_STATE_DIR" "$OPENCTI_LOG_DIR"
  opencti_fix_bridge_permissions
}

opencti_write_systemd_units() {
  opencti_require_root
  unit_dir=${1:-/etc/systemd/system}
  mkdir -p "$unit_dir"
  poll_minutes=$(opencti_env_value POLL_MINUTES 2>/dev/null || true)
  [ -n "$poll_minutes" ] || poll_minutes="30"
  cat >"$unit_dir/opencti-iris-bridge.service" <<EOFUNIT
[Unit]
Description=OpenCTI to DFIR-IRIS bridge one-shot enrichment run
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=${OPENCTI_ENV_FILE}
Environment=OPENCTI_IRIS_CORE=${OPENCTI_CORE}
ExecStart=${OPENCTI_RUNNER} --env-file ${OPENCTI_ENV_FILE} --once
WorkingDirectory=${OPENCTI_BRIDGE_DIR}
User=${OPENCTI_SERVICE_USER}
Group=${OPENCTI_SERVICE_USER}
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ReadWritePaths=${OPENCTI_STATE_DIR} ${OPENCTI_LOG_DIR}
EOFUNIT

  cat >"$unit_dir/opencti-iris-bridge.timer" <<EOFUNIT
[Unit]
Description=Run OpenCTI to DFIR-IRIS bridge periodically

[Timer]
OnBootSec=2min
OnUnitActiveSec=${poll_minutes}min
AccuracySec=30s
Persistent=false
Unit=opencti-iris-bridge.service

[Install]
WantedBy=timers.target
EOFUNIT

  cat >"$unit_dir/opencti-iris-bridge-api.service" <<EOFUNIT
[Unit]
Description=OpenCTI to DFIR-IRIS bridge local control API
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=${OPENCTI_CONTROL_ENV}
Environment=OPENCTI_IRIS_CORE=${OPENCTI_CORE}
ExecStart=${OPENCTI_API}
WorkingDirectory=${OPENCTI_BRIDGE_DIR}
Restart=on-failure
RestartSec=3
User=${OPENCTI_SERVICE_USER}
Group=${OPENCTI_SERVICE_USER}
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ReadWritePaths=${OPENCTI_STATE_DIR} ${OPENCTI_LOG_DIR}

[Install]
WantedBy=multi-user.target
EOFUNIT
  if [ "$unit_dir" = "/etc/systemd/system" ]; then
    systemctl daemon-reload
  fi
}

opencti_api_health() {
  opencti_require_env
  bind_host=$(opencti_env_value CONTROL_BIND_HOST "$OPENCTI_CONTROL_ENV")
  bind_port=$(opencti_env_value CONTROL_BIND_PORT "$OPENCTI_CONTROL_ENV")
  control_token=$(opencti_env_value CONTROL_TOKEN "$OPENCTI_CONTROL_ENV")
  if ! output="$(python3 - "$bind_host" "$bind_port" "$control_token" 2>&1 <<'PYHEALTH'
import json
import sys
import urllib.request
host, port, token = sys.argv[1:4]
base = f"http://{host}:{port}"
with urllib.request.urlopen(base + "/health", timeout=10) as resp:
    health = json.loads(resp.read().decode())
if health.get("status") != "ok":
    raise SystemExit("health endpoint did not return ok")
req = urllib.request.Request(base + "/cases/enabled", headers={"Authorization": "Bearer " + token})
with urllib.request.urlopen(req, timeout=10) as resp:
    resp.read()
print(json.dumps({"status": "ok", "url": base}))
PYHEALTH
)"; then
    printf '%s\n' "$output"
    return 1
  fi
  printf '%s\n' "$output"
}

opencti_ensure_control_api_bind_host() {
  opencti_require_root
  desired_host=${1:-}
  desired_port=${2:-9097}
  [ -n "$desired_host" ] || die "Could not determine an IRIS-reachable host IP for the OpenCTI bridge control API."
  opencti_is_usable_bind_host "$desired_host" || die "Refusing to bind OpenCTI bridge control API to unsafe/loopback host: $desired_host"
  [ -f "$OPENCTI_CONTROL_ENV" ] || die "OpenCTI control API env is missing: $OPENCTI_CONTROL_ENV"

  current_host=$(opencti_env_value CONTROL_BIND_HOST "$OPENCTI_CONTROL_ENV" 2>/dev/null || true)
  current_port=$(opencti_env_value CONTROL_BIND_PORT "$OPENCTI_CONTROL_ENV" 2>/dev/null || true)
  changed=0
  if [ "$current_host" != "$desired_host" ]; then
    opencti_set_env_key "$OPENCTI_CONTROL_ENV" "CONTROL_BIND_HOST" "$desired_host"
    changed=1
  fi
  if [ "$current_port" != "$desired_port" ]; then
    opencti_set_env_key "$OPENCTI_CONTROL_ENV" "CONTROL_BIND_PORT" "$desired_port"
    changed=1
  fi
  opencti_set_env_key "$OPENCTI_CONTROL_ENV" "OPENCTI_IRIS_RUNNER" "$OPENCTI_RUNNER"
  opencti_set_env_key "$OPENCTI_CONTROL_ENV" "BRIDGE_ENV_FILE" "$OPENCTI_ENV_FILE"
  opencti_fix_bridge_permissions

  if [ "$changed" -eq 1 ]; then
    warn "The OpenCTI bridge control API is being moved to ${desired_host}:${desired_port} so IRIS containers can reach it."
  fi
  if have systemctl; then
    systemctl restart opencti-iris-bridge-api.service || die "Could not restart opencti-iris-bridge-api.service after updating bind host."
    sleep 2
  fi
  warn "The OpenCTI bridge control API is listening on ${desired_host}:${desired_port}. It requires a bearer token, but network access should still be restricted to trusted IRIS/management sources."
  if have ss; then
    ss -lntp 2>/dev/null | grep ":${desired_port}[[:space:]]" || true
  fi
}

opencti_test_bridge_api_from_container() {
  c=$1
  py=$2
  url=$3
  docker exec -i "$c" "$py" - "$url" <<'PYREACH'
import json
import sys
import urllib.request

base = sys.argv[1].rstrip("/")
try:
    print("Testing " + base + "/health")
    with urllib.request.urlopen(base + "/health", timeout=10) as resp:
        payload = json.loads(resp.read().decode("utf-8", errors="replace"))
    if payload.get("status") != "ok":
        raise RuntimeError(f"unexpected health payload: {payload}")
    print(json.dumps({"status": "ok", "url": base}, sort_keys=True))
except Exception as exc:
    raise SystemExit(f"[ERROR] IRIS container cannot reach OpenCTI bridge control API at {base}: {exc}")
PYREACH
}

opencti_sanitized_env_to() {
  src=$1
  dst=$2
  if [ -f "$src" ]; then
    sed -E 's/^(.*(TOKEN|PASSWORD|API_KEY|SECRET|KEY).*)=.*/\1=<redacted>/I' "$src" >"$dst"
  fi
}

opencti_support_bundle() {
  opencti_prepare_dirs
  bundle_dir="$OPENCTI_LOG_DIR/support-bundle-$(date +%Y%m%d_%H%M%S)"
  mkdir -p "$bundle_dir"
  cp -a "$OPENCTI_REPORT_TXT" "$OPENCTI_REPORT_JSON" "$bundle_dir/" 2>/dev/null || true
  opencti_sanitized_env_to "$OPENCTI_ENV_FILE" "$bundle_dir/opencti-iris-bridge.env.sanitized"
  opencti_sanitized_env_to "$OPENCTI_CONTROL_ENV" "$bundle_dir/control-api.env.sanitized"
  cp -a /etc/systemd/system/opencti-iris-bridge.service /etc/systemd/system/opencti-iris-bridge.timer /etc/systemd/system/opencti-iris-bridge-api.service "$bundle_dir/" 2>/dev/null || true
  tail -n 300 "$OPENCTI_BRIDGE_LOG" >"$bundle_dir/bridge.log.tail" 2>/dev/null || true
  { python3 --version 2>&1 || true; curl --version 2>&1 | head -5 || true; } >"$bundle_dir/package-checks.txt"
  if have systemctl; then
    systemctl --no-pager status opencti-iris-bridge.service opencti-iris-bridge.timer opencti-iris-bridge-api.service >"$bundle_dir/systemd-status.txt" 2>&1 || true
  fi
  if [ -f "$OPENCTI_ENV_FILE" ] && [ -f "$OPENCTI_CONTROL_ENV" ]; then
    opencti_python_api_check both >"$bundle_dir/connectivity.json" 2>"$bundle_dir/connectivity.err" || true
    opencti_state_check >"$bundle_dir/state-db-check.json" 2>"$bundle_dir/state-db-check.err" || true
  else
    printf '{"status":"skipped","reason":"bridge env files are not configured"}\n' >"$bundle_dir/connectivity.json"
  fi
  tarball="${bundle_dir}.tar.gz"
  tar -C "$OPENCTI_LOG_DIR" -czf "$tarball" "$(basename "$bundle_dir")"
  chmod 600 "$tarball"
  info "OpenCTI bridge support bundle written: $tarball"
}

opencti_uninstall_service_only() {
  opencti_require_root
  warn "This removes only the OpenCTI bridge service files and systemd units."
  warn "It does not remove IRIS, Wazuh, OpenCTI, bridge env files, state, or logs."
  if ! prompt_yes_no "Continue with OpenCTI bridge service-only uninstall?"; then
    die "Cancelled."
  fi
  systemctl disable --now opencti-iris-bridge.timer >/dev/null 2>&1 || true
  systemctl stop opencti-iris-bridge-api.service opencti-iris-bridge.service >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/opencti-iris-bridge.service /etc/systemd/system/opencti-iris-bridge.timer /etc/systemd/system/opencti-iris-bridge-api.service
  systemctl daemon-reload >/dev/null 2>&1 || true
  if [ -d "$OPENCTI_BRIDGE_DIR" ]; then
    mv "$OPENCTI_BRIDGE_DIR" "${OPENCTI_BRIDGE_DIR}.removed-$(date +%Y%m%d_%H%M%S)"
  fi
  opencti_write_report "service-uninstalled-state-kept"
  info "OpenCTI bridge service removed. State/logs/env files were kept."
}

opencti_detect_iris_module_containers() {
  have docker || return 0
  docker ps --format '{{.Names}}' | while IFS= read -r c; do
    [ -n "$c" ] || continue
    docker exec -i "$c" sh -lc '
      for p in /opt/venv/bin/python /usr/local/bin/python /usr/bin/python3 /usr/bin/python python3 python; do
        if command -v "$p" >/dev/null 2>&1 || [ -x "$p" ]; then
          "$p" - <<PY >/dev/null 2>&1
import iris_interface
PY
          exit $?
        fi
      done
      exit 1
    ' >/dev/null 2>&1 && printf '%s\n' "$c"
  done
}

opencti_container_python() {
  docker exec "$1" sh -lc '
    for p in /opt/venv/bin/python /usr/local/bin/python /usr/bin/python3 /usr/bin/python python3 python; do
      if command -v "$p" >/dev/null 2>&1 || [ -x "$p" ]; then echo "$p"; exit 0; fi
    done
    exit 1
  '
}

opencti_container_site_packages() {
  docker exec "$1" "$2" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])'
}

opencti_container_gateway() {
  docker exec "$1" sh -lc "ip route 2>/dev/null | awk '/default/ {print \$3; exit}'" 2>/dev/null || true
}

docker_container_running() {
  local c="$1"
  docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null | grep -qx 'true'
}

require_running_container() {
  local c="$1"
  if ! docker_container_running "$c"; then
    printf '[ERROR] Required container is not running: %s\n' "$c" >&2
    docker ps --format 'table {{.Names}}\t{{.Status}}' | grep -E 'iriswebapp|NAME' || true
    return 1
  fi
}

iris_restart_containers() {
  local containers=(iriswebapp_app iriswebapp_worker iriswebapp_nginx)
  local existing=()
  local c

  for c in "${containers[@]}"; do
    if docker inspect "$c" >/dev/null 2>&1; then
      existing+=("$c")
    else
      printf '[WARN] Container not found, skipping restart: %s\n' "$c" >&2
    fi
  done

  if [ "${#existing[@]}" -gt 0 ]; then
    docker restart "${existing[@]}"
  fi
}

opencti_install_iris_module() {
  opencti_require_root
  opencti_require_env
  [ -x "$OPENCTI_RUNNER" ] || die "Bridge service files are not installed. Run ./setup.sh opencti-install first."
  iris_container_check
  require_running_container iriswebapp_app || return 1
  require_running_container iriswebapp_worker || return 1
  require_running_container iriswebapp_nginx || return 1
  local module_containers=(iriswebapp_app iriswebapp_worker)
  control_token=$(opencti_env_value CONTROL_TOKEN "$OPENCTI_CONTROL_ENV")
  control_port=$(opencti_env_value CONTROL_BIND_PORT "$OPENCTI_CONTROL_ENV")
  bridge_host=$(opencti_detect_iris_host_ip 2>/dev/null || true)
  [ -n "$bridge_host" ] || die "Could not detect the IRIS host IP that containers can reach."
  bridge_url="http://${bridge_host}:${control_port}"

  opencti_ensure_control_api_bind_host "$bridge_host" "$control_port"
  opencti_api_health || die "Bridge control API health check failed."
  opencti_test_iris_api || die "IRIS API test failed."
  opencti_test_opencti_api || die "OpenCTI API test failed."
  opencti_run_dry_once || die "Dry-run failed; module installation is blocked."

  for c in "${module_containers[@]}"; do
    py=$(opencti_container_python "$c")
    opencti_test_bridge_api_from_container "$c" "$py" "$bridge_url" || return 1
  done

  printf '\nIRIS manual enrichment module/buttons will be installed into:\n'
  printf '%s\n' "${module_containers[@]}" | sed 's/^/  - /'
  printf 'Bridge control API URL: %s\n' "$bridge_url"
  printf 'Buttons: OpenCTI: Enrich this case, OpenCTI: Enrich this IOC\n'
  printf 'The installer will copy files, restart IRIS app/worker/nginx if present, register the module, refresh hooks if supported, and verify database visibility.\n'
  if opencti_auto_confirm_enabled; then
    info "Automated OpenCTI setup: installing IRIS manual enrichment module/buttons without an additional confirmation prompt."
  else
    if ! prompt_yes_no "Proceed with IRIS OpenCTI module/button install?"; then
      die "Cancelled."
    fi
  fi

  for c in "${module_containers[@]}"; do
    py=$(opencti_container_python "$c")
    site=$(opencti_container_site_packages "$c" "$py")
    pkg_dir="$site/iris_opencti_bridge_module"
    opencti_test_bridge_api_from_container "$c" "$py" "$bridge_url" || return 1
    info "Installing OpenCTI IRIS module in $c at $pkg_dir"
    docker exec "$c" sh -lc "if [ -d '$pkg_dir' ]; then mv '$pkg_dir' '${pkg_dir}.backup-opencti-$(date +%Y%m%d_%H%M%S)'; fi; mkdir -p '$pkg_dir'"
    docker exec -i "$c" sh -lc "cat > '$pkg_dir/__init__.py'" <<'PYINIT'
__iris_module_interface = "IrisOpenCTIBridgeInterface"
PYINIT
    docker exec -i "$c" sh -lc "cat > '$pkg_dir/IrisOpenCTIBridgeConfig.py'" <<PYCONF
module_name = "IrisOpenCTIBridge"
module_description = "Manual OpenCTI enrichment actions through the local OpenCTI IRIS bridge API"
interface_version = "1.2.0"
module_version = "1.0.5"
pipeline_support = False
pipeline_info = {}
module_configuration = [
    {"param_name": "bridge_control_url", "param_human_name": "Bridge control API URL", "param_description": "URL reachable from this IRIS container.", "default": "${bridge_url}", "mandatory": True, "type": "string", "section": "Bridge API"},
    {"param_name": "bridge_control_token", "param_human_name": "Bridge control API token", "param_description": "Bearer token from ${OPENCTI_CONTROL_ENV}", "default": "${control_token}", "mandatory": True, "type": "sensitive_string", "section": "Bridge API"},
    {"param_name": "bridge_control_timeout", "param_human_name": "Bridge API timeout", "param_description": "HTTP timeout in seconds.", "default": "600", "mandatory": True, "type": "float", "section": "Bridge API"}
]
PYCONF
    docker exec -i "$c" sh -lc "cat > '$pkg_dir/IrisOpenCTIBridgeInterface.py'" <<'PYIFACE'
#!/usr/bin/env python3
import json
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from iris_interface.IrisModuleInterface import IrisModuleInterface, IrisModuleTypes
import iris_interface.IrisInterfaceStatus as InterfaceStatus
import iris_opencti_bridge_module.IrisOpenCTIBridgeConfig as interface_conf

class IrisOpenCTIBridgeInterface(IrisModuleInterface):
    _module_name = interface_conf.module_name
    _module_description = interface_conf.module_description
    _interface_version = interface_conf.interface_version
    _module_version = interface_conf.module_version
    _pipeline_support = interface_conf.pipeline_support
    _pipeline_info = interface_conf.pipeline_info
    _module_configuration = interface_conf.module_configuration
    _module_type = IrisModuleTypes.module_processor

    def _conf(self, key, default=None):
        try:
            return self._dict_conf.get(key, default)
        except Exception:
            return default

    def register_hooks(self, module_id: int):
        hooks = [
            ("on_manual_trigger_case", "OpenCTI: Enrich this case"),
            ("on_manual_trigger_ioc", "OpenCTI: Enrich this IOC"),
        ]
        for hook_name, ui_name in hooks:
            status = self.register_to_hook(module_id, iris_hook_name=hook_name, manual_hook_name=ui_name, run_asynchronously=False)
            if status.is_failure():
                self.log.error(status.get_message())
            else:
                self.log.info(f"Registered OpenCTI bridge hook: {hook_name} / {ui_name}")

    def _as_list(self, data):
        if data is None:
            return []
        if isinstance(data, list):
            return data
        if isinstance(data, tuple):
            return list(data)
        return [data]

    def _obj_dict(self, obj):
        if isinstance(obj, dict):
            return obj
        try:
            return {k: v for k, v in vars(obj).items() if not k.startswith("_")}
        except Exception:
            return {}

    def _get_any(self, obj, names):
        data = self._obj_dict(obj)
        for name in names:
            if data.get(name) not in [None, ""]:
                return data.get(name)
        for name in names:
            try:
                value = getattr(obj, name)
                if value not in [None, ""]:
                    return value
            except Exception:
                pass
        return None

    def _nested_dicts(self, obj):
        seen = set()
        stack = [self._obj_dict(obj)]
        while stack:
            item = stack.pop(0)
            if not isinstance(item, dict):
                continue
            marker = id(item)
            if marker in seen:
                continue
            seen.add(marker)
            yield item
            for value in item.values():
                if isinstance(value, dict):
                    stack.append(value)
                elif isinstance(value, (list, tuple)):
                    for child in value:
                        if isinstance(child, dict):
                            stack.append(child)

    def _case_id_from_text(self, text):
        if text in [None, ""]:
            return None
        raw = str(text)
        for pattern in [
            r"(?:[?&]|\b)(?:cid|case_id|caseid)=([A-Za-z0-9_-]+)",
            r"/case/([A-Za-z0-9_-]+)(?:[/?#]|$)",
            r"/cases/([A-Za-z0-9_-]+)(?:[/?#]|$)",
        ]:
            match = re.search(pattern, raw)
            if match:
                return urllib.parse.unquote(match.group(1))
        try:
            parsed = urllib.parse.urlsplit(raw)
            query = urllib.parse.parse_qs(parsed.query)
            for name in ["cid", "case_id", "caseid"]:
                if query.get(name) and query[name][0] not in [None, ""]:
                    return query[name][0]
        except Exception:
            return None
        return None

    def _get_nested_any(self, obj, parent_names, names, scan_all=False):
        data = self._obj_dict(obj)
        for parent in parent_names:
            child = data.get(parent)
            if isinstance(child, dict):
                for name in names:
                    if child.get(name) not in [None, ""]:
                        return child.get(name)
        if not scan_all:
            return None
        for item in self._nested_dicts(obj):
            for name in names:
                if item.get(name) not in [None, ""]:
                    return item.get(name)
        return None

    def _get_case_id(self, obj):
        case_id = self._get_any(obj, ["case_id", "caseid", "cid", "parent_case_id", "object_case_id", "ioc_case_id", "ioc_caseid", "ioc_cid"])
        if case_id:
            return case_id
        data = self._obj_dict(obj)
        if data.get("case") not in [None, ""] and not isinstance(data.get("case"), dict):
            return data.get("case")
        for name in ["url", "referrer", "referer", "route", "path", "link", "href", "current_url", "page_url", "request_url"]:
            case_id = self._case_id_from_text(data.get(name))
            if case_id:
                return case_id
        for item in self._nested_dicts(obj):
            for name in ["url", "referrer", "referer", "route", "path", "link", "href", "current_url", "page_url", "request_url"]:
                case_id = self._case_id_from_text(item.get(name))
                if case_id:
                    return case_id
        case_id = self._get_nested_any(obj, ["case", "case_data", "case_obj", "parent_case", "ioc_case", "context", "hook_context", "data"], ["case_id", "caseid", "cid", "id"])
        if case_id:
            return case_id
        return self._get_nested_any(obj, [], ["case_id", "caseid", "cid"], scan_all=True)

    def _get_ioc_id(self, obj):
        ioc_id = self._get_any(obj, ["ioc_id", "iocid"])
        if ioc_id:
            return ioc_id
        nested = self._get_nested_any(obj, ["ioc", "ioc_data", "ioc_obj", "observable"], ["ioc_id", "iocid", "id"])
        if nested:
            return nested
        nested = self._get_nested_any(obj, [], ["ioc_id", "iocid"], scan_all=True)
        if nested:
            return nested
        return self._get_any(obj, ["id"])

    def _api_post(self, path, payload=None):
        base_url = str(self._conf("bridge_control_url", "")).rstrip("/")
        token = str(self._conf("bridge_control_token", ""))
        timeout = float(self._conf("bridge_control_timeout", 600))
        if not base_url:
            raise RuntimeError("bridge_control_url is not configured")
        if not token:
            raise RuntimeError("bridge_control_token is not configured")
        self.log.info(f"IrisOpenCTIBridge using bridge_control_url={base_url}")
        req = urllib.request.Request(
            base_url + path,
            data=json.dumps(payload or {}).encode("utf-8"),
            method="POST",
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/json", "User-Agent": "IrisOpenCTIBridgeModule"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                return json.loads(raw) if raw.strip() else {}
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            if exc.code in (401, 403):
                raise RuntimeError(f"Bridge API authentication failed with HTTP {exc.code}; check bridge_control_token")
            raise RuntimeError(f"Bridge API HTTP {exc.code}: {raw[:1000]}")
        except socket.timeout as exc:
            raise RuntimeError(f"Bridge API timeout reaching {base_url}: {exc}")
        except urllib.error.URLError as exc:
            reason = str(getattr(exc, "reason", exc))
            if "Connection refused" in reason or "Errno 111" in reason:
                raise RuntimeError(f"Bridge API connection refused at {base_url}; check control API bind host, port, and service status")
            if "timed out" in reason.lower():
                raise RuntimeError(f"Bridge API timeout reaching {base_url}: {reason}")
            raise RuntimeError(f"Bridge API connection failed at {base_url}: {reason}")

    def _handle_case_action(self, data, force=True):
        results = []
        for obj in self._as_list(data):
            case_id = self._get_case_id(obj) or self._get_any(obj, ["id"])
            if not case_id:
                self.log.error(f"OpenCTI bridge: could not extract case_id from {self._obj_dict(obj)}")
                results.append({"status": "error", "message": "case_id could not be extracted"})
                continue
            path = f"/cases/{case_id}/enrich"
            self.log.info(f"OpenCTI bridge selected route={path} case_id={case_id}")
            result = self._api_post(path, {"manual": True, "force": True, "live_write": True})
            self.log.info(f"OpenCTI bridge case enrichment result: {result}")
            results.append({"status": result.get("status", "ok") if isinstance(result, dict) else "ok", "case_id": str(case_id), "route": path, "bridge_response": result})
        return {"status": "ok", "message": "OpenCTI case enrichment request completed.", "results": results}

    def _handle_ioc_action(self, data, force=True):
        results = []
        for obj in self._as_list(data):
            self.log.info(f"OpenCTI bridge IOC hook raw object keys: {list(self._obj_dict(obj).keys())}")
            ioc_id = self._get_ioc_id(obj)
            case_id = self._get_case_id(obj)
            self.log.info(f"OpenCTI bridge IOC extracted case_id={case_id} ioc_id={ioc_id}")
            if not ioc_id:
                self.log.error(f"OpenCTI bridge: could not extract ioc_id from {self._obj_dict(obj)}")
                results.append({"status": "error", "message": "ioc_id could not be extracted"})
                continue
            payload = {"manual": True, "force": True, "live_write": True}
            if case_id:
                path = f"/cases/{case_id}/iocs/{ioc_id}/enrich-async"
            else:
                path = f"/iocs/{ioc_id}/enrich-async"
                self.log.warning(
                    f"OpenCTI bridge: case_id unavailable for IOC {ioc_id}; using IOC-only fallback. "
                    "IOC Description update may require case resolution in the API."
                )
            self.log.info(f"OpenCTI bridge selected route={path} case_id={case_id} ioc_id={ioc_id}")
            result = self._api_post(path, payload)
            self.log.info(
                "OpenCTI bridge IOC async enrichment accepted: "
                f"status={result.get('status') if isinstance(result, dict) else 'unknown'} "
                f"job_id={result.get('job_id') if isinstance(result, dict) else None} "
                f"duplicate={result.get('duplicate') if isinstance(result, dict) else None}"
            )
            results.append({
                "status": result.get("status", "accepted") if isinstance(result, dict) else "accepted",
                "message": "OpenCTI IOC enrichment job accepted.",
                "route": path,
                "case_id": str(result.get("case_id") or case_id) if isinstance(result, dict) and (result.get("case_id") or case_id) not in [None, ""] else (str(case_id) if case_id not in [None, ""] else None),
                "ioc_id": str(ioc_id),
                "bridge_status": result.get("status") if isinstance(result, dict) else None,
                "job_id": result.get("job_id") if isinstance(result, dict) else None,
                "duplicate": result.get("duplicate") if isinstance(result, dict) else None,
                "bridge_response": result,
            })
        return {"status": "accepted", "message": "OpenCTI IOC enrichment job accepted.", "results": results}

    def hooks_handler(self, hook_name: str, hook_ui_name: str, data: any):
        try:
            if hook_name == "on_manual_trigger_case":
                result_data = self._handle_case_action(data, force=True)
            elif hook_name == "on_manual_trigger_ioc":
                result_data = self._handle_ioc_action(data, force=True)
            elif hook_name in ["on_postload_ioc_create", "on_postload_ioc_update"]:
                self.log.info(f"OpenCTI bridge ignored automatic IOC hook {hook_name} to prevent loops")
                result_data = {"status": "ignored", "message": f"Automatic IOC hook {hook_name} ignored to prevent loops."}
            else:
                self.log.info(f"OpenCTI bridge ignored hook {hook_name}")
                result_data = {"status": "ignored", "message": f"Hook {hook_name} ignored."}
            return InterfaceStatus.I2Success(data=result_data, logs=list(self.message_queue))
        except Exception as exc:
            self.log.error(f"OpenCTI bridge module failed: {exc}")
            return InterfaceStatus.I2Error(data={"status": "error", "message": str(exc)}, message=str(exc), logs=list(self.message_queue))
PYIFACE
    docker exec "$c" sh -lc "rm -rf '$pkg_dir/__pycache__'; '$py' -m py_compile '$pkg_dir/IrisOpenCTIBridgeInterface.py'"
    if ! config_output="$(docker exec -i "$c" "$py" - <<'PYCONFTEST' 2>&1
import importlib

pkg = importlib.import_module("iris_opencti_bridge_module")
conf = importlib.import_module("iris_opencti_bridge_module.IrisOpenCTIBridgeConfig")

assert getattr(pkg, "__iris_module_interface", "") == "IrisOpenCTIBridgeInterface"
assert conf.module_name == "IrisOpenCTIBridge"
assert conf.interface_version == "1.2.0"
assert conf.pipeline_support is False

print("config_import_ok")
PYCONFTEST
)"; then
      printf '%s\n' "$config_output"
      python3 - <<'PY'
import json
print(json.dumps({
  "status": "error",
  "file_install_ok": True,
  "config_import_ok": False,
  "registration_ok": False,
  "message": "Module files were copied, but lightweight config import failed.",
  "recommended_action": "Check package files inside the IRIS container and rerun option 10."
}, indent=2, sort_keys=True))
PY
      return 1
    fi
    printf '[INFO] %s: %s\n' "$c" "$config_output"
  done

  info "Restarting IRIS containers so the module package can be loaded."
  iris_restart_containers >/dev/null
  ensure_iris_app_ready "OpenCTI IRIS module restart" || return 1

  app_py=$(opencti_container_python iriswebapp_app)
  set +e
  registration_output="$(docker exec -i iriswebapp_app sh -lc "cd /iriswebapp && '$app_py' - '$bridge_url'" <<'PYREGISTER' 2>&1
import copy
import inspect
import json
import sys
import traceback

PACKAGE = "iris_opencti_bridge_module"
TARGET = "IrisOpenCTIBridge"
BRIDGE_URL = sys.argv[1]

result = {
    "status": "unknown",
    "file_install_ok": True,
    "config_import_ok": True,
    "package": PACKAGE,
    "module_name": TARGET,
    "registration_attempted": False,
    "registration_ok": False,
    "already_registered": False,
    "hooks_update_attempted": False,
    "hooks_update_ok": False,
    "hooks_update_reason": "",
    "stale_force_hooks_cleanup_attempted": False,
    "stale_force_hooks_removed": 0,
    "verification_attempted": False,
    "verification_ok": False,
    "config_update_attempted": False,
    "config_update_ok": False,
    "config_url": BRIDGE_URL,
    "module_visible_expected": False,
    "matches": [],
    "errors": [],
}

def status_message(status):
    if hasattr(status, "get_message"):
        try:
            return status.get_message()
        except Exception:
            pass
    return str(status)

def status_failed(status):
    if hasattr(status, "is_failure"):
        try:
            return bool(status.is_failure())
        except Exception:
            return False
    return False

try:
    from app import app
    try:
        from app import db
    except Exception:
        from app.datamgmt.manage.manage_db import db
    from app.iris_engine.module_handler.module_handler import register_module
    from sqlalchemy.orm.attributes import flag_modified

    try:
        from app.iris_engine.module_handler.module_handler import iris_update_hooks
    except Exception:
        iris_update_hooks = None

    with app.app_context():
        result["registration_attempted"] = True
        status = register_module(PACKAGE)
        message = status_message(status)
        result["register_module_message"] = message
        lower = message.lower()
        if "already exists" in lower or "already registered" in lower:
            result["already_registered"] = True
            result["registration_ok"] = True
        elif not status_failed(status):
            result["registration_ok"] = True
        else:
            result["errors"].append(message)

        if result["registration_ok"]:
            result["hooks_update_attempted"] = True
            if iris_update_hooks is None:
                result["hooks_update_ok"] = False
                result["hooks_update_reason"] = "unsupported_or_missing"
            else:
                try:
                    params = inspect.signature(iris_update_hooks).parameters
                    if len(params) == 0:
                        iris_update_hooks()
                    else:
                        iris_update_hooks()
                    result["hooks_update_ok"] = True
                except TypeError as exc:
                    result["hooks_update_ok"] = False
                    result["hooks_update_reason"] = "unsupported_or_signature_mismatch: " + str(exc)
                except Exception as exc:
                    result["hooks_update_ok"] = False
                    result["hooks_update_reason"] = str(exc)

            result["stale_force_hooks_cleanup_attempted"] = True
            import app.models.models as models
            stale_removed = 0
            for model_name in dir(models):
                obj = getattr(models, model_name)
                if "Hook" not in model_name or not hasattr(obj, "query") or not hasattr(obj, "__table__"):
                    continue
                try:
                    rows = obj.query.all()
                except Exception:
                    continue
                for hook_row in rows:
                    values = []
                    for column in getattr(obj, "__table__").columns:
                        try:
                            values.append(str(getattr(hook_row, column.name)))
                        except Exception:
                            pass
                    blob = " ".join(values)
                    if "OpenCTI: Force enrich" in blob:
                        try:
                            db.session.delete(hook_row)
                            stale_removed += 1
                        except Exception as exc:
                            result["errors"].append(f"failed deleting stale force hook from {model_name}: {exc}")
            if stale_removed:
                db.session.commit()
            result["stale_force_hooks_removed"] = stale_removed

            result["verification_attempted"] = True
            from app.models.models import IrisModule
            rows = IrisModule.query.all()
            matches = []
            for row in rows:
                data = {}
                for attr in ["id", "module_name", "name", "module_human_name", "module_version", "interface_version", "active"]:
                    if hasattr(row, attr):
                        try:
                            value = getattr(row, attr)
                            if isinstance(value, (str, int, float, bool)) or value is None:
                                data[attr] = value
                            else:
                                data[attr] = str(value)
                        except Exception:
                            pass
                blob = " ".join(str(v) for v in data.values())
                if TARGET in blob or PACKAGE in blob:
                    result["config_update_attempted"] = True
                    if hasattr(row, "module_config"):
                        cfg = copy.deepcopy(getattr(row, "module_config") or [])
                        found_url = False
                        if isinstance(cfg, list):
                            for item in cfg:
                                if isinstance(item, dict) and item.get("param_name") == "bridge_control_url":
                                    item["default"] = BRIDGE_URL
                                    item["value"] = BRIDGE_URL
                                    found_url = True
                        elif isinstance(cfg, dict):
                            item = cfg.get("bridge_control_url")
                            if isinstance(item, dict):
                                item["default"] = BRIDGE_URL
                                item["value"] = BRIDGE_URL
                                found_url = True
                            elif "bridge_control_url" in cfg:
                                cfg["bridge_control_url"] = BRIDGE_URL
                                found_url = True
                        if found_url:
                            row.module_config = cfg
                            flag_modified(row, "module_config")
                            db.session.add(row)
                            data["bridge_control_url_default"] = BRIDGE_URL
                            data["bridge_control_url_value"] = BRIDGE_URL
                        else:
                            result["errors"].append("bridge_control_url not found in module_config")
                    matches.append(data)
            if result["config_update_attempted"]:
                db.session.commit()
            result["matches"] = matches
            result["verification_ok"] = bool(matches)
            result["config_update_ok"] = bool(matches) and not any("bridge_control_url not found" in err for err in result["errors"])
            if not matches:
                result["errors"].append("Module registration succeeded, but IrisModule verification did not find IrisOpenCTIBridge.")
            elif not result["config_update_ok"]:
                result["errors"].append("Module registration succeeded, but bridge_control_url DB config update did not verify.")

except Exception as exc:
    result["errors"].append(str(exc))
    result["traceback"] = traceback.format_exc()

result["module_visible_expected"] = bool(result["registration_ok"] and result["verification_ok"] and result["config_update_ok"])
result["manual_verification"] = "Open IRIS > Advanced > Modules management, click Refresh, search for IrisOpenCTIBridge."
if result["registration_ok"] and result["verification_ok"] and result["config_update_ok"]:
    result["status"] = "ok"
else:
    result["status"] = "error"
    if not result["registration_ok"]:
        result["message"] = "Module files installed, but IRIS registration failed."
    elif not result["verification_ok"]:
        result["message"] = "Module registered, but IRIS database verification failed."
    else:
        result["message"] = "Module registered, but IRIS module_config bridge_control_url update failed."
    result["recommended_action"] = "Check iriswebapp_app logs and try manual Add module with package iris_opencti_bridge_module."

print(json.dumps(result, indent=2, sort_keys=True))
raise SystemExit(0 if result["status"] == "ok" else 1)
PYREGISTER
)"
  registration_rc=$?
  set -e
  printf '%s\n' "$registration_output"
  if [ "$registration_rc" -ne 0 ]; then
    return 1
  fi
  for c in "${module_containers[@]}"; do
    py=$(opencti_container_python "$c")
    opencti_test_bridge_api_from_container "$c" "$py" "$bridge_url" || return 1
  done

  opencti_write_report "iris-module-installed"
}

opencti_rollback_iris_module() {
  iris_container_check
  warn "This removes only the OpenCTI bridge IRIS module registration and package. IRIS core files and data are not touched."
  if ! prompt_yes_no "Continue with IRIS OpenCTI module rollback?"; then
    die "Cancelled."
  fi
  if docker_container_running iriswebapp_app; then
    app_py=$(opencti_container_python iriswebapp_app)
    set +e
    rollback_output="$(docker exec -i iriswebapp_app sh -lc "cd /iriswebapp && '$app_py' -" <<'PYROLLBACKREG' 2>&1
import json
import traceback

PACKAGE = "iris_opencti_bridge_module"
TARGET = "IrisOpenCTIBridge"

result = {
    "status": "unknown",
    "package": PACKAGE,
    "module_name": TARGET,
    "registration_remove_attempted": True,
    "registration_removed": False,
    "hooks_removed": 0,
    "module_rows_removed": 0,
    "errors": [],
}

try:
    from app import app
    try:
        from app import db
    except Exception:
        from app.datamgmt.manage.manage_db import db
    import app.models.models as models

    with app.app_context():
        removed = 0
        hook_removed = 0
        for name in dir(models):
            obj = getattr(models, name)
            if not hasattr(obj, "query") or not hasattr(obj, "__table__"):
                continue
            if "Module" not in name and "Hook" not in name:
                continue
            try:
                rows = obj.query.all()
            except Exception:
                continue
            for row in rows:
                values = []
                for column in getattr(obj, "__table__").columns:
                    try:
                        values.append(str(getattr(row, column.name)))
                    except Exception:
                        pass
                blob = " ".join(values)
                if TARGET in blob or PACKAGE in blob:
                    try:
                        db.session.delete(row)
                        removed += 1
                        if "Hook" in name:
                            hook_removed += 1
                    except Exception as exc:
                        result["errors"].append(f"failed deleting {name}: {exc}")
        db.session.commit()
        result["module_rows_removed"] = removed
        result["hooks_removed"] = hook_removed
        result["registration_removed"] = True

        try:
            from app.iris_engine.module_handler.module_handler import iris_update_hooks
            iris_update_hooks()
            result["hooks_refresh_ok"] = True
        except Exception as exc:
            result["hooks_refresh_ok"] = False
            result["hooks_refresh_reason"] = str(exc)

except Exception as exc:
    result["errors"].append(str(exc))
    result["traceback"] = traceback.format_exc()

result["status"] = "ok" if result["registration_removed"] else "error"
print(json.dumps(result, indent=2, sort_keys=True))
raise SystemExit(0 if result["status"] == "ok" else 1)
PYROLLBACKREG
)"
    rollback_rc=$?
    set -e
    printf '%s\n' "$rollback_output"
    if [ "$rollback_rc" -ne 0 ]; then
      return 1
    fi
  else
    warn "iriswebapp_app is not running; registration rollback was skipped."
    docker ps --format 'table {{.Names}}\t{{.Status}}' | grep -E 'iriswebapp|NAME' || true
  fi
  local module_containers=(iriswebapp_app iriswebapp_worker)
  local c
  for c in "${module_containers[@]}"; do
    if ! docker inspect "$c" >/dev/null 2>&1; then
      warn "Container not found, skipping package removal: $c"
      continue
    fi
    if ! docker_container_running "$c"; then
      warn "Container is not running, skipping package removal until it is started: $c"
      continue
    fi
    py=$(opencti_container_python "$c")
    site=$(opencti_container_site_packages "$c" "$py")
    pkg_dir="$site/iris_opencti_bridge_module"
    docker exec "$c" sh -lc "
      rm -rf '$pkg_dir'
      echo '[INFO] Removed OpenCTI module package in $c'
    "
  done
  if docker inspect iriswebapp_app >/dev/null 2>&1 || docker inspect iriswebapp_worker >/dev/null 2>&1 || docker inspect iriswebapp_nginx >/dev/null 2>&1; then
    info "Restarting IRIS containers after OpenCTI module rollback."
    iris_restart_containers >/dev/null
    if docker_container_running iriswebapp_app; then
      ensure_iris_app_ready "OpenCTI IRIS module rollback restart" || return 1
    else
      warn "iriswebapp_app is not running after rollback restart; health wait skipped."
    fi
  fi
  opencti_write_report "iris-module-rolled-back"
}

opencti_write_bridge_files() {
  target_dir=${1:-$OPENCTI_BRIDGE_DIR}
  production_dir=$OPENCTI_BRIDGE_DIR
  local OPENCTI_CORE_DIR="$target_dir/opencti_iris_bridge_core"
  local OPENCTI_RUNNER="$target_dir/opencti_iris_bridge_runner.py"
  local OPENCTI_API="$target_dir/opencti_iris_bridge_control_api.py"
  opencti_prepare_dirs
  if [ "$target_dir" != "$production_dir" ]; then
    rm -rf "$target_dir"
    mkdir -p "$target_dir"
  fi
  mkdir -p "$OPENCTI_CORE_DIR"
  if [ "$target_dir" = "$production_dir" ]; then
    opencti_backup_file "$OPENCTI_RUNNER"
    opencti_backup_file "$OPENCTI_API"
  fi
  if [ "$target_dir" = "$production_dir" ] && [ -d "$OPENCTI_CORE_DIR" ]; then
    backup_dir="${OPENCTI_CORE_DIR}.backup-$(date +%Y%m%d_%H%M%S)"
    cp -a "$OPENCTI_CORE_DIR" "$backup_dir" 2>/dev/null || true
    info "Backup created: $backup_dir"
  fi

  cat >"$OPENCTI_CORE_DIR/__init__.py" <<'PY'
"""OpenCTI to DFIR-IRIS bridge core package."""

BRIDGE_VERSION = "2.0.0"
PY

  cat >"$OPENCTI_CORE_DIR/config.py" <<'PY'
import json
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


SECRET_KEYS = ("TOKEN", "PASSWORD", "SECRET", "API_KEY", "KEY")


def load_env_file(path):
    env = {}
    p = Path(path)
    if not p.exists():
        return env
    for raw in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def as_bool(value, default=False):
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def normalize_url(value):
    value = str(value or "").strip().rstrip("/")
    if not value:
        return ""
    parsed = urlsplit(value)
    if not parsed.scheme or not parsed.netloc:
        return value
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path.rstrip("/"), "", ""))


def redact_value(key, value):
    if any(token in key.upper() for token in SECRET_KEYS):
        return "<redacted>" if value else ""
    return value


@dataclass
class BridgeConfig:
    env_file: str
    opencti_url: str
    opencti_token: str
    opencti_verify_ssl: bool
    opencti_ca_bundle: str
    iris_url: str
    iris_token: str
    iris_verify_ssl: bool
    iris_ca_bundle: str
    iris_case_ids: list
    max_cases: int
    max_iocs_per_case: int
    reenrich_hours: int
    min_score: int
    min_confidence: int
    default_iris_tlp_id: int
    update_iris_ioc: bool
    add_case_note: bool
    note_dir_name: str
    dry_run: bool
    state_db: str
    watchlist: str
    run_log: str
    capabilities_file: str
    last_preflight_file: str
    last_dry_run_file: str
    last_live_write_file: str

    @property
    def live_writes_enabled(self):
        return not self.dry_run and (self.update_iris_ioc or self.add_case_note)

    def validate(self, require_opencti=True, require_iris=True):
        missing = []
        if require_opencti:
            for name, value in (("OPENCTI_URL", self.opencti_url), ("OPENCTI_TOKEN", self.opencti_token)):
                if not value:
                    missing.append(name)
        if require_iris:
            for name, value in (("IRIS_URL", self.iris_url), ("IRIS_TOKEN", self.iris_token)):
                if not value:
                    missing.append(name)
        if missing:
            raise ValueError("Missing required bridge configuration: " + ", ".join(missing))
        for name, path in (("OPENCTI_CA_BUNDLE", self.opencti_ca_bundle), ("IRIS_CA_BUNDLE", self.iris_ca_bundle)):
            if path and not Path(path).is_file():
                raise ValueError(f"{name} does not exist or is not a file: {path}")

    def redacted(self):
        raw = {
            "OPENCTI_URL": self.opencti_url,
            "OPENCTI_TOKEN": self.opencti_token,
            "OPENCTI_CA_BUNDLE": self.opencti_ca_bundle,
            "IRIS_URL": self.iris_url,
            "IRIS_TOKEN": self.iris_token,
            "IRIS_CA_BUNDLE": self.iris_ca_bundle,
            "DRY_RUN": str(self.dry_run).lower(),
            "UPDATE_IRIS_IOC": str(self.update_iris_ioc).lower(),
            "ADD_CASE_NOTE": str(self.add_case_note).lower(),
            "STATE_DB": self.state_db,
            "CAPABILITIES_FILE": self.capabilities_file,
        }
        return {key: redact_value(key, value) for key, value in raw.items()}


def load_config(env_file=None, dry_run_override=None):
    env_file = env_file or os.environ.get("BRIDGE_ENV_FILE", "/etc/opencti-iris-bridge/opencti-iris-bridge.env")
    env = load_env_file(env_file)
    merged = dict(env)
    merged.update(os.environ)
    dry_run = as_bool(merged.get("DRY_RUN"), True)
    if dry_run_override is not None:
        dry_run = bool(dry_run_override)
    state_dir = str(Path(merged.get("STATE_DB", "/var/lib/opencti-iris-bridge/state.sqlite3")).parent)
    return BridgeConfig(
        env_file=env_file,
        opencti_url=normalize_url(merged.get("OPENCTI_URL", "")),
        opencti_token=merged.get("OPENCTI_TOKEN", ""),
        opencti_verify_ssl=as_bool(merged.get("OPENCTI_VERIFY_SSL"), True),
        opencti_ca_bundle=merged.get("OPENCTI_CA_BUNDLE", ""),
        iris_url=normalize_url(merged.get("IRIS_URL", "")),
        iris_token=merged.get("IRIS_TOKEN", ""),
        iris_verify_ssl=as_bool(merged.get("IRIS_VERIFY_SSL"), False),
        iris_ca_bundle=merged.get("IRIS_CA_BUNDLE", ""),
        iris_case_ids=[x.strip() for x in merged.get("IRIS_CASE_IDS", "").split(",") if x.strip()],
        max_cases=int(merged.get("MAX_CASES", "500")),
        max_iocs_per_case=int(merged.get("MAX_IOCS_PER_CASE", "500")),
        reenrich_hours=int(merged.get("REENRICH_HOURS", "24")),
        min_score=int(merged.get("MIN_SCORE", "0")),
        min_confidence=int(merged.get("MIN_CONFIDENCE", "0")),
        default_iris_tlp_id=int(merged.get("DEFAULT_IRIS_TLP_ID", "2")),
        update_iris_ioc=as_bool(merged.get("UPDATE_IRIS_IOC"), False),
        add_case_note=as_bool(merged.get("ADD_CASE_NOTE"), False),
        note_dir_name=merged.get("NOTE_DIR_NAME", "OpenCTI Enrichment"),
        dry_run=dry_run,
        state_db=merged.get("STATE_DB", "/var/lib/opencti-iris-bridge/state.sqlite3"),
        watchlist=merged.get("WATCHLIST", "/var/lib/opencti-iris-bridge/enabled_cases.json"),
        run_log=merged.get("RUN_LOG", "/var/log/opencti-iris-bridge/bridge.log"),
        capabilities_file=merged.get("CAPABILITIES_FILE", f"{state_dir}/opencti-capabilities.json"),
        last_preflight_file=merged.get("LAST_PREFLIGHT_FILE", f"{state_dir}/last-preflight.json"),
        last_dry_run_file=merged.get("LAST_DRY_RUN_FILE", f"{state_dir}/last-dry-run.json"),
        last_live_write_file=merged.get("LAST_LIVE_WRITE_FILE", f"{state_dir}/last-live-write.json"),
    )


def write_json(path, data):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

  cat >"$OPENCTI_CORE_DIR/logging_utils.py" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def utc_now():
    return datetime.now(timezone.utc).isoformat()


class BridgeLogger:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, level, message, **extra):
        event = {"ts": utc_now(), "level": level, "message": message}
        event.update(extra)
        line = json.dumps(event, separators=(",", ":"), sort_keys=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        print(line, file=sys.stderr, flush=True)
PY

  cat >"$OPENCTI_CORE_DIR/matching.py" <<'PY'
import re
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


def normalize_value(value):
    value = str(value or "").strip()
    if value.startswith("hxxp://"):
        return "http://" + value[7:]
    if value.startswith("hxxps://"):
        return "https://" + value[8:]
    return value


def infer_ioc_type(ioc_type, value):
    t = str(ioc_type or "").lower()
    v = normalize_value(value)
    vl = v.lower()
    if "sha256" in t or SHA256_RE.match(vl):
        return "sha256"
    if "sha1" in t or SHA1_RE.match(vl):
        return "sha1"
    if "md5" in t or MD5_RE.match(vl):
        return "md5"
    if "url" in t or vl.startswith(("http://", "https://")):
        return "url"
    if "email" in t or "@" in vl:
        return "email"
    if "domain" in t or "fqdn" in t or "hostname" in t:
        return "domain"
    if "ip" in t or IP_RE.match(vl):
        return "ip"
    return t or "unknown"


def normalize_url(value):
    value = normalize_value(value)
    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower()
        port = f":{parsed.port}" if parsed.port else ""
        path = quote(parsed.path or "/", safe="/:@")
        query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
        return urlunsplit((scheme, host + port, path.rstrip("/") or "/", query, ""))
    except Exception:
        return value.lower().rstrip("/")


def stix_pattern_values(pattern):
    values = []
    for match in re.finditer(r"=\s*'([^']+)'|=\s*\"([^\"]+)\"", str(pattern or "")):
        values.append(match.group(1) or match.group(2))
    return values


def values_match(kind, value, candidate):
    v = normalize_value(value).strip()
    c = normalize_value(candidate).strip()
    vl = v.lower().strip(".")
    cl = c.lower().strip(".")
    if not vl or not cl:
        return False
    if kind in {"ip", "md5", "sha1", "sha256", "email"}:
        return vl == cl
    if kind == "domain":
        return cl == vl or cl.endswith("." + vl)
    if kind == "url":
        return normalize_url(v) == normalize_url(c)
    return vl == cl
PY

  cat >"$OPENCTI_CORE_DIR/opencti_queries.py" <<'PY'
QUERY_LEVELS = ["enhanced", "safe", "minimal", "fallback"]

BASE_FIELDS = {
    "Indicator": ["id", "entity_type", "name", "pattern", "x_opencti_score"],
    "StixCyberObservable": ["id", "entity_type", "observable_value"],
}

OPTIONAL_FIELDS = {
    "Indicator": {
        "confidence": "confidence",
        "objectLabel": "objectLabel { value }",
        "labels": "labels { value }",
        "objectMarking": "objectMarking { definition }",
        "externalReferences": "externalReferences { edges { node { source_name url external_id } } }",
    },
    "StixCyberObservable": {
        "confidence": "confidence",
        "x_opencti_score": "x_opencti_score",
        "objectLabel": "objectLabel { value }",
        "labels": "labels { value }",
        "objectMarking": "objectMarking { definition }",
        "externalReferences": "externalReferences { edges { node { source_name url external_id } } }",
    },
}


def fields_for(kind, capabilities, level):
    supported = set((capabilities.get("supported_fields") or {}).get(kind, []))
    base = [field for field in BASE_FIELDS[kind] if field in supported]
    if not base and "id" in supported:
        base = ["id"]
    if level == "fallback":
        return [field for field in base if field in {"id", "name", "pattern", "observable_value", "entity_type"}]
    if level == "minimal":
        return base
    optional_order = ["confidence", "x_opencti_score", "objectLabel", "objectMarking", "externalReferences"]
    if level == "enhanced" and "labels" in supported and "objectLabel" not in supported:
        optional_order.insert(2, "labels")
    for field in optional_order:
        template = OPTIONAL_FIELDS.get(kind, {}).get(field)
        if template and field in supported:
            base.append(template)
    return base


def build_search_query(kind, capabilities, level):
    root = "indicators" if kind == "Indicator" else "stixCyberObservables"
    fields = "\n".join(fields_for(kind, capabilities, level))
    return f"""
query($search: String!) {{
  {root}(first: 20, search: $search) {{
    edges {{
      node {{
        {fields}
      }}
    }}
  }}
}}
"""


def root_for(kind):
    return "indicators" if kind == "Indicator" else "stixCyberObservables"
PY

  cat >"$OPENCTI_CORE_DIR/state.py" <<'PY'
import json
import shutil
import sqlite3
import time
from pathlib import Path

SCHEMA_VERSION = 3
REQUIRED_ENRICHED_IOC_COLUMNS = {
    "key": "key TEXT NOT NULL DEFAULT ''",
    "case_id": "case_id TEXT DEFAULT ''",
    "ioc_id": "ioc_id TEXT DEFAULT ''",
    "ioc_hash": "ioc_hash TEXT",
    "status": "status TEXT",
    "dry_run": "dry_run INTEGER NOT NULL DEFAULT 0",
    "last_seen": "last_seen REAL DEFAULT 0",
    "last_enriched": "last_enriched REAL DEFAULT 0",
    "opencti_ids": "opencti_ids TEXT DEFAULT ''",
    "opencti_object_ids": "opencti_object_ids TEXT DEFAULT '[]'",
    "match_count": "match_count INTEGER NOT NULL DEFAULT 0",
    "query_mode": "query_mode TEXT DEFAULT ''",
    "last_error": "last_error TEXT DEFAULT ''",
    "last_run_at": "last_run_at REAL DEFAULT 0",
    "live_write": "live_write INTEGER NOT NULL DEFAULT 0",
}
REQUIRED_NOTE_DIR_COLUMNS = {
    "case_id": "case_id TEXT NOT NULL DEFAULT ''",
    "directory_id": "directory_id TEXT",
    "created_at": "created_at REAL DEFAULT 0",
}
REQUIRED_MIGRATION_COLUMNS = {
    "version": "version INTEGER NOT NULL DEFAULT 0",
    "applied_at": "applied_at REAL NOT NULL DEFAULT 0",
    "action": "action TEXT NOT NULL DEFAULT ''",
}


class StateMigrationError(RuntimeError):
    def __init__(self, db_path, message):
        super().__init__(message)
        self.db_path = str(db_path)
        self.target = str(db_path)


def table_exists(db, table):
    row = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
    return row is not None


def table_columns(db, table):
    if not table_exists(db, table):
        return []
    return [row[1] for row in db.execute(f"PRAGMA table_info({table})").fetchall()]


def column_exists(db, table, column):
    return column in table_columns(db, table)


def add_column_if_missing(db, table, column, ddl, actions):
    if not column_exists(db, table, column):
        db.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")
        actions.append(f"add {table}.{column}")


def required_missing_columns(db):
    required = {
        "enriched_iocs": list(REQUIRED_ENRICHED_IOC_COLUMNS),
        "note_dirs": list(REQUIRED_NOTE_DIR_COLUMNS),
        "state_migrations": list(REQUIRED_MIGRATION_COLUMNS),
    }
    missing = {}
    for table, columns in required.items():
        existing = set(table_columns(db, table))
        table_missing = [column for column in columns if column not in existing]
        if table_missing:
            missing[table] = table_missing
    return missing


def backup_state_db_if_needed(db, db_path, actions):
    path = Path(db_path)
    if not path.exists() or path.stat().st_size == 0:
        return
    if not required_missing_columns(db) and int(db.execute("PRAGMA user_version").fetchone()[0] or 0) >= SCHEMA_VERSION:
        return
    backup = path.with_name(path.name + f".backup-before-schema-v{SCHEMA_VERSION}-{int(time.time())}")
    with sqlite3.connect(str(backup)) as backup_db:
        db.backup(backup_db)
    actions.append(f"backup state DB to {backup}")


def migrate_state_db(db, db_path):
    actions = []
    try:
        backup_state_db_if_needed(db, db_path, actions)
        db.execute("""CREATE TABLE IF NOT EXISTS enriched_iocs (
            key TEXT PRIMARY KEY,
            case_id TEXT DEFAULT '',
            ioc_id TEXT DEFAULT '',
            ioc_hash TEXT,
            status TEXT,
            dry_run INTEGER NOT NULL DEFAULT 0,
            last_seen REAL DEFAULT 0,
            last_enriched REAL DEFAULT 0,
            opencti_ids TEXT DEFAULT '',
            opencti_object_ids TEXT DEFAULT '[]',
            match_count INTEGER NOT NULL DEFAULT 0,
            query_mode TEXT DEFAULT '',
            last_error TEXT DEFAULT '',
            last_run_at REAL DEFAULT 0,
            live_write INTEGER NOT NULL DEFAULT 0
        )""")
        db.execute("CREATE TABLE IF NOT EXISTS note_dirs (case_id TEXT PRIMARY KEY, directory_id TEXT, created_at REAL DEFAULT 0)")
        db.execute("CREATE TABLE IF NOT EXISTS state_migrations (version INTEGER PRIMARY KEY, applied_at REAL NOT NULL DEFAULT 0, action TEXT NOT NULL DEFAULT '')")

        for column, ddl in REQUIRED_ENRICHED_IOC_COLUMNS.items():
            add_column_if_missing(db, "enriched_iocs", column, ddl, actions)
        for column, ddl in REQUIRED_NOTE_DIR_COLUMNS.items():
            add_column_if_missing(db, "note_dirs", column, ddl, actions)
        for column, ddl in REQUIRED_MIGRATION_COLUMNS.items():
            add_column_if_missing(db, "state_migrations", column, ddl, actions)

        current_version = int(db.execute("PRAGMA user_version").fetchone()[0] or 0)
        if current_version < SCHEMA_VERSION:
            actions.append(f"set user_version {current_version}->{SCHEMA_VERSION}")
        db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

        now = time.time()
        for action in actions:
            db.execute("INSERT OR REPLACE INTO state_migrations(version, applied_at, action) VALUES(?,?,?)", (SCHEMA_VERSION, now, "; ".join(actions)))
            break
        db.commit()
        return actions
    except Exception as exc:
        db.rollback()
        raise StateMigrationError(db_path, f"State DB migration failed for {db_path}: {exc}") from exc


def state_db_status(path):
    p = Path(path)
    required = {
        "enriched_iocs": list(REQUIRED_ENRICHED_IOC_COLUMNS),
        "note_dirs": list(REQUIRED_NOTE_DIR_COLUMNS),
        "state_migrations": list(REQUIRED_MIGRATION_COLUMNS),
    }
    if not p.exists():
        missing_flat = [f"{table}.{column}" for table, columns in required.items() for column in columns]
        return {
            "path": str(p),
            "exists": False,
            "schema_version": 0,
            "schema_current": False,
            "missing_columns": missing_flat,
            "missing_columns_by_table": required,
            "last_migration_timestamp": None,
            "last_migration_result": "missing_state_db",
            "migrations_applied": [],
        }
    with sqlite3.connect(str(p)) as db:
        version = int(db.execute("PRAGMA user_version").fetchone()[0] or 0)
        missing = {}
        for table, columns in required.items():
            existing = set(table_columns(db, table))
            missing_cols = [col for col in columns if col not in existing]
            if missing_cols:
                missing[table] = missing_cols
        missing_flat = [f"{table}.{column}" for table, columns in missing.items() for column in columns]
        migrations = []
        last_ts = None
        if table_exists(db, "state_migrations"):
            rows = db.execute("SELECT applied_at, action FROM state_migrations ORDER BY applied_at DESC LIMIT 10").fetchall()
            migrations = [row[1] for row in rows]
            if rows:
                last_ts = rows[0][0]
        return {
            "path": str(p),
            "exists": True,
            "schema_version": version,
            "schema_current": version >= SCHEMA_VERSION and not missing,
            "missing_columns": missing_flat,
            "missing_columns_by_table": missing,
            "last_migration_timestamp": last_ts,
            "last_migration_result": migrations[0] if migrations else "none",
            "migrations_applied": migrations,
        }


class BridgeState:
    def __init__(self, config, migrate=True):
        self.config = config
        Path(config.state_db).parent.mkdir(parents=True, exist_ok=True)
        self.migrations_applied = []
        self._migrated = False
        if migrate:
            self.migrate()

    def migrate(self):
        with sqlite3.connect(self.config.state_db) as db:
            self.migrations_applied = migrate_state_db(db, self.config.state_db)
        self._migrated = True
        return self.migrations_applied

    def ensure_migrated(self):
        if not self._migrated:
            self.migrate()

    def status(self):
        self.ensure_migrated()
        data = state_db_status(self.config.state_db)
        if self.migrations_applied:
            data["migrations_applied"] = self.migrations_applied
        return data

    def should_process(self, key, digest, force=False):
        self.ensure_migrated()
        if force:
            return True
        now = int(time.time())
        ttl = self.config.reenrich_hours * 3600
        with sqlite3.connect(self.config.state_db) as db:
            row = db.execute("SELECT ioc_hash,last_enriched,status,dry_run FROM enriched_iocs WHERE key=?", (key,)).fetchone()
        if not row:
            return True
        old_digest, last_enriched, status, dry_run = row
        if int(dry_run or 0) == 1:
            return True
        return old_digest != digest or now - int(last_enriched) >= ttl

    def mark(self, key, case_id, ioc_id, digest, status, opencti_ids, dry_run=False, match_count=0, query_mode="", last_error="", live_write=False):
        self.ensure_migrated()
        now = int(time.time())
        object_ids_json = json.dumps(list(opencti_ids or []))
        with sqlite3.connect(self.config.state_db) as db:
            db.execute("""INSERT OR REPLACE INTO enriched_iocs
                (key,case_id,ioc_id,ioc_hash,status,dry_run,last_seen,last_enriched,opencti_ids,opencti_object_ids,match_count,query_mode,last_error,last_run_at,live_write)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (key, str(case_id), str(ioc_id), digest, status, 1 if dry_run else 0, now, now, ",".join(opencti_ids or []), object_ids_json, int(match_count or 0), query_mode or "", last_error or "", now, 1 if live_write else 0))

    def note_already_written(self, key, digest, opencti_ids):
        self.ensure_migrated()
        wanted = sorted({str(item) for item in (opencti_ids or []) if str(item)})
        with sqlite3.connect(self.config.state_db) as db:
            row = db.execute("SELECT ioc_hash,opencti_object_ids,opencti_ids,dry_run,live_write FROM enriched_iocs WHERE key=?", (key,)).fetchone()
        if not row:
            return False
        old_hash, object_ids_json, object_ids_csv, dry_run, live_write = row
        if str(old_hash or "") != str(digest or ""):
            return False
        if int(dry_run or 0) == 1 or int(live_write or 0) != 1:
            return False
        previous = []
        try:
            previous = json.loads(object_ids_json or "[]")
        except Exception:
            previous = [item.strip() for item in str(object_ids_csv or "").split(",") if item.strip()]
        return sorted({str(item) for item in previous if str(item)}) == wanted

    def get_note_dir(self, case_id):
        self.ensure_migrated()
        with sqlite3.connect(self.config.state_db) as db:
            row = db.execute("SELECT directory_id FROM note_dirs WHERE case_id=?", (str(case_id),)).fetchone()
        return str(row[0]) if row else None

    def set_note_dir(self, case_id, directory_id):
        self.ensure_migrated()
        with sqlite3.connect(self.config.state_db) as db:
            db.execute("INSERT OR REPLACE INTO note_dirs(case_id,directory_id,created_at) VALUES(?,?,?)", (str(case_id), str(directory_id), int(time.time())))

    def read_watchlist(self):
        path = Path(self.config.watchlist)
        if not path.exists():
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return [str(x).strip() for x in data.get("case_ids", []) if str(x).strip()]
        except Exception:
            return []

    def write_watchlist(self, case_ids):
        path = Path(self.config.watchlist)
        path.parent.mkdir(parents=True, exist_ok=True)
        clean = []
        seen = set()
        for case_id in case_ids:
            case_id = str(case_id).strip()
            if case_id and case_id not in seen:
                seen.add(case_id)
                clean.append(case_id)
        path.write_text(json.dumps({"case_ids": clean, "updated_at": int(time.time())}, indent=2) + "\n", encoding="utf-8")
PY

  cat >"$OPENCTI_CORE_DIR/http_utils.py" <<'PY'
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request


class BridgeHTTPError(RuntimeError):
    def __init__(self, message, target="", error_type="http_error", recommended_action=""):
        super().__init__(message)
        self.target = target
        self.error_type = error_type
        self.recommended_action = recommended_action


class SSLCertificateVerifyError(BridgeHTTPError):
    def __init__(self, target, original):
        super().__init__(
            "SSL certificate verification failed. The server appears to use a self-signed or untrusted certificate.",
            target=target,
            error_type="ssl_certificate_verify_failed",
            recommended_action="Disable SSL verification for lab/self-signed deployments or provide a trusted CA bundle.",
        )
        self.original = original


def ssl_context(verify, ca_bundle=None):
    if not verify:
        return ssl._create_unverified_context()
    if ca_bundle:
        return ssl.create_default_context(cafile=ca_bundle)
    return None


def is_ssl_verify_error(exc):
    reason = getattr(exc, "reason", exc)
    if isinstance(reason, ssl.SSLCertVerificationError):
        return True
    text = str(exc).lower()
    return "certificate verify failed" in text or "self-signed certificate" in text


class HTTPClient:
    def __init__(self, token, verify_ssl=True, ca_bundle="", user_agent="opencti-iris-bridge"):
        self.token = token
        self.verify_ssl = verify_ssl
        self.ca_bundle = ca_bundle
        self.user_agent = user_agent

    def json(self, method, url, payload=None, params=None, timeout=60):
        if params:
            clean = {k: v for k, v in params.items() if v not in [None, ""]}
            if clean:
                url += "?" + urllib.parse.urlencode(clean)
        headers = {"Authorization": "Bearer " + self.token, "Accept": "application/json", "User-Agent": self.user_agent}
        data = None
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        last_error = None
        for attempt in range(1, 4):
            try:
                with urllib.request.urlopen(req, timeout=timeout, context=ssl_context(self.verify_ssl, self.ca_bundle)) as resp:
                    raw = resp.read().decode("utf-8", errors="replace")
                    return json.loads(raw) if raw.strip() else {}
            except urllib.error.HTTPError as exc:
                body = exc.read().decode("utf-8", errors="replace")
                if exc.code in {429, 500, 502, 503, 504} and attempt < 3:
                    time.sleep(attempt * 2)
                    continue
                raise RuntimeError(f"HTTP {exc.code} for {url}: {body[:1000]}")
            except urllib.error.URLError as exc:
                if is_ssl_verify_error(exc):
                    raise SSLCertificateVerifyError(url, exc) from exc
                last_error = exc
                if attempt < 3:
                    time.sleep(attempt * 2)
                    continue
                raise RuntimeError(f"Connection failed for {url}: {exc}") from exc
        raise RuntimeError(str(last_error))
PY

  cat >"$OPENCTI_CORE_DIR/opencti_client.py" <<'PY'
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from .config import write_json
from .http_utils import HTTPClient
from .matching import stix_pattern_values, values_match
from .opencti_queries import QUERY_LEVELS, build_search_query, root_for


VALIDATION_RE = re.compile(r"Cannot query field|Unknown argument|Field .* must not have a selection|Expected type", re.I)


class GraphQLValidationError(RuntimeError):
    pass


class OpenCTIClient:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.http = HTTPClient(config.opencti_token, config.opencti_verify_ssl, config.opencti_ca_bundle)
        self.capabilities = self.load_capabilities()

    def load_capabilities(self):
        path = Path(self.config.capabilities_file)
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {
            "opencti_version": "",
            "supported_query_level": "minimal",
            "supported_fields": {},
            "unsupported_fields": {},
            "schema_warnings": [],
            "last_successful_query_mode": "minimal",
            "last_downgrade_reason": "",
            "last_graphql_validation_error": "",
        }

    def save_capabilities(self):
        self.capabilities["updated_at"] = datetime.now(timezone.utc).isoformat()
        write_json(self.config.capabilities_file, self.capabilities)

    def graphql(self, query, variables=None):
        payload = self.http.json("POST", self.config.opencti_url + "/graphql", {"query": query, "variables": variables or {}})
        if payload.get("errors"):
            text = json.dumps(payload["errors"])
            if VALIDATION_RE.search(text):
                raise GraphQLValidationError(text[:1500])
            raise RuntimeError(text[:1500])
        return payload.get("data") or {}

    def type_fields(self, type_name):
        data = self.graphql("query($name:String!){ __type(name:$name){ fields { name } } }", {"name": type_name})
        fields = (((data.get("__type") or {}).get("fields")) or [])
        return sorted({item.get("name") for item in fields if item.get("name")})

    def detect_version(self):
        for query in ("query { about { version } }", "query { settings { platform_version } }"):
            try:
                data = self.graphql(query)
                if data.get("about", {}).get("version"):
                    return data["about"]["version"]
                if data.get("settings", {}).get("platform_version"):
                    return data["settings"]["platform_version"]
            except Exception:
                continue
        return ""

    def detect_capabilities(self):
        self.config.validate(require_opencti=True, require_iris=False)
        supported = {}
        unsupported = {}
        for type_name in ("Indicator", "StixCyberObservable"):
            fields = self.type_fields(type_name)
            supported[type_name] = fields
            wanted = {
                "Indicator": ["id", "entity_type", "name", "pattern", "x_opencti_score", "confidence", "objectLabel", "labels", "objectMarking", "externalReferences"],
                "StixCyberObservable": ["id", "entity_type", "observable_value", "x_opencti_score", "confidence", "objectLabel", "labels", "objectMarking", "externalReferences"],
            }[type_name]
            unsupported[type_name] = [field for field in wanted if field not in fields]
        caps = {
            "opencti_version": self.detect_version(),
            "supported_fields": supported,
            "unsupported_fields": unsupported,
            "schema_warnings": [],
            "last_successful_query_mode": "",
            "supported_query_level": "",
            "last_downgrade_reason": "",
            "last_graphql_validation_error": "",
        }
        self.capabilities = caps
        mode, warnings = self.find_working_query_mode()
        caps["supported_query_level"] = mode
        caps["last_successful_query_mode"] = mode
        caps["schema_warnings"] = warnings
        self.save_capabilities()
        return caps

    def find_working_query_mode(self):
        warnings = []
        for level in QUERY_LEVELS:
            try:
                for kind in ("Indicator", "StixCyberObservable"):
                    query = build_search_query(kind, self.capabilities, level)
                    self.graphql(query, {"search": "__opencti_iris_bridge_preflight__"})
                return level, warnings
            except GraphQLValidationError as exc:
                warnings.append({"mode": level, "error": str(exc)[:500]})
                continue
        raise GraphQLValidationError("No OpenCTI query mode validated successfully")

    def preflight(self):
        self.graphql("query { __typename }")
        return self.detect_capabilities()

    def _edges(self, value):
        if isinstance(value, dict) and isinstance(value.get("edges"), list):
            return [(edge or {}).get("node") or {} for edge in value.get("edges") or []]
        if isinstance(value, list):
            return value
        return []

    def _nested_values(self, obj, key, value_key):
        raw = obj.get(key)
        values = []
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, dict) and item.get(value_key):
                    values.append(item.get(value_key))
        elif isinstance(raw, dict):
            if raw.get(value_key):
                values.append(raw.get(value_key))
            for node in self._edges(raw):
                if node.get(value_key):
                    values.append(node.get(value_key))
        return values

    def _candidate_values(self, obj):
        values = []
        for key in ("observable_value", "value", "name"):
            if obj.get(key):
                values.append(obj.get(key))
        if obj.get("pattern"):
            values.extend(stix_pattern_values(obj.get("pattern")))
        return values

    def _confidence_applicability(self, type_name):
        supported = set((self.capabilities.get("supported_fields") or {}).get(type_name, []))
        if type_name == "Indicator" and "confidence" in supported:
            return True, ""
        if type_name == "StixCyberObservable":
            return False, "OpenCTI schema does not expose confidence on StixCyberObservable"
        return False, "OpenCTI schema does not expose confidence on this object type"

    def _threshold_metadata(self, obj, type_name):
        score_raw = obj.get("x_opencti_score")
        confidence_raw = obj.get("confidence")
        confidence_applicable, confidence_reason = self._confidence_applicability(type_name)
        score_applied = score_raw not in [None, ""]
        confidence_applied = confidence_applicable and confidence_raw not in [None, ""]
        confidence_skipped_reason = ""
        if not confidence_applied:
            if not confidence_applicable and type_name == "StixCyberObservable":
                confidence_skipped_reason = "confidence_not_supported_for_stix_cyber_observable"
            elif not confidence_applicable:
                confidence_skipped_reason = "confidence_not_supported_for_object_type"
            else:
                confidence_skipped_reason = "confidence_value_missing"
        return {
            "score_threshold": self.config.min_score,
            "score_threshold_applied": score_applied,
            "score_threshold_skipped_reason": "" if score_applied else "score_value_missing",
            "confidence_threshold": self.config.min_confidence,
            "confidence_threshold_applied": confidence_applied,
            "confidence_threshold_skipped_reason": confidence_skipped_reason,
            "confidence_applicable": confidence_applicable,
            "confidence_unavailable_reason": "" if confidence_applicable else confidence_reason,
        }

    def _score_allowed(self, obj, type_name):
        meta = self._threshold_metadata(obj, type_name)
        if meta["score_threshold_applied"]:
            try:
                if int(obj.get("x_opencti_score")) < self.config.min_score:
                    return False
            except Exception:
                return False
        if meta["confidence_threshold_applied"]:
            try:
                if int(obj.get("confidence")) < self.config.min_confidence:
                    return False
            except Exception:
                return False
        return True

    def _normalize_match(self, obj, type_name):
        labels = self._nested_values(obj, "objectLabel", "value") + self._nested_values(obj, "labels", "value")
        markings = self._nested_values(obj, "objectMarking", "definition")
        refs = []
        for node in self._edges(obj.get("externalReferences")):
            refs.append({k: node.get(k) for k in ("source_name", "url", "external_id") if node.get(k)})
        threshold_meta = self._threshold_metadata(obj, type_name)
        family = "indicator" if type_name == "Indicator" else "observable"
        return {
            "id": obj.get("id"),
            "opencti_object_family": family,
            "entity_type": obj.get("entity_type"),
            "type": obj.get("entity_type"),
            "name": obj.get("name") or obj.get("observable_value") or obj.get("pattern"),
            "score": obj.get("x_opencti_score"),
            "confidence": obj.get("confidence") if threshold_meta["confidence_applicable"] else None,
            "confidence_applicable": threshold_meta["confidence_applicable"],
            "confidence_unavailable_reason": threshold_meta["confidence_unavailable_reason"],
            "score_threshold": threshold_meta["score_threshold"],
            "score_threshold_applied": threshold_meta["score_threshold_applied"],
            "score_threshold_skipped_reason": threshold_meta["score_threshold_skipped_reason"],
            "confidence_threshold": threshold_meta["confidence_threshold"],
            "confidence_threshold_applied": threshold_meta["confidence_threshold_applied"],
            "confidence_threshold_skipped_reason": threshold_meta["confidence_threshold_skipped_reason"],
            "related_indicator_confidence": None,
            "related_indicator_confidence_source": "",
            "labels": sorted({str(x) for x in labels if x}),
            "markings": sorted({str(x) for x in markings if x}),
            "external_references": refs,
        }

    def downgrade_mode(self, current, reason):
        order = QUERY_LEVELS
        try:
            idx = order.index(current)
        except ValueError:
            idx = 0
        next_mode = order[min(idx + 1, len(order) - 1)]
        self.capabilities["last_downgrade_reason"] = reason[:500]
        self.capabilities["last_graphql_validation_error"] = reason[:500]
        self.capabilities["last_successful_query_mode"] = next_mode
        self.capabilities["supported_query_level"] = next_mode
        self.save_capabilities()
        self.logger.log("warning", "opencti_query_mode_downgraded", from_mode=current, to_mode=next_mode, reason=reason[:300])
        return next_mode

    def search_ioc(self, value, kind):
        if not (self.capabilities.get("supported_fields") or {}) or not (self.capabilities.get("last_successful_query_mode") or self.capabilities.get("supported_query_level")):
            self.logger.log("warning", "opencti_capabilities_missing_or_incomplete_runtime_detection")
            self.detect_capabilities()
        mode = self.capabilities.get("last_successful_query_mode") or self.capabilities.get("supported_query_level") or "minimal"
        for attempt in range(2):
            try:
                matches = []
                seen = set()
                for type_name in ("Indicator", "StixCyberObservable"):
                    query = build_search_query(type_name, self.capabilities, mode)
                    data = self.graphql(query, {"search": value})
                    for obj in self._edges(data.get(root_for(type_name))):
                        if not self._score_allowed(obj, type_name):
                            continue
                        if not any(values_match(kind, value, candidate) for candidate in self._candidate_values(obj)):
                            continue
                        oid = str(obj.get("id") or "")
                        if oid in seen:
                            continue
                        seen.add(oid)
                        matches.append(self._normalize_match(obj, type_name))
                self.capabilities["last_successful_query_mode"] = mode
                self.capabilities["last_graphql_validation_error"] = ""
                self.save_capabilities()
                return matches, mode
            except GraphQLValidationError as exc:
                if attempt == 0:
                    mode = self.downgrade_mode(mode, str(exc))
                    continue
                raise
        return [], mode
PY

  cat >"$OPENCTI_CORE_DIR/reporting.py" <<'PY'
def markdown_value(value):
    if value in [None, ""]:
        return "N/A"
    return str(value).replace("|", "\\|").replace("\n", "<br>")


def human_result(result):
    if int(result.get("match_count") or 0) > 0:
        return "Context found"
    return "No OpenCTI context found"


def analyst_meaning(result):
    if int(result.get("match_count") or 0) > 0:
        return "OpenCTI found threat-intelligence context. Validate it against local telemetry before escalation or containment."
    return "OpenCTI did not return matching intelligence for this IOC. Continue normal triage using local evidence."


def object_family(match):
    family = str(match.get("opencti_object_family") or "").lower()
    if family == "indicator":
        return "Indicator"
    if family == "observable":
        return "Observable"
    return markdown_value(family or "OpenCTI object")


def source_reference_from_ref(ref):
    if not isinstance(ref, dict):
        return ""
    parts = []
    for key in ("source_name", "external_id", "url"):
        value = ref.get(key)
        if value not in [None, ""]:
            parts.append(str(value))
    return " ".join(parts)


def match_source(match):
    refs = match.get("external_references") or []
    rendered = [source_reference_from_ref(ref) for ref in refs]
    rendered = [item for item in rendered if item]
    return "; ".join(rendered[:5]) if rendered else "N/A"


def first_source_reference(matches):
    for match in matches or []:
        source = match_source(match)
        if source != "N/A":
            return source
    return "N/A"


def threshold_text(match, kind):
    configured = match.get(f"{kind}_threshold")
    applied = bool(match.get(f"{kind}_threshold_applied"))
    reason = match.get(f"{kind}_threshold_skipped_reason") or ""
    if applied:
        return f"Configured: {markdown_value(configured)}; applied and passed"
    if kind == "confidence" and match.get("opencti_object_family") == "observable":
        return f"Configured: {markdown_value(configured)}; not applied to this observable match"
    if reason:
        return f"Configured: {markdown_value(configured)}; not applied ({markdown_value(reason)})"
    return f"Configured: {markdown_value(configured)}; not applied"


def match_confidence(match):
    if match.get("confidence") not in [None, ""]:
        return match.get("confidence")
    return "N/A"


def highest_confidence_text(result):
    if result.get("max_confidence") not in [None, ""]:
        return result.get("max_confidence")
    if int(result.get("observable_matches") or 0) > 0 and int(result.get("indicator_matches") or 0) == 0:
        return "N/A - observable matches do not expose confidence in this OpenCTI schema"
    return "N/A"


def enrichment_markdown(result):
    matches = result.get("matches") or []
    markings = result.get("markings") or []
    lines = [
        "## OpenCTI Enrichment Summary",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| IOC | `{markdown_value(result.get('value'))}` |",
        f"| IOC type | {markdown_value(result.get('kind'))} |",
        f"| Result | {markdown_value(human_result(result))} |",
        f"| Analyst meaning | {markdown_value(analyst_meaning(result))} |",
        f"| Match count | {markdown_value(result.get('match_count'))} |",
        f"| Highest OpenCTI score | {markdown_value(result.get('max_score'))} |",
        f"| Highest applicable confidence | {markdown_value(highest_confidence_text(result))} |",
        f"| TLP / marking | {markdown_value(', '.join(markings) if markings else None)} |",
        f"| Source reference | {markdown_value(first_source_reference(matches))} |",
    ]
    labels = result.get("labels") or []
    if labels:
        lines.append(f"| Labels | {markdown_value(', '.join(labels))} |")

    lines.extend([
        "",
        "## What This Means",
        "",
    ])
    if int(result.get("match_count") or 0) > 0:
        lines.append("OpenCTI found threat-intelligence context for this IOC.")
    else:
        lines.append("OpenCTI did not find threat-intelligence context for this IOC.")
    lines.extend([
        "",
        "Indicator matches are intelligence assessments and may include confidence.",
        "",
        "Observable matches are raw artifacts such as IPs, domains, URLs, or hashes. In this OpenCTI schema, observables do not expose confidence.",
        "",
        "## Analyst Decision Guidance",
        "",
        "1. Check whether this IOC appears in local telemetry.",
        "2. Confirm whether the affected host communicated with the IOC.",
        "3. Review source references and OpenCTI object details.",
        "4. If activity is recent and relevant, consider escalation or containment.",
        "5. If not seen locally, document it as contextual intelligence only.",
        "",
        "## Matched OpenCTI Objects",
    ])

    if not matches:
        lines.append("")
        lines.append("No matching OpenCTI objects were returned for this IOC.")

    for index, match in enumerate(matches[:10], start=1):
        family = object_family(match)
        is_indicator = family == "Indicator"
        is_observable = family == "Observable"
        title = match.get("type") or match.get("entity_type") or "OpenCTI object"
        lines.extend(["", f"### Match {index}: {markdown_value(family)} - {markdown_value(title)}", ""])
        if is_indicator:
            lines.append("This is the stronger match because it is an OpenCTI Indicator. Indicators represent intelligence assessments and can include confidence.")
        elif is_observable:
            lines.append("This is a raw observable in OpenCTI. It confirms that the artifact exists as a known object, but confidence is not available for this object type. Use score, source reference, and linked intelligence for context.")
        else:
            lines.append("This is an OpenCTI object returned during enrichment. Review the score, source, and object details before making a triage decision.")

        lines.extend(["", "| Field | Value |", "|---|---|"])
        lines.append(f"| OpenCTI object family | {markdown_value(family)} |")
        lines.append(f"| OpenCTI type | {markdown_value(match.get('entity_type') or match.get('type'))} |")
        lines.append(f"| Name | {markdown_value(match.get('name'))} |")
        lines.append(f"| Score | {markdown_value(match.get('score'))} |")
        lines.append(f"| Confidence | {markdown_value(match_confidence(match))} |")
        if is_observable or not match.get("confidence_applicable"):
            lines.append(f"| Confidence reason | {markdown_value(match.get('confidence_unavailable_reason') or 'OpenCTI does not expose confidence for observable objects in this schema')} |")
        lines.append(f"| Confidence threshold | {markdown_value(threshold_text(match, 'confidence'))} |")
        lines.append(f"| Score threshold | {markdown_value(threshold_text(match, 'score'))} |")
        lines.append(f"| Source | {markdown_value(match_source(match))} |")
        lines.append(f"| OpenCTI object ID | {markdown_value(match.get('id'))} |")
        if match.get("related_indicator_confidence") not in [None, ""]:
            lines.append(f"| Related indicator confidence | {markdown_value(match.get('related_indicator_confidence'))} |")
            lines.append(f"| Related indicator confidence source | {markdown_value(match.get('related_indicator_confidence_source') or 'linked Indicator')} |")

    lines.extend([
        "",
        "## Final Analyst Note",
        "",
    ])
    if int(result.get("match_count") or 0) > 0:
        lines.append(f"OpenCTI found relevant context for `{markdown_value(result.get('value'))}`. Review this IOC against local telemetry before containment or escalation.")
    else:
        lines.append(f"OpenCTI did not find matching context for `{markdown_value(result.get('value'))}`. Continue triage with local telemetry and document the absence of OpenCTI context if relevant.")
    return "\n".join(lines)


def clean_labels(items):
    out = []
    seen = set()
    for item in items or []:
        value = str(item or "").strip().replace(" ", "-")[:64]
        if value and value.lower() not in seen:
            seen.add(value.lower())
            out.append(value)
    return out[:25]
PY

  cat >"$OPENCTI_CORE_DIR/iris_client.py" <<'PY'
import os
import re
import urllib.parse

from .http_utils import HTTPClient
from .reporting import clean_labels, enrichment_markdown

START_MARKER = "<!-- opencti-enrichment:start -->"
END_MARKER = "<!-- opencti-enrichment:end -->"


def flatten_note_dirs(payload):
    out = []
    def walk(obj):
        if isinstance(obj, dict):
            out.append(obj)
            for key in ("subdirectories", "children", "directories", "note_directories"):
                if isinstance(obj.get(key), list):
                    walk(obj[key])
        elif isinstance(obj, list):
            for item in obj:
                walk(item)
    if isinstance(payload, dict):
        walk(payload.get("data"))
        walk(payload.get("message"))
    return out


def find_any_id(payload):
    found = None
    def walk(obj):
        nonlocal found
        if found is not None:
            return
        if isinstance(obj, dict):
            for key in ("id", "directory_id", "note_directory_id"):
                if obj.get(key) not in [None, ""]:
                    found = obj[key]
                    return
            for value in obj.values():
                walk(value)
        elif isinstance(obj, list):
            for value in obj:
                walk(value)
    walk(payload)
    return found


def merge_description(original, result):
    block = START_MARKER + "\n" + enrichment_markdown(result) + "\n" + END_MARKER
    original = original or ""
    pattern = re.compile(re.escape(START_MARKER) + r".*?" + re.escape(END_MARKER), re.S)
    if pattern.search(original):
        return pattern.sub(block, original)
    return (original.rstrip() + "\n\n" + block).strip()


def merge_tags(existing, result):
    raw = []
    if isinstance(existing, str):
        raw.extend([x.strip() for x in re.split(r"[,;]", existing) if x.strip()])
    elif isinstance(existing, list):
        raw.extend([str(x).strip() for x in existing if str(x).strip()])
    raw.extend(["opencti", "opencti-enriched", result.get("verdict", "context-found")])
    raw.extend(result.get("labels") or [])
    return ",".join(clean_labels(raw))


def bridge_debug_enabled():
    return os.environ.get("BRIDGE_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"}


def empty_ioc_update_stats():
    return {
        "ioc_update_attempted": 0,
        "ioc_update_response_ok": 0,
        "ioc_update_verified": 0,
        "ioc_update_failed": 0,
        "ioc_description_updated": 0,
    }


def find_ioc_description(payload):
    if isinstance(payload, dict):
        value = payload.get("ioc_description")
        if value not in [None, ""]:
            return str(value)
        for item in payload.values():
            found = find_ioc_description(item)
            if found not in [None, ""]:
                return found
    elif isinstance(payload, list):
        for item in payload:
            found = find_ioc_description(item)
            if found not in [None, ""]:
                return found
    return ""


def find_ioc_by_id(items, ioc_id):
    target = str(ioc_id)
    for item in items or []:
        if not isinstance(item, dict):
            continue
        for key in ("ioc_id", "id", "iocid"):
            if str(item.get(key) or "") == target:
                return item
    return None


class IRISClient:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.http = HTTPClient(config.iris_token, config.iris_verify_ssl, config.iris_ca_bundle)

    def get(self, path, params=None):
        return self.http.json("GET", self.config.iris_url + path, params=params)

    def post(self, path, payload, params=None):
        if self.config.dry_run:
            self.logger.log("info", "dry_run_iris_post", path=path, params=params or {}, payload=payload)
            return {"status": "dry_run"}
        return self.http.json("POST", self.config.iris_url + path, payload=payload, params=params)

    def preflight(self):
        self.config.validate(require_opencti=False, require_iris=True)
        self.get("/manage/cases/filter", {"page": 1, "per_page": 1, "sort": "desc"})
        result = {"case_list": True, "ioc_list": "not_tested_no_case_id"}
        if self.config.iris_case_ids:
            self.get("/case/ioc/list", {"cid": self.config.iris_case_ids[0]})
            result["ioc_list"] = True
        return result

    def list_cases(self):
        if self.config.iris_case_ids:
            return [{"case_id": cid, "id": cid, "name": f"case-{cid}"} for cid in self.config.iris_case_ids]
        cases = []
        page = 1
        while len(cases) < self.config.max_cases:
            payload = self.get("/manage/cases/filter", {"page": page, "per_page": 100, "sort": "desc"})
            batch = self.extract_cases(payload)
            if not batch:
                break
            for case in batch:
                if self.is_open_case(case):
                    cases.append(case)
                if len(cases) >= self.config.max_cases:
                    break
            if len(batch) < 100:
                break
            page += 1
        return cases

    def extract_cases(self, payload):
        if isinstance(payload.get("message"), dict) and isinstance(payload["message"].get("cases"), list):
            return payload["message"]["cases"]
        if isinstance(payload.get("data"), dict) and isinstance(payload["data"].get("cases"), list):
            return payload["data"]["cases"]
        if isinstance(payload.get("data"), list):
            return payload["data"]
        return []

    def is_open_case(self, case):
        status = str(case.get("status_name") or case.get("state_name") or "").lower()
        return not case.get("close_date") and "closed" not in status and "close" not in status

    def case_iocs(self, case_id):
        payload = self.get("/case/ioc/list", {"cid": case_id})
        data = payload.get("data")
        if isinstance(data, dict):
            for key in ("ioc", "iocs", "items"):
                if isinstance(data.get(key), list):
                    return data[key][: self.config.max_iocs_per_case]
        if isinstance(data, list):
            return data[: self.config.max_iocs_per_case]
        return []

    def build_ioc_update_payload(self, case_id, ioc, result):
        ioc_id = str(ioc.get("ioc_id") or ioc.get("id") or ioc.get("iocid") or "")
        if not ioc_id:
            self.logger.log("warning", "skip_ioc_update_missing_ioc_id", case_id=case_id, value=ioc.get("ioc_value") or ioc.get("value") or result.get("value"))
            return "", {}
        ioc_type_id = ioc.get("ioc_type_id") or ioc.get("type_id")
        if not ioc_type_id:
            self.logger.log("warning", "skip_ioc_update_missing_type_id", case_id=case_id, ioc_id=ioc_id)
            return "", {}
        value = ioc.get("ioc_value") or ioc.get("value") or result.get("value")
        description = merge_description(str(ioc.get("ioc_description") or ""), result)
        tags = merge_tags(ioc.get("ioc_tags") or ioc.get("tags") or "", result)
        payload = {
            "ioc_value": value,
            "ioc_tlp_id": ioc.get("ioc_tlp_id") or ioc.get("tlp_id") or self.config.default_iris_tlp_id,
            "ioc_type_id": ioc_type_id,
            "ioc_description": description,
            "ioc_tags": tags,
        }
        if bridge_debug_enabled():
            self.logger.log(
                "debug",
                "iris_ioc_update_payload_prepared",
                case_id=case_id,
                ioc_id=ioc_id,
                value=value,
                ioc_type_id=ioc_type_id,
                ioc_tlp_id=payload["ioc_tlp_id"],
                description_has_opencti_marker=START_MARKER in description,
                description_length=len(description),
                tags=tags,
            )
        return ioc_id, payload

    def dry_run_ioc_update_payload(self, case_id, ioc, result):
        stats = empty_ioc_update_stats()
        ioc_id, payload = self.build_ioc_update_payload(case_id, ioc, result)
        if not ioc_id or not payload:
            stats["ioc_update_failed"] = 1
            return stats
        description = str(payload.get("ioc_description") or "")
        self.logger.log(
            "info",
            "dry_run_ioc_update_payload_prepared",
            case_id=case_id,
            ioc_id=ioc_id,
            value=payload.get("ioc_value"),
            description_has_opencti_marker=START_MARKER in description,
            description_length=len(description),
            would_post_to="/case/ioc/update/" + urllib.parse.quote(ioc_id) + "?cid=" + urllib.parse.quote(str(case_id)),
        )
        return stats

    def update_ioc(self, case_id, ioc, result):
        stats = empty_ioc_update_stats()
        if not self.config.update_iris_ioc:
            return stats
        ioc_id, payload = self.build_ioc_update_payload(case_id, ioc, result)
        if not ioc_id or not payload:
            stats["ioc_update_failed"] = 1
            return stats
        path = "/case/ioc/update/" + urllib.parse.quote(ioc_id)
        description = str(payload.get("ioc_description") or "")
        response = self.post(path, payload, {"cid": case_id})
        stats["ioc_update_attempted"] = 1
        stats["ioc_update_response_ok"] = 1
        response_description = find_ioc_description(response)
        response_status = response.get("status") if isinstance(response, dict) else ""
        response_message = response.get("message") if isinstance(response, dict) else ""
        self.logger.log(
            "info",
            "iris_ioc_update_response",
            case_id=case_id,
            ioc_id=ioc_id,
            value=payload.get("ioc_value"),
            response_status=response_status,
            response_message=response_message,
            response_description_length=len(response_description),
            payload_description_length=len(description),
        )
        if START_MARKER in response_description:
            stats["ioc_update_verified"] = 1
            stats["ioc_description_updated"] = 1
            return stats

        refetched_iocs = self.case_iocs(case_id)
        refetched = find_ioc_by_id(refetched_iocs, ioc_id)
        refetched_description = str((refetched or {}).get("ioc_description") or "")
        if START_MARKER in refetched_description:
            stats["ioc_update_verified"] = 1
            stats["ioc_description_updated"] = 1
            self.logger.log(
                "info",
                "iris_ioc_update_refetch_verified",
                case_id=case_id,
                ioc_id=ioc_id,
                value=payload.get("ioc_value"),
                refetched_description_length=len(refetched_description),
            )
            return stats

        stats["ioc_update_failed"] = 1
        sample = refetched or (refetched_iocs[0] if refetched_iocs and isinstance(refetched_iocs[0], dict) else {})
        self.logger.log(
            "error",
            "ioc_update_verification_failed",
            case_id=case_id,
            ioc_id=ioc_id,
            value=payload.get("ioc_value"),
            payload_description_length=len(description),
            response_description_length=len(response_description),
            refetched_description_length=len(refetched_description),
            available_ioc_keys=sorted(sample.keys()) if isinstance(sample, dict) else [],
            recommended_action="Check payload generation and IRIS IOC update response.",
        )
        return stats

    def ensure_note_dir(self, state, case_id):
        cached = state.get_note_dir(case_id)
        dirs = flatten_note_dirs(self.get("/case/notes/directories/filter", {"cid": case_id}))
        valid = {str(d.get("id") or d.get("directory_id") or d.get("note_directory_id")) for d in dirs}
        if cached and cached in valid:
            return cached
        for item in dirs:
            name = item.get("name") or item.get("directory_name") or item.get("note_directory_name")
            did = item.get("id") or item.get("directory_id") or item.get("note_directory_id")
            if name == self.config.note_dir_name and did not in [None, ""]:
                state.set_note_dir(case_id, str(did))
                return str(did)
        created = self.post("/case/notes/directories/add", {"name": self.config.note_dir_name, "parent_id": None}, {"cid": case_id})
        did = find_any_id(created)
        if did:
            state.set_note_dir(case_id, str(did))
            return str(did)
        return None

    def add_note(self, state, case_id, ioc, result, key, digest):
        if not self.config.add_case_note:
            return "disabled"
        if state.note_already_written(key, digest, result.get("opencti_ids") or []):
            self.logger.log("info", "duplicate_opencti_note_skipped", case_id=case_id, ioc_id=str(ioc.get("ioc_id") or ioc.get("id") or ""), value=result.get("value"), opencti_ids=result.get("opencti_ids") or [])
            return "duplicate"
        directory_id = self.ensure_note_dir(state, case_id)
        if not directory_id:
            self.logger.log("warning", "skip_note_no_directory", case_id=case_id)
            return "skipped"
        try:
            directory_value = int(directory_id)
        except Exception:
            directory_value = directory_id
        title = "OpenCTI enrichment: " + str(result.get("value", ""))[:80]
        self.post("/case/notes/add", {"note_title": title, "note_content": enrichment_markdown(result), "directory_id": directory_value}, {"cid": case_id})
        return "written"
PY

  cat >"$OPENCTI_CORE_DIR/enrichment.py" <<'PY'
import hashlib
import json
from datetime import datetime, timezone

from .config import write_json
from .iris_client import IRISClient
from .logging_utils import BridgeLogger
from .matching import infer_ioc_type, normalize_value
from .opencti_client import OpenCTIClient
from .state import BridgeState, StateMigrationError, state_db_status


def ioc_identity(case_id, ioc):
    ioc_id = str(ioc.get("ioc_id") or ioc.get("id") or ioc.get("iocid") or "")
    value = normalize_value(ioc.get("ioc_value") or ioc.get("value") or ioc.get("ioc") or "")
    kind = infer_ioc_type(ioc.get("ioc_type") or ioc.get("type") or "", value)
    raw = json.dumps({"case_id": str(case_id), "ioc_id": ioc_id, "value": value.lower(), "kind": kind}, sort_keys=True)
    key = f"{case_id}:{ioc_id}:{hashlib.sha256(value.lower().encode()).hexdigest()[:16]}"
    return key, hashlib.sha256(raw.encode()).hexdigest(), ioc_id, value, kind


class EnrichmentEngine:
    def __init__(self, config):
        self.config = config
        self.logger = BridgeLogger(config.run_log)
        self.iris = IRISClient(config, self.logger)
        self.opencti = OpenCTIClient(config, self.logger)
        self.state = BridgeState(config)

    def result_from_matches(self, value, kind, matches, query_mode):
        scores = [int(m["score"]) for m in matches if str(m.get("score") or "").isdigit()]
        confidences = [int(m["confidence"]) for m in matches if str(m.get("confidence") or "").isdigit()]
        labels = sorted({label for match in matches for label in (match.get("labels") or [])})
        markings = sorted({mark for match in matches for mark in (match.get("markings") or [])})
        indicator_matches = sum(1 for match in matches if match.get("opencti_object_family") == "indicator")
        observable_matches = sum(1 for match in matches if match.get("opencti_object_family") == "observable")
        matches_with_confidence = sum(1 for match in matches if match.get("confidence") not in [None, ""])
        matches_without_confidence = len(matches) - matches_with_confidence
        confidence_threshold_applied_count = sum(1 for match in matches if match.get("confidence_threshold_applied"))
        confidence_threshold_skipped_count = len(matches) - confidence_threshold_applied_count
        score_threshold_applied_count = sum(1 for match in matches if match.get("score_threshold_applied"))
        observable_only = bool(matches) and observable_matches == len(matches)
        indicator_only = bool(matches) and indicator_matches == len(matches)
        if observable_only:
            confidence_applicability = "Not available for OpenCTI observable matches"
            confidence_threshold_skipped_reason = "confidence_not_supported_for_stix_cyber_observable"
        elif indicator_only:
            confidence_applicability = "Available for OpenCTI indicator matches"
            confidence_threshold_skipped_reason = "" if confidence_threshold_applied_count else "confidence_value_missing"
        elif matches:
            confidence_applicability = "Available for Indicator matches; not available for Observable matches"
            confidence_threshold_skipped_reason = "" if confidence_threshold_skipped_count == 0 else "some_matches_do_not_support_confidence"
        else:
            confidence_applicability = "N/A"
            confidence_threshold_skipped_reason = "no_matches"
        return {
            "value": value,
            "kind": kind,
            "verdict": "context-found" if matches else "no-context-found",
            "match_count": len(matches),
            "max_score": max(scores) if scores else None,
            "max_confidence": max(confidences) if confidences else None,
            "score_threshold": self.config.min_score,
            "score_threshold_applied": score_threshold_applied_count > 0,
            "score_threshold_skipped_reason": "" if score_threshold_applied_count > 0 else "score_value_missing_or_no_matches",
            "confidence_threshold": self.config.min_confidence,
            "confidence_threshold_applied": confidence_threshold_applied_count > 0,
            "confidence_threshold_skipped_reason": confidence_threshold_skipped_reason,
            "confidence_applicability": confidence_applicability,
            "indicator_matches": indicator_matches,
            "observable_matches": observable_matches,
            "matches_with_confidence": matches_with_confidence,
            "matches_without_confidence": matches_without_confidence,
            "confidence_threshold_applied_count": confidence_threshold_applied_count,
            "confidence_threshold_skipped_count": confidence_threshold_skipped_count,
            "labels": labels,
            "markings": markings,
            "opencti_ids": [m.get("id") for m in matches if m.get("id")],
            "matches": matches,
            "query_mode": query_mode,
        }

    def process_ioc(self, case_id, ioc, force=False):
        key, digest, ioc_id, value, kind = ioc_identity(case_id, ioc)
        if not value:
            return {"status": "skipped", "reason": "empty_ioc"}
        if not self.state.should_process(key, digest, force=force):
            self.logger.log("info", "skip_recently_enriched_ioc", case_id=case_id, ioc_id=ioc_id, value=value)
            return {"status": "skipped", "reason": "recently_enriched"}
        matches, query_mode = self.opencti.search_ioc(value, kind)
        result = self.result_from_matches(value, kind, matches, query_mode)
        would_write = bool(matches and (self.config.update_iris_ioc or self.config.add_case_note))
        self.logger.log("info", "ioc_enrichment_result", case_id=case_id, ioc_id=ioc_id, value=value, kind=kind, match_count=len(matches), dry_run=self.config.dry_run, query_mode=query_mode, live_writes_would_have_occurred=would_write)
        ioc_update_stats = {
            "ioc_update_attempted": 0,
            "ioc_update_response_ok": 0,
            "ioc_update_verified": 0,
            "ioc_update_failed": 0,
            "ioc_description_updated": 0,
        }
        if self.config.dry_run:
            if matches and self.config.update_iris_ioc:
                ioc_update_stats = self.iris.dry_run_ioc_update_payload(case_id, ioc, result)
            self.state.mark(key, case_id, ioc_id, digest, "dry_run_matched" if matches else "dry_run_no_match", result["opencti_ids"], dry_run=True, match_count=result["match_count"], query_mode=query_mode, live_write=False)
            return {"status": "dry_run", "result": result, "would_write": would_write, "ioc_update_written": False, "case_note_written": False, "duplicate_skipped": False, **ioc_update_stats}
        note_status = "disabled"
        if matches and self.config.update_iris_ioc:
            ioc_update_stats = self.iris.update_ioc(case_id, ioc, result)
        if matches and self.config.add_case_note:
            note_status = self.iris.add_note(self.state, case_id, ioc, result, key, digest)
        duplicate_skipped = note_status == "duplicate"
        case_note_written = note_status == "written"
        self.state.mark(key, case_id, ioc_id, digest, "matched" if matches else "no_match", result["opencti_ids"], dry_run=False, match_count=result["match_count"], query_mode=query_mode, live_write=would_write)
        return {"status": "ok", "result": result, "would_write": would_write, "ioc_update_written": bool(ioc_update_stats.get("ioc_update_verified")), "case_note_written": case_note_written, "duplicate_skipped": duplicate_skipped, **ioc_update_stats}

    def run(self, case_ids=None, ioc_ids=None, force=False):
        cases = [{"case_id": cid, "id": cid} for cid in case_ids] if case_ids else self.iris.list_cases()
        selected_iocs = {str(x) for x in (ioc_ids or [])}
        summary = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "cases_scanned": 0,
            "iocs_seen": 0,
            "iocs_processed": 0,
            "matches_found": 0,
            "schema_warnings": self.opencti.capabilities.get("schema_warnings", []),
            "query_mode_used": self.opencti.capabilities.get("last_successful_query_mode") or self.opencti.capabilities.get("supported_query_level"),
            "dry_run": self.config.dry_run,
            "live_write": not self.config.dry_run,
            "live_writes_would_have_occurred": False,
            "ioc_updates_written": 0,
            "ioc_update_attempted": 0,
            "ioc_update_response_ok": 0,
            "ioc_update_verified": 0,
            "ioc_update_failed": 0,
            "ioc_description_updated": 0,
            "case_notes_written": 0,
            "duplicates_skipped": 0,
            "recently_enriched_skipped": 0,
            "indicator_matches": 0,
            "observable_matches": 0,
            "matches_with_confidence": 0,
            "matches_without_confidence": 0,
            "confidence_threshold_applied_count": 0,
            "confidence_threshold_skipped_count": 0,
            "last_result": None,
        }
        for case in cases:
            case_id = str(case.get("case_id") or case.get("id") or "")
            if not case_id:
                continue
            iocs = self.iris.case_iocs(case_id)
            summary["cases_scanned"] += 1
            summary["iocs_seen"] += len(iocs)
            for ioc in iocs:
                current_id = str(ioc.get("ioc_id") or ioc.get("id") or ioc.get("iocid") or "")
                if selected_iocs and current_id not in selected_iocs:
                    continue
                outcome = self.process_ioc(case_id, ioc, force=force)
                if outcome.get("reason") == "recently_enriched":
                    summary["recently_enriched_skipped"] += 1
                if outcome.get("status") not in {"skipped"}:
                    summary["iocs_processed"] += 1
                result = outcome.get("result") or {}
                summary["matches_found"] += int(result.get("match_count") or 0)
                summary["indicator_matches"] += int(result.get("indicator_matches") or 0)
                summary["observable_matches"] += int(result.get("observable_matches") or 0)
                summary["matches_with_confidence"] += int(result.get("matches_with_confidence") or 0)
                summary["matches_without_confidence"] += int(result.get("matches_without_confidence") or 0)
                summary["confidence_threshold_applied_count"] += int(result.get("confidence_threshold_applied_count") or 0)
                summary["confidence_threshold_skipped_count"] += int(result.get("confidence_threshold_skipped_count") or 0)
                summary["live_writes_would_have_occurred"] = summary["live_writes_would_have_occurred"] or bool(outcome.get("would_write"))
                summary["ioc_update_attempted"] += int(outcome.get("ioc_update_attempted") or 0)
                summary["ioc_update_response_ok"] += int(outcome.get("ioc_update_response_ok") or 0)
                summary["ioc_update_verified"] += int(outcome.get("ioc_update_verified") or 0)
                summary["ioc_update_failed"] += int(outcome.get("ioc_update_failed") or 0)
                summary["ioc_description_updated"] += int(outcome.get("ioc_description_updated") or 0)
                summary["ioc_updates_written"] += int(outcome.get("ioc_update_verified") or 0)
                summary["case_notes_written"] += 1 if outcome.get("case_note_written") else 0
                summary["duplicates_skipped"] += 1 if outcome.get("duplicate_skipped") else 0
                summary["query_mode_used"] = result.get("query_mode") or summary["query_mode_used"]
                summary["last_result"] = result or summary["last_result"]
        target = self.config.last_dry_run_file if self.config.dry_run else self.config.last_live_write_file
        write_json(target, summary)
        self.logger.log("info", "bridge_run_completed", **summary)
        return summary
PY

  cat >"$OPENCTI_CORE_DIR/runner_impl.py" <<'PY'
import argparse
import fcntl
import json
import os
import sys
import time
import traceback
from pathlib import Path

from .config import load_config, write_json
from .enrichment import EnrichmentEngine
from .http_utils import BridgeHTTPError, SSLCertificateVerifyError
from .iris_client import IRISClient
from .logging_utils import BridgeLogger
from .opencti_client import OpenCTIClient
from .state import BridgeState, StateMigrationError, state_db_status

LOCK_FILE = "/var/lib/opencti-iris-bridge/bridge.lock"
BRIDGE_VERSION = "2.0.0"
RUNNER_CLI_VERSION = 2


def parse_csv(values):
    out = []
    for value in values or []:
        for item in str(value).split(","):
            item = item.strip()
            if item:
                out.append(item)
    return out


def preflight(config, component="both"):
    logger = BridgeLogger(config.run_log)
    state = BridgeState(config)
    if state.migrations_applied:
        logger.log("info", "state_db_migrated", path=config.state_db, migrations_applied=state.migrations_applied)
    result = {
        "timestamp": time.time(),
        "component": component,
        "status": "ok",
        "bridge_version": BRIDGE_VERSION,
        "runner_cli_version": RUNNER_CLI_VERSION,
        "supports_env_file": True,
        "supports_state_check": True,
        "iris": None,
        "opencti": None,
        "state_db": state.status(),
    }
    if component in {"both", "iris"}:
        result["iris"] = IRISClient(config, logger).preflight()
    if component in {"both", "opencti"}:
        result["opencti"] = OpenCTIClient(config, logger).preflight()
    write_json(config.last_preflight_file, result)
    print(json.dumps({"status": "ok", "result": result}, indent=2))
    return 0


def error_payload(exc, component="runner", config=None):
    target = getattr(exc, "target", "")
    resolved_component = component
    if config is not None and target:
        if config.iris_url and target.startswith(config.iris_url):
            resolved_component = "iris"
        elif config.opencti_url and target.startswith(config.opencti_url):
            resolved_component = "opencti"
    if isinstance(exc, SSLCertificateVerifyError):
        if resolved_component == "iris":
            message = "IRIS SSL certificate verification failed. The IRIS server appears to use a self-signed certificate."
            action = "Disable IRIS SSL verification for lab/self-signed deployments or provide a trusted IRIS CA bundle."
        elif resolved_component == "opencti":
            message = "OpenCTI SSL certificate verification failed. The OpenCTI server appears to use a self-signed certificate."
            action = "Disable OpenCTI SSL verification for lab/self-signed deployments or provide a trusted OpenCTI CA bundle."
        else:
            message = str(exc)
            action = getattr(exc, "recommended_action", "")
        return {
            "status": "error",
            "component": resolved_component,
            "error_type": "ssl_certificate_verify_failed",
            "message": message,
            "target": target,
            "recommended_action": action,
        }
    if isinstance(exc, BridgeHTTPError):
        return {
            "status": "error",
            "component": resolved_component,
            "error_type": exc.error_type,
            "message": str(exc),
            "target": target,
            "recommended_action": exc.recommended_action,
        }
    if isinstance(exc, StateMigrationError):
        missing_columns = []
        try:
            missing_columns = state_db_status(exc.db_path).get("missing_columns", [])
        except Exception:
            missing_columns = []
        return {
            "status": "error",
            "component": "state_db",
            "error_type": "state_db_migration_failed",
            "message": str(exc),
            "target": exc.db_path,
            "missing_columns": missing_columns,
            "recommended_action": "Do not enable the timer or live writes. Collect the OpenCTI bridge support bundle and review SQLite file permissions/schema.",
        }
    return {
        "status": "error",
        "component": resolved_component,
        "error_type": exc.__class__.__name__,
        "message": str(exc),
        "target": target,
        "recommended_action": "Review bridge configuration and rerun preflight. Set BRIDGE_DEBUG=true only when a raw traceback is needed.",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="OpenCTI IRIS bridge runner")
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--component", choices=["both", "iris", "opencti"], default="both")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--case-id", action="append")
    parser.add_argument("--ioc-id", action="append")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--list-enabled", action="store_true")
    parser.add_argument("--enable-case")
    parser.add_argument("--disable-case")
    parser.add_argument("--clear-enabled", action="store_true")
    parser.add_argument("--state-check", action="store_true")
    parser.add_argument("--state-migrate", action="store_true")
    parser.add_argument("--env-file")
    parser.add_argument("--version", action="store_true")
    args = parser.parse_args(argv)

    config = None
    try:
        if args.version:
            print(json.dumps({
                "bridge_version": BRIDGE_VERSION,
                "runner_cli_version": RUNNER_CLI_VERSION,
                "supports_env_file": True,
                "supports_state_check": True,
                "supports_state_migrate": True,
            }, indent=2, sort_keys=True))
            return 0
        config = load_config(env_file=args.env_file, dry_run_override=True if args.dry_run else None)
        state = BridgeState(config, migrate=True)
        if state.migrations_applied:
            BridgeLogger(config.run_log).log("info", "state_db_migrated", path=config.state_db, migrations_applied=state.migrations_applied)
        if args.state_check:
            print(json.dumps({"status": "ok", "state_db": state.status()}, indent=2))
            return 0
        if args.state_migrate:
            print(json.dumps({"status": "ok", "state_db": state.status()}, indent=2))
            return 0

        if args.list_enabled:
            print(json.dumps({"case_ids": state.read_watchlist()}, indent=2))
            return 0
        if args.clear_enabled:
            state.write_watchlist([])
            print(json.dumps({"status": "ok", "case_ids": []}, indent=2))
            return 0
        if args.enable_case:
            ids = state.read_watchlist()
            if str(args.enable_case) not in ids:
                ids.append(str(args.enable_case))
            state.write_watchlist(ids)
            print(json.dumps({"status": "ok", "case_ids": ids}, indent=2))
            return 0
        if args.disable_case:
            ids = [x for x in state.read_watchlist() if x != str(args.disable_case)]
            state.write_watchlist(ids)
            print(json.dumps({"status": "ok", "case_ids": ids}, indent=2))
            return 0
        if args.preflight:
            return preflight(config, args.component)

        Path(LOCK_FILE).parent.mkdir(parents=True, exist_ok=True)
        with open(LOCK_FILE, "w") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                print(json.dumps({"status": "skipped", "reason": "bridge run already active"}))
                return 0
            case_ids = parse_csv(args.case_id) or state.read_watchlist()
            ioc_ids = parse_csv(args.ioc_id)
            result = EnrichmentEngine(config).run(case_ids=case_ids or None, ioc_ids=ioc_ids or None, force=args.force)
            print(json.dumps({"status": "ok", "result": result}, indent=2))
        return 0
    except Exception as exc:
        component = args.component if args.preflight else "runner"
        print(json.dumps(error_payload(exc, component, config), indent=2), file=sys.stderr)
        if os.environ.get("BRIDGE_DEBUG", "").lower() in {"1", "true", "yes", "on"}:
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
PY

  cat >"$OPENCTI_RUNNER" <<'PY'
#!/usr/bin/env python3
import sys
from pathlib import Path

BRIDGE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BRIDGE_DIR))

from opencti_iris_bridge_core.runner_impl import main

if __name__ == "__main__":
    raise SystemExit(main())
PY

  cat >"$OPENCTI_API" <<'PY'
#!/usr/bin/env python3
import json
import os
import re
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

BIND_HOST = os.environ.get("CONTROL_BIND_HOST", "127.0.0.1")
BIND_PORT = int(os.environ.get("CONTROL_BIND_PORT", "9097"))
TOKEN = os.environ.get("CONTROL_TOKEN", "")
RUNNER = os.environ.get("OPENCTI_IRIS_RUNNER", "/opt/opencti-iris-bridge/opencti_iris_bridge_runner.py")
TIMEOUT = int(os.environ.get("CONTROL_TIMEOUT", "900"))
BRIDGE_ENV_FILE = os.environ.get("BRIDGE_ENV_FILE", "/etc/opencti-iris-bridge/opencti-iris-bridge.env")
START_MARKER = "<!-- opencti-enrichment:start -->"
ASYNC_JOB_DELAY_SECONDS = float(os.environ.get("MANUAL_IOC_ASYNC_DELAY_SECONDS", "2.5"))
ASYNC_JOB_TTL_SECONDS = float(os.environ.get("MANUAL_IOC_ASYNC_TTL_SECONDS", "60"))
ASYNC_JOBS = {}
ASYNC_JOBS_LOCK = threading.Lock()


def read_json(handler):
    try:
        length = int(handler.headers.get("Content-Length") or 0)
    except Exception:
        length = 0
    if length <= 0:
        return {}
    raw = handler.rfile.read(length).decode("utf-8", errors="replace")
    try:
        return json.loads(raw) if raw.strip() else {}
    except Exception:
        return {}


def read_env_file(path):
    env = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                env[key.strip()] = value.strip().strip('"').strip("'")
    except FileNotFoundError:
        return env
    return env


def as_bool(value, default=False):
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def json_file(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def parse_runner_json(stdout):
    text = (stdout or "").strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except Exception:
        pass
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        try:
            return json.loads(text[start : end + 1])
        except Exception:
            return {}
    return {}


def api_log(message, **extra):
    event = {"event": message}
    event.update(extra)
    print(json.dumps(event, sort_keys=True), flush=True)


def parse_csv_values(value):
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


def env_int(env, key, default):
    try:
        return int(env.get(key, default))
    except Exception:
        return int(default)


def iris_ssl_context(env):
    verify = as_bool(env.get("IRIS_VERIFY_SSL"), False)
    if not verify:
        return ssl._create_unverified_context()
    ca_bundle = str(env.get("IRIS_CA_BUNDLE") or "").strip()
    if ca_bundle:
        return ssl.create_default_context(cafile=ca_bundle)
    return ssl.create_default_context()


def iris_get_json(env, path, params=None):
    base_url = str(env.get("IRIS_URL") or "").rstrip("/")
    token = str(env.get("IRIS_TOKEN") or "")
    if not base_url or not token:
        raise RuntimeError("IRIS_URL and IRIS_TOKEN are required to resolve IOC case context")
    query = urllib.parse.urlencode(params or {})
    url = base_url + path + (("?" + query) if query else "")
    req = urllib.request.Request(
        url,
        method="GET",
        headers={"Authorization": "Bearer " + token, "User-Agent": "OpenCTI-IRIS-Bridge-Control"},
    )
    parsed = urllib.parse.urlsplit(url)
    context = iris_ssl_context(env) if parsed.scheme.lower() == "https" else None
    with urllib.request.urlopen(req, timeout=30, context=context) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    return json.loads(raw) if raw.strip() else {}


def extract_cases(payload):
    if isinstance(payload.get("message"), dict) and isinstance(payload["message"].get("cases"), list):
        return payload["message"]["cases"]
    if isinstance(payload.get("data"), dict) and isinstance(payload["data"].get("cases"), list):
        return payload["data"]["cases"]
    if isinstance(payload.get("data"), list):
        return payload["data"]
    return []


def extract_iocs(payload, max_iocs):
    data = payload.get("data") if isinstance(payload, dict) else None
    if isinstance(data, dict):
        for key in ("ioc", "iocs", "items"):
            if isinstance(data.get(key), list):
                return data[key][:max_iocs]
    if isinstance(data, list):
        return data[:max_iocs]
    return []


def is_open_case(case):
    status = str(case.get("status_name") or case.get("state_name") or "").lower()
    return not case.get("close_date") and "closed" not in status and "close" not in status


def case_identifier(case):
    return str(case.get("case_id") or case.get("id") or case.get("cid") or "")


def ioc_identifier(ioc):
    return str(ioc.get("ioc_id") or ioc.get("id") or ioc.get("iocid") or "")


def ioc_description_value(ioc):
    return str(ioc.get("ioc_description") or ioc.get("description") or ioc.get("ioc_desc") or "")


def ioc_tags_value(ioc):
    value = ioc.get("ioc_tags")
    if value in [None, ""]:
        value = ioc.get("tags")
    if value in [None, ""]:
        value = ioc.get("tag_list")
    if isinstance(value, list):
        return ",".join(str(item) for item in value)
    return str(value or "")


def verify_ioc_description_from_iris(case_id, ioc_id):
    env = read_env_file(BRIDGE_ENV_FILE)
    max_iocs = env_int(env, "MAX_IOCS_PER_CASE", 500)
    payload = iris_get_json(env, "/case/ioc/list", {"cid": case_id})
    iocs = extract_iocs(payload, max_iocs)
    target = str(ioc_id)
    for ioc in iocs:
        if ioc_identifier(ioc) == target:
            description = ioc_description_value(ioc)
            return {
                "case_id": str(case_id),
                "ioc_id": target,
                "description_length": len(description),
                "has_opencti_marker": START_MARKER in description,
                "marker_present": START_MARKER in description,
                "tags": ioc_tags_value(ioc),
            }
    return {
        "case_id": str(case_id),
        "ioc_id": target,
        "description_length": 0,
        "has_opencti_marker": False,
        "marker_present": False,
        "tags": "",
        "error": "ioc_not_found",
    }


class ControlAPI:
    def run_runner(self, args, extra_env=None):
        env = os.environ.copy()
        env["BRIDGE_ENV_FILE"] = BRIDGE_ENV_FILE
        if extra_env:
            env.update({str(k): str(v) for k, v in extra_env.items()})
        proc = subprocess.run([sys.executable, RUNNER, "--env-file", BRIDGE_ENV_FILE] + list(args), env=env, capture_output=True, text=True, timeout=TIMEOUT)
        parsed = parse_runner_json(proc.stdout)
        return {"returncode": proc.returncode, "stdout": proc.stdout[-4000:], "stderr": proc.stderr[-4000:], "json": parsed}

    def resolve_case_id_for_ioc(self, ioc_id):
        env = read_env_file(BRIDGE_ENV_FILE)
        target = str(ioc_id)
        max_cases = env_int(env, "MAX_CASES", 500)
        max_iocs = env_int(env, "MAX_IOCS_PER_CASE", 500)
        configured_case_ids = parse_csv_values(env.get("IRIS_CASE_IDS"))
        matches = []
        cases_checked = 0
        iocs_checked = 0
        api_log("resolve_ioc_case_started", ioc_id=target, configured_case_ids=bool(configured_case_ids))
        try:
            if configured_case_ids:
                cases = [{"case_id": cid, "id": cid} for cid in configured_case_ids]
            else:
                cases = []
                page = 1
                while len(cases) < max_cases:
                    payload = iris_get_json(env, "/manage/cases/filter", {"page": page, "per_page": 100, "sort": "desc"})
                    batch = extract_cases(payload)
                    if not batch:
                        break
                    for case in batch:
                        if is_open_case(case):
                            cases.append(case)
                        if len(cases) >= max_cases:
                            break
                    if len(batch) < 100:
                        break
                    page += 1
            for case in cases[:max_cases]:
                case_id = case_identifier(case)
                if not case_id:
                    continue
                cases_checked += 1
                iocs = extract_iocs(iris_get_json(env, "/case/ioc/list", {"cid": case_id}), max_iocs)
                iocs_checked += len(iocs)
                for ioc in iocs:
                    if ioc_identifier(ioc) == target:
                        matches.append(case_id)
            unique_matches = sorted(set(matches))
            if len(unique_matches) == 1:
                api_log("resolve_ioc_case_succeeded", ioc_id=target, case_id=unique_matches[0], cases_checked=cases_checked, iocs_checked=iocs_checked)
                return {"status": "ok", "case_id": unique_matches[0], "ioc_id": target, "cases_checked": cases_checked, "iocs_checked": iocs_checked}
            if not unique_matches:
                api_log("resolve_ioc_case_failed", ioc_id=target, cases_checked=cases_checked, iocs_checked=iocs_checked)
                return {
                    "status": "error",
                    "message": "case_id could not be resolved for IOC enrichment",
                    "ioc_id": target,
                    "cases_checked": cases_checked,
                    "iocs_checked": iocs_checked,
                    "required_action": "Use case-scoped route or improve IRIS hook case_id extraction",
                }
            api_log("resolve_ioc_case_ambiguous", ioc_id=target, case_ids=unique_matches, cases_checked=cases_checked, iocs_checked=iocs_checked)
            return {
                "status": "error",
                "message": "case_id resolution was ambiguous for IOC enrichment",
                "ioc_id": target,
                "case_ids": unique_matches,
                "required_action": "Use case-scoped route from the IRIS button payload",
            }
        except Exception as exc:
            api_log("resolve_ioc_case_error", ioc_id=target, error=str(exc))
            return {
                "status": "error",
                "message": "case_id could not be resolved for IOC enrichment",
                "ioc_id": target,
                "error": str(exc),
                "required_action": "Use case-scoped route or improve IRIS hook case_id extraction",
            }

    def manual_live_safety_check(self):
        env = read_env_file(BRIDGE_ENV_FILE)
        if not (as_bool(env.get("UPDATE_IRIS_IOC"), False) or as_bool(env.get("ADD_CASE_NOTE"), False)):
            return {"status": "blocked", "reason": "write_options_disabled", "message": "Enable UPDATE_IRIS_IOC or ADD_CASE_NOTE before manual live enrichment."}

        state_db = env.get("STATE_DB", "/var/lib/opencti-iris-bridge/state.sqlite3")
        state_dir = os.path.dirname(state_db) or "/var/lib/opencti-iris-bridge"
        activation = json_file(os.path.join(state_dir, "activation-status.json"))
        activation_status = activation.get("status") or env.get("ACTIVATION_STATUS", "")
        if activation_status and activation_status != "ready":
            return {"status": "blocked", "reason": "activation_not_ready", "activation_status": activation_status, "message": "Bridge activation status is not ready."}

        state_check = self.run_runner(["--state-check"])
        if state_check["returncode"] != 0:
            return {"status": "blocked", "reason": "state_db_schema_invalid", "runner": state_check}
        preflight = self.run_runner(["--preflight", "--component", "both"])
        if preflight["returncode"] != 0:
            return {"status": "blocked", "reason": "preflight_failed", "runner": preflight}
        capabilities = json_file(env.get("CAPABILITIES_FILE", os.path.join(state_dir, "opencti-capabilities.json")))
        if capabilities.get("last_graphql_validation_error"):
            return {"status": "blocked", "reason": "opencti_schema_validation_error", "message": str(capabilities.get("last_graphql_validation_error"))}
        return {"status": "ok"}

    def summarize_runner_result(self, result, manual=False, force=False, live_write=False, case_id=None, ioc_id=None, route=""):
        payload = result.get("json") or {}
        summary = payload.get("result") if isinstance(payload.get("result"), dict) else payload
        status = "ok" if result.get("returncode") == 0 and payload.get("status", "ok") == "ok" else "error"
        response = {
            "status": status,
            "manual": bool(manual),
            "force": bool(force),
            "dry_run": summary.get("dry_run"),
            "live_write": bool(live_write) if live_write else summary.get("live_write"),
            "case_id": str(case_id) if case_id not in [None, ""] else None,
            "ioc_id": str(ioc_id) if ioc_id not in [None, ""] else None,
            "route": route,
            "iocs_processed": int(summary.get("iocs_processed") or 0),
            "matches_found": int(summary.get("matches_found") or 0),
            "ioc_updates_written": int(summary.get("ioc_updates_written") or 0),
            "ioc_update_attempted": int(summary.get("ioc_update_attempted") or 0),
            "ioc_update_response_ok": int(summary.get("ioc_update_response_ok") or 0),
            "ioc_update_verified": int(summary.get("ioc_update_verified") or 0),
            "ioc_update_failed": int(summary.get("ioc_update_failed") or 0),
            "ioc_description_updated": int(summary.get("ioc_description_updated") or 0),
            "case_notes_written": int(summary.get("case_notes_written") or 0),
            "duplicates_skipped": int(summary.get("duplicates_skipped") or 0),
            "recently_enriched_skipped": int(summary.get("recently_enriched_skipped") or 0),
            "runner_returncode": result.get("returncode"),
        }
        if response["duplicates_skipped"] > 0 and response["ioc_description_updated"] > 0 and response["case_notes_written"] == 0:
            response["message"] = "IOC Description updated; note already existed for this OpenCTI object set."
        elif response["duplicates_skipped"] > 0:
            response["message"] = "OpenCTI enrichment already exists for this IOC and OpenCTI object set."
        elif response["recently_enriched_skipped"] > 0 and response["iocs_processed"] == 0 and not force:
            response["message"] = "This IOC was recently enriched. Manual OpenCTI enrichment normally refreshes immediately; check whether this request reached the manual live-refresh path."
        elif response["dry_run"] is True:
            response["message"] = "Dry-run completed; no IRIS writes were made."
        if status != "ok":
            response["runner"] = result
        return response

    def run_manual_enrichment(self, args, force=False, live_write=True, case_id=None, ioc_id=None, route=""):
        if live_write:
            safety = self.manual_live_safety_check()
            if safety.get("status") != "ok":
                return safety
        extra_env = {"DRY_RUN": "false"} if live_write else None
        result = self.run_runner(args, extra_env=extra_env)
        return self.summarize_runner_result(result, manual=True, force=force, live_write=live_write, case_id=case_id, ioc_id=ioc_id, route=route)

    def queue_manual_ioc_async(self, case_id, ioc_id, route):
        now = time.time()
        key = f"{case_id or 'resolve'}:{ioc_id}"
        with ASYNC_JOBS_LOCK:
            stale = [item_key for item_key, item in ASYNC_JOBS.items() if now - float(item.get("queued_at", 0)) >= ASYNC_JOB_TTL_SECONDS]
            for item_key in stale:
                ASYNC_JOBS.pop(item_key, None)
            existing = None
            for item in ASYNC_JOBS.values():
                if now - float(item.get("queued_at", 0)) >= ASYNC_JOB_TTL_SECONDS:
                    continue
                same_ioc = str(item.get("ioc_id") or "") == str(ioc_id)
                item_case = item.get("case_id")
                same_or_unknown_case = not case_id or not item_case or str(item_case) == str(case_id)
                if same_ioc and same_or_unknown_case:
                    existing = item
                    break
            if existing:
                api_log("manual_ioc_async_job_queued", job_id=existing.get("job_id"), case_id=case_id, ioc_id=ioc_id, route=route, duplicate=True)
                return {
                    "status": "accepted",
                    "queued": False,
                    "duplicate_suppressed": True,
                    "job_id": existing.get("job_id"),
                    "case_id": str(case_id) if case_id not in [None, ""] else None,
                    "ioc_id": str(ioc_id),
                    "route": route,
                    "message": "A manual IOC enrichment job is already queued or running for this IOC.",
                }
            job_id = uuid.uuid4().hex
            ASYNC_JOBS[key] = {"job_id": job_id, "queued_at": now, "case_id": case_id, "ioc_id": str(ioc_id), "route": route}
        api_log("manual_ioc_async_job_queued", job_id=job_id, case_id=case_id, ioc_id=ioc_id, route=route, duplicate=False)
        thread = threading.Thread(target=self.manual_ioc_async_worker, args=(job_id, key, case_id, str(ioc_id), route), daemon=True)
        thread.start()
        return {
            "status": "accepted",
            "queued": True,
            "job_id": job_id,
            "case_id": str(case_id) if case_id not in [None, ""] else None,
            "ioc_id": str(ioc_id),
            "route": route,
            "delay_seconds": ASYNC_JOB_DELAY_SECONDS,
            "message": "Manual IOC enrichment job accepted.",
        }

    def manual_ioc_async_worker(self, job_id, job_key, case_id, ioc_id, route):
        final_case_id = str(case_id) if case_id not in [None, ""] else ""
        try:
            api_log("manual_ioc_async_job_started", job_id=job_id, case_id=final_case_id or None, ioc_id=ioc_id, route=route)
            if not final_case_id:
                resolved = self.resolve_case_id_for_ioc(ioc_id)
                if resolved.get("status") != "ok":
                    api_log("manual_ioc_async_job_failed", job_id=job_id, ioc_id=ioc_id, route=route, reason="case_resolution_failed", details=resolved)
                    return
                final_case_id = str(resolved.get("case_id"))
                api_log("manual_ioc_async_job_case_resolved", job_id=job_id, case_id=final_case_id, ioc_id=ioc_id, route=route)
            time.sleep(ASYNC_JOB_DELAY_SECONDS)
            api_log("manual_ioc_async_job_delay_completed", job_id=job_id, case_id=final_case_id, ioc_id=ioc_id, delay_seconds=ASYNC_JOB_DELAY_SECONDS)
            args = ["--case-id", final_case_id, "--ioc-id", str(ioc_id), "--force"]
            response = self.run_manual_enrichment(args, force=True, live_write=True, case_id=final_case_id, ioc_id=ioc_id, route=route)
            api_log(
                "manual_ioc_async_job_write_completed",
                job_id=job_id,
                case_id=final_case_id,
                ioc_id=ioc_id,
                status=response.get("status"),
                ioc_description_updated=response.get("ioc_description_updated"),
                ioc_update_verified=response.get("ioc_update_verified"),
                case_notes_written=response.get("case_notes_written"),
                duplicates_skipped=response.get("duplicates_skipped"),
            )
            verification = verify_ioc_description_from_iris(final_case_id, ioc_id)
            api_log(
                "manual_ioc_async_job_verified",
                job_id=job_id,
                case_id=final_case_id,
                ioc_id=ioc_id,
                description_length=verification.get("description_length", 0),
                has_opencti_marker=verification.get("has_opencti_marker", False),
                tags=verification.get("tags", ""),
            )
            if response.get("ioc_update_verified") and not verification.get("has_opencti_marker"):
                api_log(
                    "manual_ioc_async_job_repair_attempted",
                    job_id=job_id,
                    case_id=final_case_id,
                    ioc_id=ioc_id,
                    description_length=verification.get("description_length", 0),
                    has_opencti_marker=verification.get("has_opencti_marker", False),
                )
                repair_response = self.run_manual_enrichment(args, force=True, live_write=True, case_id=final_case_id, ioc_id=ioc_id, route=route + "-repair")
                api_log(
                    "manual_ioc_async_job_write_completed",
                    job_id=job_id,
                    case_id=final_case_id,
                    ioc_id=ioc_id,
                    repair=True,
                    status=repair_response.get("status"),
                    ioc_description_updated=repair_response.get("ioc_description_updated"),
                    ioc_update_verified=repair_response.get("ioc_update_verified"),
                    case_notes_written=repair_response.get("case_notes_written"),
                    duplicates_skipped=repair_response.get("duplicates_skipped"),
                )
                repair_verification = verify_ioc_description_from_iris(final_case_id, ioc_id)
                api_log(
                    "manual_ioc_async_job_verified",
                    job_id=job_id,
                    case_id=final_case_id,
                    ioc_id=ioc_id,
                    repair=True,
                    description_length=repair_verification.get("description_length", 0),
                    has_opencti_marker=repair_verification.get("has_opencti_marker", False),
                    tags=repair_verification.get("tags", ""),
                )
                if not repair_verification.get("has_opencti_marker"):
                    api_log("manual_ioc_async_job_failed", job_id=job_id, case_id=final_case_id, ioc_id=ioc_id, route=route, reason="post_write_verification_failed_after_repair")
        except Exception as exc:
            api_log("manual_ioc_async_job_failed", job_id=job_id, case_id=final_case_id or None, ioc_id=ioc_id, route=route, error=str(exc))


CONTROL = ControlAPI()


class Handler(BaseHTTPRequestHandler):
    server_version = "OpenCTIIRISBridgeControl/2.0"

    def log_message(self, fmt, *args):
        safe = fmt % args if args else fmt
        print(json.dumps({"event": "request", "client": self.client_address[0], "path": self.path, "message": safe}), flush=True)

    def send_json(self, status, payload):
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def check_auth(self):
        if self.path == "/health":
            return True
        if not TOKEN:
            self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"status": "error", "error": "CONTROL_TOKEN is not configured"})
            return False
        if self.headers.get("Authorization", "") != "Bearer " + TOKEN:
            self.send_json(HTTPStatus.UNAUTHORIZED, {"status": "error", "error": "unauthorized"})
            return False
        return True

    def do_GET(self):
        if self.path == "/health":
            self.send_json(HTTPStatus.OK, {"status": "ok", "service": "opencti-iris-bridge-api", "version": "2.0.0"})
            return
        if not self.check_auth():
            return
        if urlparse(self.path).path == "/cases/enabled":
            result = CONTROL.run_runner(["--list-enabled"])
            self.send_json(HTTPStatus.OK, {"status": "ok" if result["returncode"] == 0 else "error", "runner": result})
            return
        self.send_json(HTTPStatus.NOT_FOUND, {"status": "error", "error": "not_found"})

    def do_POST(self):
        if not self.check_auth():
            return
        parsed = urlparse(self.path)
        payload = read_json(self)
        m = re.fullmatch(r"/cases/([^/]+)/iocs/([^/]+)/enrich-async", parsed.path)
        if m:
            case_id = m.group(1)
            ioc_id = m.group(2)
            response = CONTROL.queue_manual_ioc_async(case_id, ioc_id, "case-scoped-ioc-async")
            self.send_json(HTTPStatus.ACCEPTED, response)
            return
        m = re.fullmatch(r"/iocs/([^/]+)/enrich-async", parsed.path)
        if m:
            ioc_id = m.group(1)
            response = CONTROL.queue_manual_ioc_async(None, ioc_id, "ioc-only-fallback-async")
            self.send_json(HTTPStatus.ACCEPTED, response)
            return
        m = re.fullmatch(r"/cases/([^/]+)/enrich", parsed.path)
        if m:
            case_id = m.group(1)
            args = ["--case-id", case_id]
            force = True
            live_write = True
            args.append("--force")
            response = CONTROL.run_manual_enrichment(args, force=force, live_write=live_write, case_id=case_id, route="case-scoped")
            self.send_json(HTTPStatus.OK if response.get("status") == "ok" else HTTPStatus.CONFLICT, response)
            return
        m = re.fullmatch(r"/cases/([^/]+)/iocs/([^/]+)/enrich", parsed.path)
        if m:
            case_id = m.group(1)
            ioc_id = m.group(2)
            args = ["--case-id", case_id, "--ioc-id", ioc_id]
            force = True
            live_write = True
            args.append("--force")
            response = CONTROL.run_manual_enrichment(args, force=force, live_write=live_write, case_id=case_id, ioc_id=ioc_id, route="case-scoped-ioc")
            self.send_json(HTTPStatus.OK if response.get("status") == "ok" else HTTPStatus.CONFLICT, response)
            return
        m = re.fullmatch(r"/iocs/([^/]+)/enrich", parsed.path)
        if m:
            ioc_id = m.group(1)
            resolved = CONTROL.resolve_case_id_for_ioc(ioc_id)
            if resolved.get("status") != "ok":
                self.send_json(HTTPStatus.CONFLICT, resolved)
                return
            case_id = resolved.get("case_id")
            args = ["--case-id", case_id, "--ioc-id", ioc_id]
            force = True
            live_write = True
            args.append("--force")
            response = CONTROL.run_manual_enrichment(args, force=force, live_write=live_write, case_id=case_id, ioc_id=ioc_id, route="ioc-only-fallback-resolved")
            response["fallback_resolution"] = {"cases_checked": resolved.get("cases_checked"), "iocs_checked": resolved.get("iocs_checked")}
            self.send_json(HTTPStatus.OK if response.get("status") == "ok" else HTTPStatus.CONFLICT, response)
            return
        m = re.fullmatch(r"/cases/([^/]+)/(enable|disable)", parsed.path)
        if m:
            opt = "--enable-case" if m.group(2) == "enable" else "--disable-case"
            result = CONTROL.run_runner([opt, m.group(1)])
            self.send_json(HTTPStatus.OK, {"status": "ok" if result["returncode"] == 0 else "error", "runner": result})
            return
        if parsed.path == "/cases/enabled/clear":
            result = CONTROL.run_runner(["--clear-enabled"])
            self.send_json(HTTPStatus.OK, {"status": "ok" if result["returncode"] == 0 else "error", "runner": result})
            return
        self.send_json(HTTPStatus.NOT_FOUND, {"status": "error", "error": "not_found"})


def main():
    print(json.dumps({"status": "starting", "bind": f"{BIND_HOST}:{BIND_PORT}", "version": "2.0.0"}), flush=True)
    ThreadingHTTPServer((BIND_HOST, BIND_PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
PY

  chmod 750 "$OPENCTI_RUNNER" "$OPENCTI_API"
  chmod 640 "$OPENCTI_CORE_DIR"/*.py
  python3 -m py_compile "$OPENCTI_RUNNER" "$OPENCTI_API" "$OPENCTI_CORE_DIR"/*.py
}

opencti_stage_bridge_files() {
  opencti_write_bridge_files "$OPENCTI_STAGING_DIR"
}

opencti_promote_staged_bridge() {
  [ -x "$OPENCTI_STAGING_DIR/opencti_iris_bridge_runner.py" ] || die "Staged OpenCTI bridge runner is missing."
  [ -x "$OPENCTI_STAGING_DIR/opencti_iris_bridge_control_api.py" ] || die "Staged OpenCTI bridge control API is missing."
  [ -d "$OPENCTI_STAGING_DIR/opencti_iris_bridge_core" ] || die "Staged OpenCTI bridge core package is missing."
  opencti_prepare_dirs
  opencti_backup_file "$OPENCTI_RUNNER"
  opencti_backup_file "$OPENCTI_API"
  if [ -d "$OPENCTI_CORE_DIR" ]; then
    backup_dir="${OPENCTI_CORE_DIR}.backup-$(date +%Y%m%d_%H%M%S)"
    cp -a "$OPENCTI_CORE_DIR" "$backup_dir" 2>/dev/null || true
    info "Backup created: $backup_dir"
  fi
  rm -rf "$OPENCTI_CORE_DIR"
  cp -a "$OPENCTI_STAGING_DIR/opencti_iris_bridge_core" "$OPENCTI_CORE_DIR"
  cp -a "$OPENCTI_STAGING_DIR/opencti_iris_bridge_runner.py" "$OPENCTI_RUNNER"
  cp -a "$OPENCTI_STAGING_DIR/opencti_iris_bridge_control_api.py" "$OPENCTI_API"
  chmod 750 "$OPENCTI_RUNNER" "$OPENCTI_API"
  chmod 640 "$OPENCTI_CORE_DIR"/*.py
}

opencti_runner_supports() {
  runner=$1
  shift
  [ -x "$runner" ] || return 1
  help_output="$(python3 "$runner" --help 2>&1 || true)"
  for flag in "$@"; do
    printf '%s\n' "$help_output" | grep -q -- "$flag" || return 1
  done
}

opencti_runner_is_compatible() {
  runner=$1
  # OPENCTI_REQUIRED_RUNNER_FLAGS intentionally contains simple flag tokens only.
  # shellcheck disable=SC2086
  set -- $OPENCTI_REQUIRED_RUNNER_FLAGS
  opencti_runner_supports "$runner" "$@"
}

opencti_runner_incompatible_message() {
  runner=$1
  if [ "$runner" = "$OPENCTI_RUNNER" ]; then
    printf '[ERROR] Installed bridge runner is older than this setup.sh.\n' >&2
    printf '[ERROR] Run option 3: Install or update bridge service.\n' >&2
  else
    printf '[ERROR] Staged bridge runner does not support the required CLI flags: %s\n' "$runner" >&2
    printf '[ERROR] The setup script and generated bridge files are out of sync.\n' >&2
  fi
}

opencti_run_runner() {
  env_file=$1
  runner=$2
  shift 2
  opencti_require_env_file "$env_file"
  if ! opencti_runner_is_compatible "$runner"; then
    opencti_runner_incompatible_message "$runner"
    return 1
  fi
  BRIDGE_ENV_FILE="$env_file" python3 "$runner" --env-file "$env_file" "$@"
}

opencti_python_api_check() {
  mode=${1:-both}
  env_file=${2:-$OPENCTI_ENV_FILE}
  runner=${3:-$OPENCTI_RUNNER}
  opencti_require_env_file "$env_file"
  if [ ! -x "$runner" ]; then
    printf '[ERROR] OpenCTI bridge runner is not installed: %s\n' "$runner" >&2
    printf '[ERROR] Run ./setup.sh opencti-install to install or update bridge code.\n' >&2
    return 1
  fi
  case "$mode" in
    iris) component="iris" ;;
    opencti) component="opencti" ;;
    both|*) component="both" ;;
  esac
  if ! output="$(opencti_run_runner "$env_file" "$runner" --preflight --component "$component" 2>&1)"; then
    printf '%s\n' "$output"
    opencti_print_ssl_failure_hint "$output"
    opencti_mark_activation_blocked "preflight_failed"
    printf '[ERROR] OpenCTI bridge %s preflight failed.\n' "$component" >&2
    return 1
  fi
  printf '%s\n' "$output"
}

opencti_bridge_preflight() {
  env_file=${1:-$OPENCTI_ENV_FILE}
  control_env=${2:-$OPENCTI_CONTROL_ENV}
  runner=${3:-$OPENCTI_RUNNER}
  opencti_require_env_file "$env_file"
  if ! opencti_host_preflight "$control_env"; then
    opencti_mark_activation_blocked "host_preflight_failed"
    return 1
  fi
  if [ ! -x "$runner" ]; then
    printf '[ERROR] OpenCTI bridge runner is not installed: %s\n' "$runner" >&2
    printf '[ERROR] Run ./setup.sh opencti-install to install or update bridge code.\n' >&2
    return 1
  fi
  if ! output="$(opencti_run_runner "$env_file" "$runner" --preflight --component both 2>&1)"; then
    printf '%s\n' "$output"
    opencti_print_ssl_failure_hint "$output"
    opencti_mark_activation_blocked "preflight_failed"
    printf '[ERROR] OpenCTI bridge preflight failed.\n' >&2
    return 1
  fi
  printf '%s\n' "$output"
  opencti_write_report "preflight-passed"
  info "OpenCTI bridge preflight passed."
}

opencti_write_systemd_units() {
  opencti_require_root
  unit_dir=${1:-/etc/systemd/system}
  mkdir -p "$unit_dir"
  poll_minutes=$(opencti_env_value POLL_MINUTES 2>/dev/null || true)
  [ -n "$poll_minutes" ] || poll_minutes="30"
  cat >"$unit_dir/opencti-iris-bridge.service" <<EOFUNIT
[Unit]
Description=OpenCTI to DFIR-IRIS bridge one-shot enrichment run
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=${OPENCTI_ENV_FILE}
ExecStart=${OPENCTI_RUNNER} --env-file ${OPENCTI_ENV_FILE} --once
WorkingDirectory=${OPENCTI_BRIDGE_DIR}
User=${OPENCTI_SERVICE_USER}
Group=${OPENCTI_SERVICE_USER}
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ReadWritePaths=${OPENCTI_STATE_DIR} ${OPENCTI_LOG_DIR}
EOFUNIT

  cat >"$unit_dir/opencti-iris-bridge.timer" <<EOFUNIT
[Unit]
Description=Run OpenCTI to DFIR-IRIS bridge periodically

[Timer]
OnBootSec=2min
OnUnitActiveSec=${poll_minutes}min
AccuracySec=30s
Persistent=false
Unit=opencti-iris-bridge.service

[Install]
WantedBy=timers.target
EOFUNIT

  cat >"$unit_dir/opencti-iris-bridge-api.service" <<EOFUNIT
[Unit]
Description=OpenCTI to DFIR-IRIS bridge local control API
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=${OPENCTI_CONTROL_ENV}
ExecStart=${OPENCTI_API}
WorkingDirectory=${OPENCTI_BRIDGE_DIR}
Restart=on-failure
RestartSec=3
User=${OPENCTI_SERVICE_USER}
Group=${OPENCTI_SERVICE_USER}
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ReadWritePaths=${OPENCTI_STATE_DIR} ${OPENCTI_LOG_DIR}

[Install]
WantedBy=multi-user.target
EOFUNIT
  if [ "$unit_dir" = "/etc/systemd/system" ]; then
    systemctl daemon-reload
  fi
}

opencti_install_bridge_service() {
  env_file="$OPENCTI_ENV_FILE"
  control_env="$OPENCTI_CONTROL_ENV"
  using_pending="false"
  if [ -f "$OPENCTI_ENV_PENDING" ]; then
    env_file="$OPENCTI_ENV_PENDING"
    control_env="$OPENCTI_CONTROL_PENDING"
    using_pending="true"
    info "Using pending OpenCTI bridge configuration for install/update validation."
  fi
  opencti_require_env_file "$env_file"
  if ! opencti_host_preflight "$control_env"; then
    opencti_mark_activation_blocked "host_preflight_failed"
    return 1
  fi
  if ! opencti_stage_bridge_files; then
    opencti_mark_activation_blocked "bridge_stage_failed"
    printf '[ERROR] OpenCTI bridge staging or Python compile failed.\n' >&2
    return 1
  fi
  staged_runner="$OPENCTI_STAGING_DIR/opencti_iris_bridge_runner.py"
  if ! output="$(opencti_run_runner "$env_file" "$staged_runner" --preflight --component both 2>&1)"; then
    printf '%s\n' "$output"
    opencti_print_ssl_failure_hint "$output"
    opencti_mark_activation_blocked "preflight_failed"
    printf '[ERROR] Staged OpenCTI bridge preflight failed. Production bridge files were left untouched.\n' >&2
    return 1
  fi
  printf '%s\n' "$output"
  if ! output="$(opencti_run_runner "$env_file" "$staged_runner" --once --dry-run 2>&1)"; then
    printf '%s\n' "$output"
    opencti_print_ssl_failure_hint "$output"
    opencti_mark_activation_blocked "dry_run_failed"
    printf '[ERROR] Staged OpenCTI bridge dry-run failed. Production bridge files were left untouched.\n' >&2
    return 1
  fi
  printf '%s\n' "$output"
  if ! opencti_promote_staged_bridge; then
    opencti_mark_activation_blocked "bridge_promote_failed"
    return 1
  fi
  if [ "$using_pending" = "true" ]; then
    opencti_backup_file "$OPENCTI_ENV_FILE"
    opencti_backup_file "$OPENCTI_CONTROL_ENV"
    mv "$OPENCTI_ENV_PENDING" "$OPENCTI_ENV_FILE"
    [ -f "$OPENCTI_CONTROL_PENDING" ] && mv "$OPENCTI_CONTROL_PENDING" "$OPENCTI_CONTROL_ENV"
    chmod 600 "$OPENCTI_ENV_FILE" "$OPENCTI_CONTROL_ENV"
    opencti_fix_env_permissions 2>/dev/null || true
    opencti_mark_activation_ready
  fi
  if ! opencti_ensure_service_user; then
    opencti_mark_activation_blocked "service_user_failed"
    return 1
  fi
  unit_stage="$OPENCTI_STAGING_DIR/systemd"
  rm -rf "$unit_stage"
  if ! opencti_write_systemd_units "$unit_stage"; then
    opencti_mark_activation_blocked "systemd_stage_failed"
    return 1
  fi
  if ! cp -a "$unit_stage/opencti-iris-bridge.service" "$unit_stage/opencti-iris-bridge.timer" "$unit_stage/opencti-iris-bridge-api.service" /etc/systemd/system/; then
    opencti_mark_activation_blocked "systemd_promote_failed"
    return 1
  fi
  if ! systemctl daemon-reload; then opencti_mark_activation_blocked "systemd_reload_failed"; return 1; fi
  if ! systemctl enable opencti-iris-bridge-api.service >/dev/null; then opencti_mark_activation_blocked "api_enable_failed"; return 1; fi
  if ! systemctl restart opencti-iris-bridge-api.service; then opencti_mark_activation_blocked "api_restart_failed"; return 1; fi
  sleep 2
  if ! opencti_api_health; then
    opencti_mark_activation_blocked "api_health_failed"
    warn "Bridge control API health check failed after install."
    return 1
  fi
  systemctl disable --now opencti-iris-bridge.timer >/dev/null 2>&1 || true
  opencti_write_report "installed-api-running-timer-disabled"
  info "OpenCTI bridge service installed. Timer remains disabled until explicitly enabled."
}

opencti_run_dry_once() {
  env_file=${1:-$OPENCTI_ENV_FILE}
  opencti_require_env_file "$env_file"
  if ! opencti_bridge_preflight "$env_file"; then
    warn "OpenCTI bridge preflight failed; dry-run is blocked."
    return 1
  fi
  info "Running one OpenCTI bridge pass in dry-run mode. No IRIS writes will be made."
  if ! output="$(opencti_run_runner "$env_file" "$OPENCTI_RUNNER" --once --dry-run 2>&1)"; then
    printf '%s\n' "$output"
    opencti_print_ssl_failure_hint "$output"
    opencti_mark_activation_blocked "dry_run_failed"
    printf '[ERROR] OpenCTI bridge dry-run failed.\n' >&2
    return 1
  fi
  printf '%s\n' "$output"
  if id "$OPENCTI_SERVICE_USER" >/dev/null 2>&1; then
    service_group=$(opencti_service_group)
    chown -R "$OPENCTI_SERVICE_USER:$service_group" "$OPENCTI_STATE_DIR" "$OPENCTI_LOG_DIR" || true
  fi
  opencti_write_report "dry-run-passed"
  opencti_write_activation_status "ready" "dry_run_passed"
}

opencti_configure_scheduled_live_mode() {
  opencti_require_env
  opencti_backup_file "$OPENCTI_ENV_FILE"
  opencti_set_env_key "$OPENCTI_ENV_FILE" "DRY_RUN" "false"
  opencti_set_env_key "$OPENCTI_ENV_FILE" "UPDATE_IRIS_IOC" "true"
  opencti_set_env_key "$OPENCTI_ENV_FILE" "ADD_CASE_NOTE" "true"
  opencti_set_env_key "$OPENCTI_ENV_FILE" "ACTIVATION_STATUS" "ready"
  opencti_set_env_key "$OPENCTI_ENV_FILE" "BLOCK_REASON" ""
  opencti_write_activation_status "ready" "scheduled_live_write_enabled"
  info "Scheduled OpenCTI bridge mode set to live-write: DRY_RUN=false, UPDATE_IRIS_IOC=true, ADD_CASE_NOTE=true."
}

opencti_run_live_once_unattended() {
  opencti_require_env
  if ! opencti_bridge_preflight "$OPENCTI_ENV_FILE"; then
    opencti_mark_activation_blocked "preflight_failed"
    warn "OpenCTI bridge preflight failed; unattended live-write validation is blocked."
    return 1
  fi
  if ! opencti_state_schema_check "$OPENCTI_ENV_FILE" >/dev/null; then
    opencti_mark_activation_blocked "state_schema_invalid"
    warn "State DB schema check failed; unattended live-write validation is blocked."
    return 1
  fi
  info "Running one unattended OpenCTI bridge live-write validation pass. This writes to IRIS according to UPDATE_IRIS_IOC and ADD_CASE_NOTE."
  err_file=$(mktemp)
  if ! output="$(DRY_RUN=false opencti_run_runner "$OPENCTI_ENV_FILE" "$OPENCTI_RUNNER" --once 2>"$err_file")"; then
    cat "$err_file" >&2 || true
    rm -f "$err_file"
    printf '%s\n' "$output"
    opencti_mark_activation_blocked "live_write_failed"
    printf '[ERROR] OpenCTI bridge unattended live-write validation failed.\n' >&2
    return 1
  fi
  cat "$err_file" >&2 || true
  rm -f "$err_file"
  printf '%s\n' "$output"
  if id "$OPENCTI_SERVICE_USER" >/dev/null 2>&1; then
    service_group=$(opencti_service_group)
    chown -R "$OPENCTI_SERVICE_USER:$service_group" "$OPENCTI_STATE_DIR" "$OPENCTI_LOG_DIR" || true
  fi
  opencti_write_report "live-write-validation-passed"
  opencti_write_activation_status "ready" "live_write_test_passed"
}

opencti_live_write_eligibility_check() {
  env_file=${1:-$OPENCTI_ENV_FILE}
  python3 - "$env_file" "$OPENCTI_CAPABILITIES" "$OPENCTI_LAST_DRY_RUN" "$OPENCTI_ACTIVATION_STATUS" <<'PY'
import json
import sys
from pathlib import Path

env_path, caps_path, dry_path, activation_path = map(Path, sys.argv[1:5])

def read_json(path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception as exc:
        return {"__read_error": str(exc), "__path": str(path)}

def env_value(key, default=""):
    if not env_path.exists():
        return default
    for raw in env_path.read_text(errors="replace").splitlines():
        if raw.startswith(key + "="):
            return raw.split("=", 1)[1]
    return default

def env_bool(key, default=False):
    value = env_value(key, "true" if default else "false").strip().lower()
    return value in {"1", "true", "yes", "on"}

def emit_blocked(reason, recommended_action, dry=None, caps=None, activation=None):
    payload = {
        "status": "blocked",
        "component": "live_write_gate",
        "reason": reason,
        "details": {
            "activation_status": (activation or {}).get("status", "missing"),
            "block_reason": (activation or {}).get("reason", ""),
            "update_iris_ioc": env_bool("UPDATE_IRIS_IOC"),
            "add_case_note": env_bool("ADD_CASE_NOTE"),
            "latest_dry_run": {
                "dry_run": (dry or {}).get("dry_run"),
                "timestamp": (dry or {}).get("finished_at") or (dry or {}).get("timestamp") or (dry_path.stat().st_mtime if dry_path.exists() else None),
                "iocs_processed": (dry or {}).get("iocs_processed", 0),
                "matches_found": (dry or {}).get("matches_found", 0),
                "schema_warnings": (dry or {}).get("schema_warnings", []),
                "live_writes_would_have_occurred": (dry or {}).get("live_writes_would_have_occurred"),
            },
            "opencti_schema": {
                "query_mode": (caps or {}).get("last_successful_query_mode") or (caps or {}).get("supported_query_level"),
                "last_graphql_validation_error": (caps or {}).get("last_graphql_validation_error", ""),
            },
        },
        "recommended_action": recommended_action,
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    raise SystemExit(1)

caps = read_json(caps_path)
dry = read_json(dry_path)
activation = read_json(activation_path) or {}

if dry is None:
    emit_blocked("missing_latest_dry_run", "Run a successful dry-run before live-write validation.", {}, caps or {}, activation)
if dry.get("__read_error"):
    emit_blocked("invalid_latest_dry_run", f"Repair or remove malformed dry-run report: {dry.get('__path')}", dry, caps or {}, activation)
if caps is None:
    emit_blocked("missing_opencti_capabilities", "Run OpenCTI bridge preflight before live-write validation.", dry, {}, activation)
if caps.get("__read_error"):
    emit_blocked("invalid_opencti_capabilities", f"Repair or regenerate malformed OpenCTI capabilities file: {caps.get('__path')}", dry, caps, activation)
if activation.get("__read_error"):
    emit_blocked("invalid_activation_status", f"Repair or remove malformed activation status file: {activation.get('__path')}", dry, caps, activation)
if dry.get("dry_run") is not True:
    emit_blocked("latest_run_is_not_dry_run", "Run a fresh dry-run before live-write validation.", dry, caps, activation)
if dry.get("schema_warnings"):
    emit_blocked("dry_run_has_schema_warnings", "Fix OpenCTI schema warnings and rerun dry-run.", dry, caps, activation)
if caps.get("last_graphql_validation_error"):
    emit_blocked("opencti_graphql_validation_error", "Fix OpenCTI schema compatibility and rerun preflight/dry-run.", dry, caps, activation)
if not (caps.get("last_successful_query_mode") or caps.get("supported_query_level")):
    emit_blocked("missing_opencti_query_mode", "Run OpenCTI bridge preflight so a supported query mode can be cached.", dry, caps, activation)

update_ioc = env_bool("UPDATE_IRIS_IOC")
add_note = env_bool("ADD_CASE_NOTE")
if activation.get("status") == "blocked":
    if not update_ioc and not add_note:
        emit_blocked(
            "write_options_disabled_by_blocked_state",
            "Fix the activation block, then re-enable write options explicitly before live-write validation.",
            dry,
            caps,
            activation,
        )
    emit_blocked("activation_blocked", "Resolve the activation block and rerun dry-run before live-write validation.", dry, caps, activation)
if not update_ioc and not add_note:
    emit_blocked("write_options_disabled", "Enable UPDATE_IRIS_IOC or ADD_CASE_NOTE in the active bridge config before live-write validation.", dry, caps, activation)

iocs_seen = int(dry.get("iocs_seen") or 0)
iocs_processed = int(dry.get("iocs_processed") or 0)
recently_enriched_skipped = int(dry.get("recently_enriched_skipped") or 0)
matches_found = int(dry.get("matches_found") or 0)
idle_reason = ""
if iocs_seen == 0:
    idle_reason = "no_iocs_seen"
elif iocs_processed == 0 and recently_enriched_skipped >= iocs_seen:
    idle_reason = "all_iocs_recently_enriched"
elif iocs_processed == 0:
    idle_reason = "no_eligible_iocs_now"
elif matches_found == 0:
    idle_reason = "no_opencti_matches_now"
if idle_reason:
    print(json.dumps({
        "status": "idle",
        "component": "live_write_gate",
        "reason": idle_reason,
        "message": "No eligible IOCs need live-write right now. This is not an error.",
        "details": {
            "iocs_seen": iocs_seen,
            "iocs_processed": iocs_processed,
            "recently_enriched_skipped": recently_enriched_skipped,
            "matches_found": matches_found,
            "schema_warnings": dry.get("schema_warnings", []),
            "query_mode": dry.get("query_mode_used") or caps.get("last_successful_query_mode") or caps.get("supported_query_level"),
        },
    }, indent=2, sort_keys=True))
    raise SystemExit(0)

if dry.get("live_writes_would_have_occurred") is False:
    emit_blocked("dry_run_write_intent_disabled", "Rerun dry-run after enabling the intended IRIS write option so the live-write gate sees current intent.", dry, caps, activation)

summary = {
    "status": "ok",
    "component": "live_write_gate",
    "iris_url": env_value("IRIS_URL"),
    "opencti_url": env_value("OPENCTI_URL"),
    "latest_dry_run_timestamp": dry.get("finished_at") or dry.get("timestamp") or dry_path.stat().st_mtime,
    "cases_to_scan": env_value("IRIS_CASE_IDS") or "active/open cases",
    "iocs_expected": dry.get("iocs_seen"),
    "iocs_processed": dry.get("iocs_processed"),
    "matches_found": dry.get("matches_found"),
    "update_iris_ioc": update_ioc,
    "add_case_note": add_note,
    "activation_status": activation.get("status", "missing"),
    "activation_reason": activation.get("reason", ""),
    "duplicate_prevention": "enabled: SQLite IOC hash + OpenCTI object IDs",
    "scheduled_dry_run": env_value("DRY_RUN", "true"),
    "forced_dry_run_for_this_execution": False,
    "query_mode_used": dry.get("query_mode_used") or caps.get("last_successful_query_mode"),
}
print(json.dumps(summary, indent=2, sort_keys=True))
PY
}

opencti_live_write_precheck() {
  opencti_live_write_eligibility_check "$@"
}

opencti_run_live_once() {
  opencti_require_env
  [ -x "$OPENCTI_RUNNER" ] || die "OpenCTI bridge runner is not installed. Run ./setup.sh opencti-install first."
  if ! opencti_bridge_preflight "$OPENCTI_ENV_FILE" "$OPENCTI_CONTROL_ENV"; then
    warn "OpenCTI bridge preflight failed; live-write validation is blocked."
    return 1
  fi

  printf '\nState schema check\n'
  set +e
  state_output="$(opencti_state_schema_check "$OPENCTI_ENV_FILE" 2>&1)"
  state_rc=$?
  set -e
  printf '%s\n' "$state_output"
  if [ "$state_rc" -ne 0 ]; then
    opencti_mark_activation_blocked "state_schema_invalid"
    python3 - <<'PY'
import json
print(json.dumps({
  "status": "blocked",
  "component": "live_write_gate",
  "reason": "state_schema_invalid",
  "details": {"state_schema_check": "failed"},
  "recommended_action": "Fix the state schema diagnostic above, then rerun dry-run and live-write validation."
}, indent=2, sort_keys=True))
PY
    return 1
  fi

  printf '\nLive-write eligibility check\n'
  set +e
  summary="$(opencti_live_write_eligibility_check "$OPENCTI_ENV_FILE" 2>&1)"
  eligibility_rc=$?
  set -e
  printf '%s\n' "$summary"
  eligibility_status="$(ELIGIBILITY_OUTPUT="$summary" python3 - <<'PY' 2>/dev/null || printf unknown
import json
import os
print(json.loads(os.environ.get("ELIGIBILITY_OUTPUT", "{}")).get("status", "unknown"))
PY
)"
  if [ "$eligibility_status" = "idle" ]; then
    info "Nothing to write right now. No eligible IOCs need live-write; this is not an error."
    return 0
  fi
  if [ "$eligibility_rc" -ne 0 ]; then
    reason="$(ELIGIBILITY_OUTPUT="$summary" python3 - <<'PY' 2>/dev/null || printf live_write_eligibility_failed
import json
import os
print(json.loads(os.environ.get("ELIGIBILITY_OUTPUT", "{}")).get("reason", "live_write_eligibility_failed"))
PY
)"
    opencti_mark_activation_blocked "$reason"
    return 1
  fi
  printf '\nControlled one-time OpenCTI -> IRIS live-write validation\n'
  python3 - "$summary" <<'PY'
import json
import sys
data = json.loads(sys.argv[1])
print(f"IRIS URL:                 {data.get('iris_url')}")
print(f"OpenCTI URL:              {data.get('opencti_url')}")
print(f"Latest dry-run timestamp: {data.get('latest_dry_run_timestamp')}")
print(f"Cases to scan:            {data.get('cases_to_scan')}")
print(f"IOCs expected:            {data.get('iocs_expected')}")
print(f"IOCs processed:           {data.get('iocs_processed')}")
print(f"Matches found:            {data.get('matches_found')}")
print(f"UPDATE_IRIS_IOC:          {data.get('update_iris_ioc')}")
print(f"ADD_CASE_NOTE:            {data.get('add_case_note')}")
print(f"Activation status:        {data.get('activation_status')}")
print(f"Duplicate prevention:     {data.get('duplicate_prevention')}")
print("DRY_RUN for this run:     false")
PY
  printf '\nThis run will force DRY_RUN=false for this one execution only.\n'
  printf 'It will not enable the timer, modify OpenCTI, touch Wazuh, install buttons, or restart IRIS/Wazuh.\n'
  printf 'IRIS writes are limited by UPDATE_IRIS_IOC and ADD_CASE_NOTE from the active bridge config.\n'
  printf '\nType LIVE_WRITE to run one live-write validation: '
  IFS= read -r confirmation || die "Input stream closed."
  if [ "$confirmation" != "LIVE_WRITE" ]; then
    warn "Live-write validation cancelled. Exact confirmation was not entered."
    return 1
  fi
  err_file=$(mktemp)
  if ! output="$(DRY_RUN=false opencti_run_runner "$OPENCTI_ENV_FILE" "$OPENCTI_RUNNER" --once 2>"$err_file")"; then
    cat "$err_file" >&2 || true
    rm -f "$err_file"
    printf '%s\n' "$output"
    opencti_mark_activation_blocked "live_write_failed"
    printf '[ERROR] OpenCTI bridge live-write validation failed.\n' >&2
    return 1
  fi
  cat "$err_file" >&2 || true
  rm -f "$err_file"
  printf '%s\n' "$output"
  opencti_write_report "live-write-validation-passed"
  opencti_write_activation_status "ready" "live_write_test_passed"
}

opencti_timer_activation_check() {
  scheduled_dry_run=$(opencti_env_value DRY_RUN "$OPENCTI_ENV_FILE" 2>/dev/null || printf 'true')
  update_ioc=$(opencti_env_value UPDATE_IRIS_IOC "$OPENCTI_ENV_FILE" 2>/dev/null || printf 'false')
  add_note=$(opencti_env_value ADD_CASE_NOTE "$OPENCTI_ENV_FILE" 2>/dev/null || printf 'false')
  python3 - "$OPENCTI_CAPABILITIES" "$OPENCTI_LAST_DRY_RUN" "$OPENCTI_LAST_LIVE_WRITE" "$OPENCTI_ACTIVATION_STATUS" "$scheduled_dry_run" "$update_ioc" "$add_note" <<'PY'
import json
import sys
from pathlib import Path

caps_path, dry_path, live_path, activation_path = map(Path, sys.argv[1:5])
scheduled_dry_run = str(sys.argv[5]).lower() in {"1", "true", "yes", "on"}
update_ioc = str(sys.argv[6]).lower() in {"1", "true", "yes", "on"}
add_note = str(sys.argv[7]).lower() in {"1", "true", "yes", "on"}

def emit(status, reason, message, code=1, **details):
    payload = {
        "status": status,
        "timer_ready": False,
        "reason": reason,
        "message": message,
        "details": details,
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    raise SystemExit(code)

def read_json(path):
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception as exc:
        emit("blocked", "invalid_json", f"Unable to read JSON file: {path}", path=str(path), error=str(exc))

if not caps_path.exists():
    emit("blocked", "missing_opencti_capabilities", "Missing OpenCTI capabilities file. Run preflight or install/update first.")
caps = read_json(caps_path)
dry = read_json(dry_path)
live = read_json(live_path)
activation = read_json(activation_path)
if activation.get("status") == "blocked":
    emit("blocked", "activation_blocked", "OpenCTI bridge activation is blocked.", activation_reason=activation.get("reason", "unknown"))
if caps.get("last_graphql_validation_error"):
    emit("blocked", "schema_validation_error", "OpenCTI schema validation errors are present; timer activation is blocked.", error=caps.get("last_graphql_validation_error"))
query_mode = caps.get("last_successful_query_mode") or caps.get("supported_query_level")
if not query_mode:
    emit("blocked", "missing_query_mode", "No successful OpenCTI query mode is cached; timer activation is blocked.")
if dry.get("schema_warnings"):
    emit("blocked", "dry_run_schema_warnings", "Latest dry-run contains schema warnings; timer activation is blocked.", schema_warnings=dry.get("schema_warnings"))

iocs_seen = int(dry.get("iocs_seen") or 0)
iocs_processed = int(dry.get("iocs_processed") or 0)
matches_found = int(dry.get("matches_found") or 0)
recently_skipped = int(dry.get("recently_enriched_skipped") or 0)
if not dry:
    current_status = "not_checked"
    current_reason = "no_recent_dry_run_snapshot"
elif iocs_seen == 0:
    current_status = "idle"
    current_reason = "no_iocs_seen"
elif iocs_processed == 0 and recently_skipped >= iocs_seen:
    current_status = "idle"
    current_reason = "all_iocs_recently_enriched"
elif iocs_processed == 0:
    current_status = "idle"
    current_reason = "no_eligible_iocs_now"
elif matches_found == 0:
    current_status = "pending-work-found"
    current_reason = "eligible_iocs_processed_no_opencti_matches"
else:
    current_status = "pending-work-found"
    current_reason = "eligible_iocs_processed_with_matches"

live_passed = live.get("dry_run") is False and not live.get("schema_warnings") and not live.get("error")
if not scheduled_dry_run and not (update_ioc or add_note):
    emit(
        "blocked",
        "live_write_options_disabled",
        "Scheduled live-write mode requires UPDATE_IRIS_IOC=true or ADD_CASE_NOTE=true.",
        scheduled_dry_run=scheduled_dry_run,
        update_iris_ioc=update_ioc,
        add_case_note=add_note,
    )
payload = {
    "status": "ok",
    "timer_ready": True,
    "current_work_status": current_status,
    "reason": current_reason,
    "query_mode": query_mode,
    "iocs_seen": iocs_seen,
    "recently_enriched_skipped": recently_skipped,
    "iocs_processed": iocs_processed,
    "matches_found": matches_found,
    "last_dry_run": "snapshot_available" if dry else "not_checked",
    "last_live_write_test": "passed" if live_passed else "missing_or_failed",
    "scheduled_dry_run": scheduled_dry_run,
    "live_write_required": not scheduled_dry_run,
    "live_write_passed": live_passed,
    "message": "Timer can be enabled. Future new or eligible IOCs will be processed automatically.",
}
print(json.dumps(payload, indent=2))
if not scheduled_dry_run and not live_passed:
    raise SystemExit(2)
PY
}

opencti_enable_timer() {
  opencti_require_env
  [ -f /etc/systemd/system/opencti-iris-bridge.timer ] || die "Bridge timer is not installed. Run ./setup.sh opencti-install first."
  [ -f /etc/systemd/system/opencti-iris-bridge.service ] || die "Bridge service is not installed. Run ./setup.sh opencti-install first."
  if ! opencti_bridge_preflight; then
    opencti_mark_activation_blocked "preflight_failed"
    warn "OpenCTI bridge preflight failed; timer activation is blocked."
    return 1
  fi
  if ! opencti_state_schema_check "$OPENCTI_ENV_FILE" >/dev/null; then
    opencti_mark_activation_blocked "state_schema_invalid"
    warn "State DB schema check failed; timer activation is blocked."
    return 1
  fi
  if ! opencti_run_dry_once; then
    opencti_mark_activation_blocked "dry_run_failed"
    warn "Dry-run failed; timer activation is blocked."
    return 1
  fi
  set +e
  timer_check_output="$(opencti_timer_activation_check 2>&1)"
  timer_check_rc=$?
  set -e
  printf '%s\n' "$timer_check_output"
  if [ "$timer_check_rc" -eq 2 ]; then
    warn "Scheduled live-write timer does not have a successful live-write validation. Override is possible but not recommended."
    if opencti_auto_confirm_enabled; then
      warn "Automated OpenCTI setup will not override scheduled live-write safety without validation. Run full setup or live-write validation first."
      return 1
    fi
    printf 'Type OVERRIDE_LIVE_WRITE_TEST to continue without a successful live-write validation: '
    IFS= read -r override_confirmation || die "Input stream closed."
    if [ "$override_confirmation" != "OVERRIDE_LIVE_WRITE_TEST" ]; then
      warn "Timer activation cancelled."
      return 1
    fi
  elif [ "$timer_check_rc" -ne 0 ]; then
    return 1
  fi
  poll_minutes=$(opencti_env_value POLL_MINUTES "$OPENCTI_ENV_FILE" 2>/dev/null || printf '30')
  scheduled_dry_run=$(opencti_env_value DRY_RUN "$OPENCTI_ENV_FILE" 2>/dev/null || printf 'true')
  update_ioc=$(opencti_env_value UPDATE_IRIS_IOC "$OPENCTI_ENV_FILE" 2>/dev/null || printf 'false')
  add_note=$(opencti_env_value ADD_CASE_NOTE "$OPENCTI_ENV_FILE" 2>/dev/null || printf 'false')
  printf '\nTimer enablement summary\n'
  TIMER_CHECK_JSON="$timer_check_output" python3 - "$poll_minutes" "$scheduled_dry_run" "$update_ioc" "$add_note" <<'PY' || true
import json
import os
import sys

poll_minutes, scheduled_dry_run, update_ioc, add_note = sys.argv[1:5]
try:
    data = json.loads(os.environ.get("TIMER_CHECK_JSON", "{}"))
except Exception:
    data = {}
scheduled_mode = "dry-run" if str(scheduled_dry_run).lower() in {"1", "true", "yes", "on"} else "live-write"
print(f"Timer readiness:          {'passed' if data.get('timer_ready') else 'failed'}")
print(f"Current work status:      {data.get('current_work_status', 'unknown')}")
print(f"Current work reason:      {data.get('reason', 'unknown')}")
print(f"IOCs seen:                {data.get('iocs_seen', 0)}")
print(f"IOCs processed now:       {data.get('iocs_processed', 0)}")
print(f"Recently enriched skipped {data.get('recently_enriched_skipped', 0)}")
print(f"Matches found now:        {data.get('matches_found', 0)}")
print(f"Scheduled mode:           {scheduled_mode}")
print(f"Timer interval:           {poll_minutes} minutes")
print(f"UPDATE_IRIS_IOC:          {update_ioc}")
print(f"ADD_CASE_NOTE:            {add_note}")
if data.get("current_work_status") == "idle":
    print("")
    print("No eligible IOCs need enrichment right now. This is not an error.")
    print("The timer will process future new or re-eligible IOCs automatically.")
elif data.get("current_work_status") == "not_checked":
    print("")
    print("No current work snapshot is available, but readiness checks passed.")
    print("The timer will process future new or eligible IOCs automatically.")
PY
  case "$scheduled_dry_run" in
    true|TRUE|yes|YES|1|on|ON)
      if opencti_auto_confirm_enabled; then
        info "Automated OpenCTI setup: enabling the bridge timer in scheduled dry-run mode without an additional confirmation prompt."
      else
        if ! prompt_yes_no "Enable the OpenCTI bridge timer in scheduled dry-run mode?"; then
          warn "Timer activation cancelled."
          return 1
        fi
      fi
      ;;
    *)
      if opencti_auto_confirm_enabled; then
        info "Automated OpenCTI setup: enabling the bridge timer in scheduled live-write mode after validation."
        info "Scheduled runs will update IRIS because DRY_RUN=false, UPDATE_IRIS_IOC=$update_ioc, ADD_CASE_NOTE=$add_note."
      else
        printf '\nScheduled runs are configured for live-write mode.\n'
        printf 'Type ENABLE_LIVE_TIMER to enable scheduled live enrichment: '
        IFS= read -r live_timer_confirmation || die "Input stream closed."
        if [ "$live_timer_confirmation" != "ENABLE_LIVE_TIMER" ]; then
          warn "Scheduled live timer activation cancelled."
          return 1
        fi
      fi
      ;;
  esac
  opencti_fix_env_permissions 2>/dev/null || true
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable --now opencti-iris-bridge.timer >/dev/null
  opencti_write_report "timer-enabled"
  info "OpenCTI bridge timer enabled."
}

opencti_configure_full_setup() {
  info "Starting guided OpenCTI bridge configuration and full deployment."
  if ! opencti_configure_bridge "$@"; then
    warn "OpenCTI bridge configuration/install validation failed."
    return 1
  fi

  info "Installing and registering IRIS OpenCTI manual enrichment module/buttons."
  if ! ( OPENCTI_AUTO_CONFIRM=true; opencti_install_iris_module ); then
    warn "OpenCTI bridge was configured, but IRIS manual enrichment module/button installation failed."
    return 1
  fi

  info "Configuring OpenCTI scheduled automation for live-write IRIS enrichment."
  opencti_configure_scheduled_live_mode

  info "Running one unattended live-write validation before enabling the scheduled timer."
  if ! opencti_run_live_once_unattended; then
    warn "OpenCTI bridge live-write validation failed. Timer was not enabled."
    return 1
  fi

  info "Enabling OpenCTI bridge scheduled live-write timer."
  if ! ( OPENCTI_AUTO_CONFIRM=true; opencti_enable_timer ); then
    warn "OpenCTI bridge and IRIS buttons were installed, but the timer was not enabled."
    return 1
  fi

  opencti_write_report "full-setup-complete"
  info "OpenCTI bridge full setup completed: bridge installed, API running, IRIS buttons registered, scheduled live-write timer enabled."
}

opencti_status() {
  bind_host=$(opencti_env_value CONTROL_BIND_HOST "$OPENCTI_CONTROL_ENV" 2>/dev/null || printf '127.0.0.1')
  bind_port=$(opencti_env_value CONTROL_BIND_PORT "$OPENCTI_CONTROL_ENV" 2>/dev/null || printf '9097')
  dry_run=$(opencti_env_value DRY_RUN "$OPENCTI_ENV_FILE" 2>/dev/null || printf 'unknown')
  update_ioc=$(opencti_env_value UPDATE_IRIS_IOC "$OPENCTI_ENV_FILE" 2>/dev/null || printf 'unknown')
  add_note=$(opencti_env_value ADD_CASE_NOTE "$OPENCTI_ENV_FILE" 2>/dev/null || printf 'unknown')
  timer_status="not-installed"
  api_status="not-installed"
  if have systemctl; then
    systemctl list-unit-files opencti-iris-bridge.timer >/dev/null 2>&1 && timer_status=$(systemctl is-enabled opencti-iris-bridge.timer 2>/dev/null || true)
    systemctl list-unit-files opencti-iris-bridge-api.service >/dev/null 2>&1 && api_status=$(systemctl is-active opencti-iris-bridge-api.service 2>/dev/null || true)
  fi
  printf '\nOpenCTI <-> IRIS bridge status\n'
  printf 'Bridge version:          %s\n' "$OPENCTI_BRIDGE_VERSION"
  printf 'Setup script version:    %s\n' "$OPENCTI_BRIDGE_VERSION"
  printf 'Installed dir:           %s\n' "$OPENCTI_BRIDGE_DIR"
  printf 'Active config:           %s\n' "$OPENCTI_ENV_FILE"
  if [ -f "$OPENCTI_ENV_PENDING" ]; then
    printf 'Pending config:          %s\n' "$OPENCTI_ENV_PENDING"
  else
    printf 'Pending config:          none\n'
  fi
  printf 'API bind:                %s:%s\n' "$bind_host" "$bind_port"
  printf 'Timer status:            %s\n' "$timer_status"
  printf 'API service status:      %s\n' "$api_status"
  printf 'Dry-run mode:            %s\n' "$dry_run"
  printf 'Update IRIS IOC table:   %s\n' "$update_ioc"
  printf 'Add Markdown notes:      %s\n' "$add_note"
  python3 - "$OPENCTI_CAPABILITIES" "$OPENCTI_LAST_PREFLIGHT" "$OPENCTI_LAST_DRY_RUN" "$OPENCTI_LAST_LIVE_WRITE" "$OPENCTI_ACTIVATION_STATUS" "$dry_run" "$update_ioc" "$add_note" <<'PY' || true
import json
import sys
from pathlib import Path
caps_path, pre_path, dry_path, live_path, activation_path = map(Path, sys.argv[1:6])
scheduled_dry_run = str(sys.argv[6]).lower() in {"1", "true", "yes", "on"}
update_ioc = str(sys.argv[7]).lower() in {"1", "true", "yes", "on"}
add_note = str(sys.argv[8]).lower() in {"1", "true", "yes", "on"}
def read(path):
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}
caps = read(caps_path)
dry = read(dry_path)
pre = read(pre_path)
live = read(live_path)
activation = read(activation_path)
dry_snapshot_ok = not dry.get('schema_warnings')
live_ok = live.get('dry_run') is False and not live.get('schema_warnings') and not live.get('error')
schema_ok = not caps.get('last_graphql_validation_error') and bool(caps.get('last_successful_query_mode') or caps.get('supported_query_level'))
blocked_reason = activation.get('reason') if activation.get('status') == 'blocked' else ''
iocs_seen = int(dry.get('iocs_seen') or 0)
iocs_processed = int(dry.get('iocs_processed') or 0)
matches_found = int(dry.get('matches_found') or 0)
recently_skipped = int(dry.get('recently_enriched_skipped') or 0)
if not dry:
    current_work_status = 'not_checked'
    current_work_reason = 'no_recent_dry_run_snapshot'
elif iocs_seen == 0:
    current_work_status = 'idle'
    current_work_reason = 'no_iocs_seen'
elif iocs_processed == 0 and recently_skipped >= iocs_seen:
    current_work_status = 'idle'
    current_work_reason = 'all_iocs_recently_enriched'
elif iocs_processed == 0:
    current_work_status = 'idle'
    current_work_reason = 'no_eligible_iocs_now'
elif matches_found == 0:
    current_work_status = 'pending-work-found'
    current_work_reason = 'eligible_iocs_processed_no_opencti_matches'
else:
    current_work_status = 'pending-work-found'
    current_work_reason = 'eligible_iocs_processed_with_matches'
live_write_options_ok = scheduled_dry_run or update_ioc or add_note
timer_eligible = bool(schema_ok and dry_snapshot_ok and not blocked_reason and live_write_options_ok and (scheduled_dry_run or live_ok))
if blocked_reason:
    timer_block_reason = blocked_reason
elif not schema_ok:
    timer_block_reason = 'schema_check_failed'
elif not dry_snapshot_ok:
    timer_block_reason = 'dry_run_schema_warnings'
elif not live_write_options_ok:
    timer_block_reason = 'live_write_options_disabled'
elif not scheduled_dry_run and not live_ok:
    timer_block_reason = 'live_write_test_missing_or_failed'
else:
    timer_block_reason = 'none'
print(f"Activation status:      {activation.get('status', 'missing')}")
print(f"Block reason:           {activation.get('reason', 'none') or 'none'}")
print(f"Last preflight result:   {pre.get('status', 'missing')}")
print(f"Last dry-run result:     iocs_processed={dry.get('iocs_processed', 'missing')} matches={dry.get('matches_found', 'missing')}")
print(f"Current work status:     {current_work_status}")
print(f"Current work reason:     {current_work_reason}")
print(f"Recently enriched skipped: {recently_skipped}")
print(f"Last live-write result:  iocs_processed={live.get('iocs_processed', 'missing')} matches={live.get('matches_found', 'missing')}")
print(f"Live-write test passed:  {'yes' if live_ok else 'no'}")
print(f"Timer eligible:          {'yes' if timer_eligible else 'no'}")
print(f"Timer block reason:      {timer_block_reason}")
print(f"Duplicate prevention:    enabled: SQLite IOC hash + OpenCTI object IDs")
print(f"Last note write count:   {live.get('case_notes_written', 0)}")
print(f"Last IOC update count:   {live.get('ioc_updates_written', 0)}")
print(f"Last duplicates skipped: {live.get('duplicates_skipped', 0)}")
print(f"OpenCTI query mode:      {caps.get('last_successful_query_mode') or caps.get('supported_query_level') or 'missing'}")
print(f"Unsupported fields:      {json.dumps(caps.get('unsupported_fields', {}), sort_keys=True)}")
print(f"Last GraphQL error:      {caps.get('last_graphql_validation_error') or 'none'}")
last = dry.get('last_result') or live.get('last_result') or {}
print(f"Last IOC result:         value={last.get('value', 'missing')} matches={last.get('match_count', 'missing')} verdict={last.get('verdict', 'missing')}")
PY
  printf '\nState DB schema:\n'
  if [ -f "$OPENCTI_ENV_FILE" ]; then
    state_db_path=$(opencti_env_value STATE_DB "$OPENCTI_ENV_FILE" 2>/dev/null || printf '%s' "$OPENCTI_STATE_DB")
    set +e
    state_output="$(STATE_DB_PATH="$state_db_path" python3 - <<'PY' 2>&1
import json
import os
import sqlite3
from pathlib import Path

path = Path(os.environ.get("STATE_DB_PATH") or "/var/lib/opencti-iris-bridge/state.sqlite3")
required = {
    "enriched_iocs": [
        "key", "case_id", "ioc_id", "ioc_hash", "status", "dry_run", "last_seen",
        "last_enriched", "opencti_ids", "opencti_object_ids", "match_count",
        "query_mode", "last_error", "last_run_at", "live_write",
    ],
    "note_dirs": ["case_id", "directory_id", "created_at"],
    "state_migrations": ["version", "applied_at", "action"],
}

def empty_status(reason):
    missing = [f"{table}.{column}" for table, columns in required.items() for column in columns]
    return {
        "status": "ok",
        "state_db": {
            "path": str(path),
            "exists": path.exists(),
            "schema_version": 0,
            "schema_current": False,
            "missing_columns": missing,
            "missing_columns_by_table": required,
            "last_migration_result": reason,
            "last_migration_timestamp": None,
        },
    }

if not path.exists():
    print(json.dumps(empty_status("missing_state_db"), indent=2, sort_keys=True))
    raise SystemExit(0)

try:
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
except Exception as exc:
    print(json.dumps({
        "status": "error",
        "state_db": {
            "path": str(path),
            "exists": path.exists(),
            "schema_version": "unknown",
            "schema_current": False,
            "missing_columns": [],
            "last_migration_result": f"unable_to_open_readonly: {exc}",
            "last_migration_timestamp": None,
        },
    }, indent=2, sort_keys=True))
    raise SystemExit(0)

with db:
    version = int(db.execute("PRAGMA user_version").fetchone()[0] or 0)
    def table_exists(table):
        return db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is not None
    def columns(table):
        if not table_exists(table):
            return []
        return [row[1] for row in db.execute(f"PRAGMA table_info({table})").fetchall()]
    missing_by_table = {}
    for table, wanted in required.items():
        existing = set(columns(table))
        missing = [column for column in wanted if column not in existing]
        if missing:
            missing_by_table[table] = missing
    missing_flat = [f"{table}.{column}" for table, cols in missing_by_table.items() for column in cols]
    migrations = []
    last_ts = None
    if table_exists("state_migrations"):
        rows = db.execute("SELECT applied_at, action FROM state_migrations ORDER BY applied_at DESC LIMIT 10").fetchall()
        migrations = [row[1] for row in rows]
        if rows:
            last_ts = rows[0][0]
    print(json.dumps({
        "status": "ok",
        "state_db": {
            "path": str(path),
            "exists": True,
            "schema_version": version,
            "schema_current": version >= 3 and not missing_by_table,
            "missing_columns": missing_flat,
            "missing_columns_by_table": missing_by_table,
            "last_migration_result": migrations[0] if migrations else "none",
            "last_migration_timestamp": last_ts,
            "migrations_applied": migrations,
        },
    }, indent=2, sort_keys=True))
PY
)"
    state_rc=$?
    set -e
    if [ "$state_rc" -eq 0 ]; then
      STATE_OUTPUT="$state_output" python3 - <<'PY' || true
import json
import os

raw = os.environ.get("STATE_OUTPUT", "")
try:
    payload = json.loads(raw)
except Exception as exc:
    print(f"  Status: unable to parse state-check output: {exc}")
    print("  Raw state-check output:")
    for line in raw.splitlines() or [""]:
        print(f"    {line}")
    raise SystemExit(0)

data = payload.get("state_db", {})
print(f"  Path: {data.get('path', 'missing')}")
print(f"  Exists: {data.get('exists', False)}")
print(f"  PRAGMA user_version: {data.get('schema_version', 'missing')}")
print(f"  Schema current: {data.get('schema_current', False)}")
print(f"  Missing columns: {json.dumps(data.get('missing_columns', []), sort_keys=True)}")
print(f"  Last migration result: {data.get('last_migration_result', 'missing')}")
print(f"  Last migration timestamp: {data.get('last_migration_timestamp', 'missing')}")
PY
    else
      printf '%s\n' "$state_output"
    fi
  else
    printf '  State check unavailable until bridge runner and active env are installed.\n'
  fi
  printf '\nLive-write eligibility:\n'
  if [ -f "$OPENCTI_ENV_FILE" ]; then
    set +e
    eligibility_output="$(opencti_live_write_eligibility_check "$OPENCTI_ENV_FILE" 2>&1)"
    eligibility_rc=$?
    set -e
    ELIGIBILITY_OUTPUT="$eligibility_output" python3 - <<'PY' || true
import json
import os

raw = os.environ.get("ELIGIBILITY_OUTPUT", "")
try:
    payload = json.loads(raw)
except Exception as exc:
    print(f"  Status: unable to parse live-write eligibility output: {exc}")
    print("  Raw live-write eligibility output:")
    for line in raw.splitlines() or [""]:
        print(f"    {line}")
    raise SystemExit(0)

print(json.dumps(payload, indent=2, sort_keys=True))
PY
    if [ "$eligibility_rc" -ne 0 ]; then
      printf '  Live-write blocked; see JSON reason above.\n'
    fi
  else
    printf '  Eligibility check unavailable until active bridge env exists.\n'
  fi
  if [ -f "$OPENCTI_BRIDGE_LOG" ]; then
    printf '\nRecent relevant bridge logs:\n'
    tail -n 80 "$OPENCTI_BRIDGE_LOG" | grep -E 'bridge_run_completed|ioc_enrichment_result|graphql|downgrad|error|warning' | tail -n 30 || true
  fi
}

opencti_show_capabilities() {
  if [ ! -f "$OPENCTI_CAPABILITIES" ]; then
    warn "OpenCTI capabilities file is missing: $OPENCTI_CAPABILITIES"
    warn "Run ./setup.sh opencti-preflight first."
    return 1
  fi
  python3 -m json.tool "$OPENCTI_CAPABILITIES"
}

opencti_rotate_logs() {
  opencti_prepare_dirs
  ts=$(date +%Y%m%d_%H%M%S)
  if [ -f "$OPENCTI_BRIDGE_LOG" ]; then
    mv "$OPENCTI_BRIDGE_LOG" "$OPENCTI_BRIDGE_LOG.$ts"
    touch "$OPENCTI_BRIDGE_LOG"
    chmod 640 "$OPENCTI_BRIDGE_LOG"
    info "Rotated bridge log to $OPENCTI_BRIDGE_LOG.$ts"
  fi
}

opencti_state_schema_check() {
  env_file=${1:-$OPENCTI_ENV_FILE}
  opencti_require_env_file "$env_file"
  [ -x "$OPENCTI_RUNNER" ] || die "OpenCTI bridge runner is not installed. Run ./setup.sh opencti-install first."
  if ! output="$(opencti_run_runner "$env_file" "$OPENCTI_RUNNER" --state-check 2>&1)"; then
    printf '%s\n' "$output"
    printf '[ERROR] OpenCTI bridge state DB check failed.\n' >&2
    return 1
  fi
  printf '%s\n' "$output"
}

opencti_state_check() {
  opencti_state_schema_check "$@"
}

opencti_state_migrate() {
  env_file=${1:-$OPENCTI_ENV_FILE}
  opencti_require_env_file "$env_file"
  [ -x "$OPENCTI_RUNNER" ] || die "OpenCTI bridge runner is not installed. Run ./setup.sh opencti-install first."
  if ! output="$(opencti_run_runner "$env_file" "$OPENCTI_RUNNER" --state-migrate 2>&1)"; then
    printf '%s\n' "$output"
    opencti_mark_activation_blocked "state_migration_failed"
    printf '[ERROR] OpenCTI bridge state DB migration failed.\n' >&2
    return 1
  fi
  printf '%s\n' "$output"
}

opencti_support_bundle() {
  opencti_prepare_dirs
  bundle_dir="$OPENCTI_LOG_DIR/support-bundle-$(date +%Y%m%d_%H%M%S)"
  mkdir -p "$bundle_dir"
  cp -a "$OPENCTI_REPORT_TXT" "$OPENCTI_REPORT_JSON" "$OPENCTI_CAPABILITIES" "$OPENCTI_LAST_PREFLIGHT" "$OPENCTI_LAST_DRY_RUN" "$OPENCTI_LAST_LIVE_WRITE" "$OPENCTI_ACTIVATION_STATUS" "$bundle_dir/" 2>/dev/null || true
  opencti_sanitized_env_to "$OPENCTI_ENV_FILE" "$bundle_dir/opencti-iris-bridge.env.sanitized"
  opencti_sanitized_env_to "$OPENCTI_ENV_PENDING" "$bundle_dir/opencti-iris-bridge.env.pending.sanitized"
  opencti_sanitized_env_to "$OPENCTI_CONTROL_ENV" "$bundle_dir/control-api.env.sanitized"
  opencti_sanitized_env_to "$OPENCTI_CONTROL_PENDING" "$bundle_dir/control-api.env.pending.sanitized"
  cp -a /etc/systemd/system/opencti-iris-bridge.service /etc/systemd/system/opencti-iris-bridge.timer /etc/systemd/system/opencti-iris-bridge-api.service "$bundle_dir/" 2>/dev/null || true
  tail -n 500 "$OPENCTI_BRIDGE_LOG" >"$bundle_dir/bridge.log.tail" 2>/dev/null || true
  { python3 --version 2>&1 || true; curl --version 2>&1 | head -5 || true; } >"$bundle_dir/package-checks.txt"
  if have sha256sum; then
    find "$OPENCTI_BRIDGE_DIR" -type f -maxdepth 3 -print0 2>/dev/null | xargs -0 sha256sum >"$bundle_dir/file-checksums.txt" 2>/dev/null || true
  fi
  if have systemctl; then
    systemctl --no-pager status opencti-iris-bridge.service opencti-iris-bridge.timer opencti-iris-bridge-api.service >"$bundle_dir/systemd-status.txt" 2>&1 || true
  fi
  if [ -f "$OPENCTI_ENV_FILE" ] && [ -f "$OPENCTI_CONTROL_ENV" ]; then
    opencti_python_api_check both >"$bundle_dir/connectivity.json" 2>"$bundle_dir/connectivity.err" || true
  else
    printf '{"status":"skipped","reason":"bridge env files are not configured"}\n' >"$bundle_dir/connectivity.json"
  fi
  tarball="${bundle_dir}.tar.gz"
  tar -C "$OPENCTI_LOG_DIR" -czf "$tarball" "$(basename "$bundle_dir")"
  chmod 600 "$tarball"
  info "OpenCTI bridge support bundle written: $tarball"
}

opencti_menu() {
  while :; do
    printf '\n============================================================\n'
    printf 'OpenCTI integration tools\n'
    printf '============================================================\n'
    printf 'This option requires an existing deployed and configured OpenCTI instance.\n'
    printf 'OpenCTI will not be installed, repaired, or modified by this script.\n\n'
    printf '  1) Configure and deploy OpenCTI <-> IRIS bridge, timer, and IRIS buttons\n'
    printf '  2) Run OpenCTI bridge preflight checks\n'
    printf '  3) Install or update bridge service\n'
    printf '  4) Test IRIS API connection\n'
    printf '  5) Test OpenCTI API connection\n'
    printf '  6) Run bridge once in dry-run mode\n'
    printf '  7) Enable bridge timer\n'
    printf '  8) Disable bridge timer\n'
    printf '  9) Show bridge status and logs\n'
    printf ' 10) Install IRIS manual enrichment module/buttons\n'
    printf ' 11) Roll back IRIS manual enrichment module/buttons\n'
    printf ' 12) Uninstall bridge service only\n'
    printf ' 13) Collect OpenCTI bridge support bundle\n'
    printf ' 14) Show OpenCTI schema capabilities\n'
    printf ' 15) Clear/rotate bridge logs\n'
    printf ' 16) Run bridge once in live-write mode with confirmation\n'
    printf ' 17) Back\n'
    printf 'Choose an option: '
    IFS= read -r choice || die "Input stream closed."
    case "$choice" in
      1) if ! opencti_configure_full_setup; then warn "OpenCTI full bridge setup did not complete."; fi; pause_menu ;;
      2) if ! opencti_bridge_preflight; then warn "OpenCTI bridge preflight failed."; fi; pause_menu ;;
      3) if ! opencti_install_bridge_service; then warn "OpenCTI bridge service install/update failed."; fi; pause_menu ;;
      4) if ! opencti_test_iris_api; then warn "IRIS API connection test failed."; fi; pause_menu ;;
      5) if ! opencti_test_opencti_api; then warn "OpenCTI API connection test failed."; fi; pause_menu ;;
      6) if ! opencti_run_dry_once; then warn "OpenCTI bridge dry-run failed."; fi; pause_menu ;;
      7) if ! opencti_enable_timer; then warn "OpenCTI bridge timer was not enabled."; fi; pause_menu ;;
      8) if ! opencti_disable_timer; then warn "OpenCTI bridge timer disable failed."; fi; pause_menu ;;
      9) opencti_status; pause_menu ;;
      10) if ! opencti_install_iris_module; then warn "IRIS OpenCTI module/button install failed."; fi; pause_menu ;;
      11) if ! opencti_rollback_iris_module; then warn "IRIS OpenCTI module/button rollback failed."; fi; pause_menu ;;
      12) if ! opencti_uninstall_service_only; then warn "OpenCTI bridge uninstall failed."; fi; pause_menu ;;
      13) if ! opencti_support_bundle; then warn "OpenCTI bridge support bundle collection failed."; fi; pause_menu ;;
      14) if ! opencti_show_capabilities; then warn "OpenCTI capabilities display failed."; fi; pause_menu ;;
      15) if ! opencti_rotate_logs; then warn "OpenCTI log rotation failed."; fi; pause_menu ;;
      16) if ! opencti_run_live_once; then warn "OpenCTI bridge live-write validation failed or was cancelled."; fi; pause_menu ;;
      17|0|q|Q) return 0 ;;
      *) warn "Choose one of the listed options." ;;
    esac
  done
}

wazuh_menu() {
  while :; do
    printf '\n============================================================\n'
    printf 'Wazuh -> IRIS integration menu\n'
    printf '============================================================\n'
    printf '  1) Detect Wazuh topology (read-only)\n'
    printf '  2) Generate remote Wazuh manager bundle\n'
    printf '  3) Install into selected local Wazuh manager container(s)\n'
    printf '  4) Roll back local Wazuh manager integration\n'
    printf '  5) Apply IRIS Wazuh Markdown alert UI patch\n'
    printf '  6) Roll back IRIS Wazuh Markdown alert UI patch\n'
    printf '  7) Send manual Wazuh test alert to IRIS\n'
    printf '  8) Run Wazuh manager-selection self-test\n'
    printf '  0) Back\n'
    printf 'Choose an option: '
    IFS= read -r choice || die "Input stream closed."
    case "$choice" in
      1) show_wazuh_topology; pause_menu ;;
      2) generate_wazuh_remote_bundle; pause_menu ;;
      3) install_wazuh_local_container || true; pause_menu ;;
      4) rollback_wazuh_local_container || true; pause_menu ;;
      5) apply_wazuh_markdown_patch; pause_menu ;;
      6) rollback_wazuh_markdown_patch; pause_menu ;;
      7) send_wazuh_test_alert || true; pause_menu ;;
      8) wazuh_selection_self_test || true; pause_menu ;;
      0|q|Q) return 0 ;;
      *) warn "Choose one of the listed options." ;;
    esac
  done
}

