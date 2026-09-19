#!/usr/bin/env bash
# Shared, intentionally small CLI foundation for AuthGuard Helm secret bootstrap.
# Shellcheck source=/dev/null

set -Eeuo pipefail

readonly BOOTSTRAP_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SECRET_TEMPLATE="${BOOTSTRAP_DIR}/authguard-secrets.env.example"

AUTHGUARD_RELEASE="${AUTHGUARD_RELEASE:-authguard}"
AUTHGUARD_NAMESPACE="${AUTHGUARD_NAMESPACE:-authguard}"
AUTHGUARD_SECRET_NAME="${AUTHGUARD_SECRET_NAME:-authguard-secrets}"
AUTHGUARD_SECRET_FILE="${AUTHGUARD_SECRET_FILE:-${PWD}/authguard-secrets.env}"
AUTHGUARD_KSA="${AUTHGUARD_KSA:-${AUTHGUARD_RELEASE}-authguard}"
DRY_RUN=false
SKIP_KUBERNETES_MIRROR=false
COMMON_ARGC=0

log() {
  printf '%s\n' "[authguard-bootstrap] $*" >&2
}

die() {
  log "error: $*"
  exit 1
}

need_value() {
  [[ $# -eq 2 && -n "$2" && "$2" != --* ]] || die "$1 requires a value"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command is not installed: $1"
}

print_common_options() {
  cat <<'EOF'
Common options:
  --release NAME          Helm release name (default: authguard).
  --namespace NAME        Kubernetes namespace (default: authguard).
  --service-account NAME  Chart ServiceAccount name (default: <release>-authguard).
  --secret-name NAME      Logical Secret name (default: authguard-secrets).
  --secret-file PATH      Filled KEY=VALUE env-file (default: ./authguard-secrets.env).
  --skip-kubernetes-mirror
                          Do not create the Secret required by bundled Redis/PostgreSQL.
  --dry-run               Print the intended operations without changing state.
  -h, --help              Show this help.
EOF
}

# Parses one common option. Callers shift COMMON_ARGC on success.
parse_common_option() {
  COMMON_ARGC=0
  case "${1:-}" in
    --release)
      need_value --release "${2:-}"
      AUTHGUARD_RELEASE="$2"
      AUTHGUARD_KSA="${AUTHGUARD_RELEASE}-authguard"
      COMMON_ARGC=2
      ;;
    --namespace)
      need_value --namespace "${2:-}"
      AUTHGUARD_NAMESPACE="$2"
      COMMON_ARGC=2
      ;;
    --service-account)
      need_value --service-account "${2:-}"
      AUTHGUARD_KSA="$2"
      COMMON_ARGC=2
      ;;
    --secret-name)
      need_value --secret-name "${2:-}"
      AUTHGUARD_SECRET_NAME="$2"
      COMMON_ARGC=2
      ;;
    --secret-file)
      need_value --secret-file "${2:-}"
      AUTHGUARD_SECRET_FILE="$2"
      COMMON_ARGC=2
      ;;
    --skip-kubernetes-mirror)
      SKIP_KUBERNETES_MIRROR=true
      COMMON_ARGC=1
      ;;
    --dry-run)
      DRY_RUN=true
      COMMON_ARGC=1
      ;;
    *)
      return 1
      ;;
  esac
}

validate_secret_file() {
  if [[ ! -f "$AUTHGUARD_SECRET_FILE" ]]; then
    die "secret file is missing: ${AUTHGUARD_SECRET_FILE}; start with: cp ${SECRET_TEMPLATE} ${AUTHGUARD_SECRET_FILE}"
  fi
  if grep -nE '^[[:space:]]*[^#].*=<[^>]+>' "$AUTHGUARD_SECRET_FILE"; then
    die "replace every active <PLACEHOLDER> in ${AUTHGUARD_SECRET_FILE}"
  fi
}

sync_kubernetes_secret() {
  if [[ "$SKIP_KUBERNETES_MIRROR" == true ]]; then
    log "Kubernetes Secret mirror skipped"
    return
  fi
  if [[ "$DRY_RUN" == true ]]; then
    log "would apply namespace ${AUTHGUARD_NAMESPACE} and Secret ${AUTHGUARD_SECRET_NAME} from ${AUTHGUARD_SECRET_FILE}"
    return
  fi
  require_command kubectl
  kubectl create namespace "$AUTHGUARD_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
  kubectl -n "$AUTHGUARD_NAMESPACE" create secret generic "$AUTHGUARD_SECRET_NAME" \
    --from-env-file="$AUTHGUARD_SECRET_FILE" \
    --dry-run=client -o yaml | kubectl apply -f -
  log "Kubernetes Secret mirror is ready: ${AUTHGUARD_NAMESPACE}/${AUTHGUARD_SECRET_NAME}"
}

write_values_file() {
  local path="$1"
  local contents="$2"
  if [[ "$DRY_RUN" == true ]]; then
    log "would write Helm values override: ${path}"
    return
  fi
  umask 077
  printf '%s\n' "$contents" >"$path"
  log "wrote Helm values override: ${path}"
}
