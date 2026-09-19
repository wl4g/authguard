#!/usr/bin/env bash
# Initialise the single Kubernetes Secret consumed by AuthGuard and its bundled
# PostgreSQL and Redis dependencies.

set -Eeuo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/common.sh"

usage() {
  cat <<'EOF'
Usage: k8s-secrets-setup.sh [OPTIONS]

Create or update the Kubernetes Secret that supplies every AuthGuard runtime
credential and the bundled PostgreSQL/Redis passwords.

EOF
  print_common_options
}

while (($#)); do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    *)
      if parse_common_option "$@"; then
        shift "$COMMON_ARGC"
      else
        die "unknown option: $1 (use --help)"
      fi
      ;;
  esac
done

validate_secret_file
[[ "$SKIP_KUBERNETES_MIRROR" == false ]] \
  || die "--skip-kubernetes-mirror is not valid for the Kubernetes Secret bootstrap"
sync_kubernetes_secret
