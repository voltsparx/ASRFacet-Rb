#!/usr/bin/env bash
# For use only on systems you own or have explicit
# written authorization to test.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"

ACTION=""
CLI_COMMAND=""
DETACH=0
REBUILD=0
PUBLIC=1
WITH_LAB=1
WEB_PORT="4567"
LAB_PORT="9292"

find_compose() {
  if docker compose version >/dev/null 2>&1; then
    echo "docker compose"
    return
  fi
  if command -v docker-compose >/dev/null 2>&1; then
    echo "docker-compose"
    return
  fi
  echo ""
}

COMPOSE_BIN=""

usage() {
  cat <<'EOF'
Usage:
  ./docker/run-docker.sh [--action ACTION] [options]

Actions:
  up, down, restart, logs, ps, shell, cli, build, help

Options:
  --action ACTION       Action to perform
  --command TEXT        CLI command for --action cli
  --detach              Run compose up in detached mode
  --rebuild             Force a rebuild before starting
  --public              Bind deploy to 0.0.0.0
  --no-public           Keep deploy bound to localhost
  --with-lab            Start the lab service in deploy mode
  --no-with-lab         Disable the lab service in deploy mode
  --web-port PORT       Host web port mapping
  --lab-port PORT       Host lab port mapping
  --help                Show this help

Examples:
  ./docker/run-docker.sh --action up --rebuild --detach
  ./docker/run-docker.sh --action cli --command "scan example.com --passive-only"
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --action|-a)
      ACTION="${2:-}"
      shift 2
      ;;
    --command|-c)
      CLI_COMMAND="${2:-}"
      shift 2
      ;;
    --detach|-d)
      DETACH=1
      shift
      ;;
    --rebuild)
      REBUILD=1
      shift
      ;;
    --public)
      PUBLIC=1
      shift
      ;;
    --no-public)
      PUBLIC=0
      shift
      ;;
    --with-lab)
      WITH_LAB=1
      shift
      ;;
    --no-with-lab)
      WITH_LAB=0
      shift
      ;;
    --web-port)
      WEB_PORT="${2:-4567}"
      shift 2
      ;;
    --lab-port)
      LAB_PORT="${2:-9292}"
      shift 2
      ;;
    --help|-h)
      ACTION="help"
      shift
      ;;
    *)
      echo "[ERROR] Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "${ACTION}" ]]; then
  echo "Select docker action:"
  echo "  1) up"
  echo "  2) down"
  echo "  3) restart"
  echo "  4) logs"
  echo "  5) ps"
  echo "  6) shell"
  echo "  7) cli"
  echo "  8) build"
  printf "Choice [1-8]: "
  read -r choice
  case "${choice}" in
    1) ACTION="up" ;;
    2) ACTION="down" ;;
    3) ACTION="restart" ;;
    4) ACTION="logs" ;;
    5) ACTION="ps" ;;
    6) ACTION="shell" ;;
    7) ACTION="cli" ;;
    8) ACTION="build" ;;
    *) echo "[ERROR] Invalid choice." >&2; exit 1 ;;
  esac

  if [[ "${ACTION}" == "up" || "${ACTION}" == "restart" ]]; then
    printf "Expose deploy publicly on 0.0.0.0? [Y/n]: "
    read -r reply
    [[ "${reply:-Y}" =~ ^[Nn]$ ]] && PUBLIC=0 || PUBLIC=1
    printf "Start the local lab too? [Y/n]: "
    read -r reply
    [[ "${reply:-Y}" =~ ^[Nn]$ ]] && WITH_LAB=0 || WITH_LAB=1
    printf "Web port [4567]: "
    read -r reply
    WEB_PORT="${reply:-4567}"
    printf "Lab port [9292]: "
    read -r reply
    LAB_PORT="${reply:-9292}"
    printf "Run detached? [Y/n]: "
    read -r reply
    [[ "${reply:-Y}" =~ ^[Nn]$ ]] && DETACH=0 || DETACH=1
    printf "Force rebuild? [y/N]: "
    read -r reply
    [[ "${reply:-N}" =~ ^[Yy]$ ]] && REBUILD=1 || REBUILD=0
  fi

  if [[ "${ACTION}" == "cli" ]]; then
    printf "ASRFacet-Rb CLI command [help]: "
    read -r reply
    CLI_COMMAND="${reply:-help}"
  fi
fi

DEPLOY_FLAGS=""
if [[ ${PUBLIC} -eq 1 ]]; then
  DEPLOY_FLAGS="--public"
fi
if [[ ${WITH_LAB} -eq 0 ]]; then
  DEPLOY_FLAGS="${DEPLOY_FLAGS} --no-with-lab"
fi
DEPLOY_FLAGS="$(echo "${DEPLOY_FLAGS}" | xargs)"

export ASRFACET_RB_DEPLOY_FLAGS="${DEPLOY_FLAGS}"
export ASRFACET_RB_WEB_PORT="${WEB_PORT}"
export ASRFACET_RB_LAB_PORT="${LAB_PORT}"
export COMPOSE_PROJECT_NAME="asrfacet_rb"

run_compose() {
  if [[ -z "${COMPOSE_BIN}" ]]; then
    COMPOSE_BIN="$(find_compose)"
  fi
  if [[ -z "${COMPOSE_BIN}" ]]; then
    echo "[ERROR] Docker Compose was not found. Install Docker Desktop or docker-compose first." >&2
    exit 1
  fi
  (cd "${REPO_ROOT}" && ${COMPOSE_BIN} -f "${COMPOSE_FILE}" "$@")
}

case "${ACTION}" in
  up)
    args=(up)
    [[ ${REBUILD} -eq 1 ]] && args+=(--build)
    [[ ${DETACH} -eq 1 ]] && args+=(-d)
    run_compose "${args[@]}"
    ;;
  down)
    run_compose down
    ;;
  restart)
    run_compose down
    args=(up)
    [[ ${REBUILD} -eq 1 ]] && args+=(--build)
    [[ ${DETACH} -eq 1 ]] && args+=(-d)
    run_compose "${args[@]}"
    ;;
  logs)
    run_compose logs -f
    ;;
  ps)
    run_compose ps
    ;;
  shell)
    run_compose run --rm asrfacet_rb bash
    ;;
  cli)
    run_compose run --rm asrfacet_rb bash -lc "bundle exec ruby bin/asrfacet-rb ${CLI_COMMAND:-help}"
    ;;
  build)
    run_compose build
    ;;
  help)
    usage
    ;;
  *)
    echo "[ERROR] Unsupported action: ${ACTION}" >&2
    usage
    exit 1
    ;;
esac
