#!/usr/bin/env bash
# Part of ASRFacet-Rb - authorized testing only

set -u
set -o pipefail

APP_NAME="asrfacet-rb"
REPO_URL="https://github.com/voltsparx/ASRFacet-Rb.git"
BRANCH="main"
TEMP_BASE="${TMPDIR:-/tmp}/${APP_NAME}-installer"
MODE=""
NO_PROMPT="no"
KEEP_TEMP="no"
VERBOSE="no"
WORK_DIR=""

log() { printf '[%s] %s\n' "$1" "$2"; }
info() { log "INFO" "$1"; }
ok() { log " OK " "$1"; }
warn() { log "WARN" "$1"; }
fail() { log "FAIL" "$1"; exit 1; }

run_cmd() {
  if [ "$VERBOSE" = "yes" ]; then
    info "Running: $*"
  fi
  "$@"
  local code=$?
  if [ "$code" -ne 0 ]; then
    fail "Command failed ($code): $*"
  fi
}

usage() {
  cat <<'EOF'
ASRFacet-Rb Website Installer (macOS)

Usage:
  bash asrfacet-rb-installer-macos.sh [install|test|update|uninstall] [options]

Options:
  --yes, --no-prompt   Run non-interactively where possible
  --keep-temp          Keep downloaded temp files after completion
  --verbose            Print command-level progress
  --help               Show this help
EOF
}

required_paths_for_mode() {
  local paths=("install/macos.sh")
  case "$MODE" in
    install|update|test)
      paths+=(
        "bin"
        "config"
        "lib"
        "man"
        "wordlists"
        "Gemfile"
        "Gemfile.lock"
        "asrfacet-rb.gemspec"
        "README.md"
        "LICENSE"
      )
      [ "$MODE" = "test" ] && paths+=("spec")
      ;;
  esac

  printf '%s\n' "${paths[@]}"
}

select_mode() {
  if [ "$NO_PROMPT" = "yes" ]; then
    MODE="install"
    return
  fi

  printf '%s\n' "Select mode:"
  printf '%s\n' "  1) install"
  printf '%s\n' "  2) test"
  printf '%s\n' "  3) update"
  printf '%s\n' "  4) uninstall"
  printf '%s' "Choice [1-4, default 1]: "
  read -r choice
  case "$choice" in
    2) MODE="test" ;;
    3) MODE="update" ;;
    4) MODE="uninstall" ;;
    *) MODE="install" ;;
  esac
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      install|test|update|uninstall) MODE="$1" ;;
      --yes|--no-prompt) NO_PROMPT="yes" ;;
      --keep-temp) KEEP_TEMP="yes" ;;
      --verbose) VERBOSE="yes" ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        fail "Unknown argument: $1"
        ;;
    esac
    shift
  done
}

ensure_requirements() {
  command -v git >/dev/null 2>&1 || fail "git is required but was not found in PATH."
  command -v bash >/dev/null 2>&1 || fail "bash is required but was not found in PATH."
}

cleanup() {
  if [ "$KEEP_TEMP" = "yes" ]; then
    [ -n "$WORK_DIR" ] && info "Keeping temp directory: $WORK_DIR"
    return
  fi

  if [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ]; then
    rm -rf "$WORK_DIR" || warn "Unable to remove temp directory: $WORK_DIR"
  fi
}

prepare_workspace() {
  local stamp
  stamp="$(date +%s)"
  WORK_DIR="${TEMP_BASE}-${stamp}-$$"
  run_cmd mkdir -p "$WORK_DIR"
}

download_repo() {
  local repo_dir="$WORK_DIR/source"
  info "Downloading only required ASRFacet-Rb files from GitHub."

  if git clone --depth 1 --filter=blob:none --sparse --branch "$BRANCH" "$REPO_URL" "$repo_dir"; then
    local sparse_paths=()
    while IFS= read -r path; do
      sparse_paths+=("$path")
    done < <(required_paths_for_mode)
    (
      cd "$repo_dir" || exit 1
      git sparse-checkout init --no-cone &&
        git sparse-checkout set --no-cone "${sparse_paths[@]}"
    ) || fail "Unable to apply sparse checkout for required files."
  else
    warn "Sparse checkout is unavailable in this git environment. Falling back to full shallow clone."
    run_cmd rm -rf "$repo_dir"
    run_cmd git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$repo_dir"
  fi

  printf '%s\n' "$repo_dir"
}

run_installer() {
  local repo_dir="$1"
  local install_script="$repo_dir/install/macos.sh"

  [ -f "$install_script" ] || fail "Expected installer script not found: $install_script"
  run_cmd chmod +x "$install_script"

  info "Starting lifecycle mode: $MODE"
  run_cmd bash "$install_script" "$MODE"
}

main() {
  parse_args "$@"
  [ -n "$MODE" ] || select_mode
  ensure_requirements
  prepare_workspace
  trap cleanup EXIT

  local repo_dir
  repo_dir="$(download_repo)" || fail "Unable to download repository."
  run_installer "$repo_dir"
  ok "ASRFacet-Rb website installer completed ($MODE)."
}

main "$@"
