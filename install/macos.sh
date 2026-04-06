#!/usr/bin/env bash
# Part of ASRFacet-Rb - authorized testing only

set -u
set -o pipefail

APP_NAME="asrfacet-rb"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INSTALL_ROOT="$HOME/Library/Application Support/$APP_NAME"
USER_BIN_DIR="$HOME/.local/bin"
SYSTEM_LAUNCHER="$USER_BIN_DIR/$APP_NAME"
TEST_BASE="$SCRIPT_DIR/test-root"
TEST_ROOT="$TEST_BASE/$APP_NAME"
TEST_BIN_DIR="$TEST_BASE/bin"
TEST_LAUNCHER="$TEST_BIN_DIR/$APP_NAME"
MANIFEST_NAME=".asrfacet-install.json"
MODE="${1:-install}"
PROFILE_FILES=("$HOME/.zshrc" "$HOME/.bash_profile" "$HOME/.bashrc" "$HOME/.profile")
RUNTIME_PAYLOAD=(
  "bin"
  "config"
  "lib"
  "man"
  "Gemfile"
  "Gemfile.lock"
  "README.md"
  "LICENSE"
  "asrfacet-rb.gemspec"
)

log() {
  printf '[%s] %s\n' "$1" "$2"
}

info() {
  log "INFO" "$1"
}

ok() {
  log " OK " "$1"
}

warn() {
  log "WARN" "$1"
}

fail() {
  log "FAIL" "$1"
  exit 1
}

run_cmd() {
  "$@"
  local code=$?
  if [ "$code" -ne 0 ]; then
    fail "Command failed ($code): $*"
  fi
}

ensure_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    fail "$1 is required but was not found in PATH."
  fi
}

ensure_bundler() {
  ensure_command ruby
  if command -v bundle >/dev/null 2>&1; then
    return
  fi

  if ! command -v gem >/dev/null 2>&1; then
    fail "Bundler is missing and gem is unavailable to install it."
  fi

  info "Bundler was not found. Attempting a user-level install."
  run_cmd gem install bundler --no-document
}

manifest_path() {
  printf '%s/%s\n' "$1" "$MANIFEST_NAME"
}

is_managed_install() {
  [ -f "$(manifest_path "$1")" ]
}

ensure_managed_or_missing() {
  if [ -e "$1" ] && ! is_managed_install "$1"; then
    fail "Refusing to replace '$1' because it is not marked as an ASRFacet-Rb managed install."
  fi
}

copy_payload() {
  local destination_root="$1"
  local include_specs="$2"

  run_cmd mkdir -p "$destination_root"

  local entry
  for entry in "${RUNTIME_PAYLOAD[@]}"; do
    if [ -e "$REPO_ROOT/$entry" ]; then
      run_cmd cp -R "$REPO_ROOT/$entry" "$destination_root/"
    fi
  done

  if [ -d "$REPO_ROOT/wordlists" ]; then
    run_cmd cp -R "$REPO_ROOT/wordlists" "$destination_root/"
  fi

  if [ "$include_specs" = "yes" ] && [ -d "$REPO_ROOT/spec" ]; then
    run_cmd cp -R "$REPO_ROOT/spec" "$destination_root/"
  fi

  run_cmd mkdir -p "$destination_root/output" "$destination_root/tmp" "$destination_root/vendor"
}

bundle_setup() {
  local app_root="$1"

  ensure_bundler
  info "Installing runtime dependencies into $app_root/vendor/bundle"
  (
    cd "$app_root" || exit 1
    bundle config set --local path vendor/bundle &&
      bundle config set --local without development &&
      bundle install
  )
  local code=$?
  if [ "$code" -ne 0 ]; then
    fail "bundle install failed for $app_root."
  fi
}

write_manifest() {
  local app_root="$1"
  local install_mode="$2"
  local ruby_version
  ruby_version="$(ruby -e 'print RUBY_VERSION' 2>/dev/null || printf 'unknown')"

  cat >"$(manifest_path "$app_root")" <<EOF
{
  "app_name": "$APP_NAME",
  "installed_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "install_mode": "$install_mode",
  "source_repo": "$REPO_ROOT",
  "ruby_version": "$ruby_version"
}
EOF
}

write_launcher() {
  local app_root="$1"
  local launcher_path="$2"

  run_cmd mkdir -p "$(dirname "$launcher_path")"
  cat >"$launcher_path" <<EOF
#!/usr/bin/env sh
# Part of ASRFacet-Rb - authorized testing only
APP_ROOT="$app_root"
if [ ! -f "\$APP_ROOT/Gemfile" ]; then
  echo "[FAIL] ASRFacet-Rb is not installed correctly at \$APP_ROOT." >&2
  exit 1
fi
if ! command -v ruby >/dev/null 2>&1; then
  echo "[FAIL] Ruby 3.2 or newer is required." >&2
  exit 1
fi
if ! command -v bundle >/dev/null 2>&1; then
  echo "[FAIL] Bundler is required. Re-run the installer to repair this installation." >&2
  exit 1
fi
export BUNDLE_GEMFILE="\$APP_ROOT/Gemfile"
export BUNDLE_APP_CONFIG="\$APP_ROOT/.bundle"
export BUNDLE_WITHOUT="development"
exec bundle exec ruby "\$APP_ROOT/bin/asrfacet-rb" "\$@"
EOF
  run_cmd chmod +x "$launcher_path"
}

ensure_path_block() {
  run_cmd mkdir -p "$USER_BIN_DIR"

  if printf '%s' ":$PATH:" | grep -Fq ":$USER_BIN_DIR:"; then
    info "$USER_BIN_DIR is already present in the current PATH."
  fi

  local marker_start="# >>> asrfacet-rb >>>"
  local marker_end="# <<< asrfacet-rb <<<"
  local export_line='export PATH="$HOME/.local/bin:$PATH"'
  local profile
  local written="no"

  for profile in "${PROFILE_FILES[@]}"; do
    if [ ! -f "$profile" ]; then
      : >"$profile" || continue
    fi

    if grep -Fq "$marker_start" "$profile" 2>/dev/null; then
      continue
    fi

    {
      printf '\n%s\n' "$marker_start"
      printf '%s\n' "$export_line"
      printf '%s\n' "$marker_end"
    } >>"$profile" || continue
    written="yes"
  done

  if [ "$written" = "yes" ]; then
    ok "Added $USER_BIN_DIR to common shell profiles."
  else
    info "Shell profile entries were already present."
  fi
}

remove_path_block() {
  local marker_start="# >>> asrfacet-rb >>>"
  local marker_end="# <<< asrfacet-rb <<<"
  local profile

  for profile in "${PROFILE_FILES[@]}"; do
    [ -f "$profile" ] || continue
    awk -v start="$marker_start" -v end="$marker_end" '
      $0 == start { skip = 1; next }
      $0 == end { skip = 0; next }
      !skip { print }
    ' "$profile" >"$profile.tmp" && mv "$profile.tmp" "$profile"
  done
}

smoke_test() {
  local launcher_path="$1"
  info "Running a launcher smoke test."
  "$launcher_path" help >/dev/null 2>&1 || fail "Smoke test failed for $launcher_path."
  ok "Launcher smoke test passed."
}

deploy_install() {
  local target_root="$1"
  local launcher_path="$2"
  local install_mode="$3"
  local add_to_path="$4"
  local include_specs="$5"
  local parent_dir
  local stage_root
  local stage_app
  local backup_root

  ensure_managed_or_missing "$target_root"

  parent_dir="$(dirname "$target_root")"
  stage_root="$parent_dir/.${APP_NAME}-staging-$$"
  stage_app="$stage_root/$APP_NAME"
  backup_root="$parent_dir/.${APP_NAME}-backup-$$"

  rm -rf "$stage_root" "$backup_root"
  run_cmd mkdir -p "$stage_root"

  info "Preparing staged files for $install_mode."
  copy_payload "$stage_app" "$include_specs"
  bundle_setup "$stage_app"
  write_manifest "$stage_app" "$install_mode"

  if [ -d "$target_root" ]; then
    run_cmd mv "$target_root" "$backup_root"
  fi

  if ! mv "$stage_app" "$target_root"; then
    [ -d "$backup_root" ] && mv "$backup_root" "$target_root"
    fail "Unable to move the staged install into place."
  fi

  if ! write_launcher "$target_root" "$launcher_path"; then
    rm -rf "$target_root"
    [ -d "$backup_root" ] && mv "$backup_root" "$target_root"
    fail "Unable to create the launcher at $launcher_path."
  fi

  if [ "$add_to_path" = "yes" ]; then
    ensure_path_block
  fi

  if ! smoke_test "$launcher_path"; then
    rm -rf "$target_root"
    [ -d "$backup_root" ] && mv "$backup_root" "$target_root"
    fail "Smoke test failed after deployment."
  fi

  rm -rf "$stage_root" "$backup_root"
  ok "ASRFacet-Rb $install_mode completed successfully."
}

uninstall_system() {
  if [ -d "$INSTALL_ROOT" ]; then
    if ! is_managed_install "$INSTALL_ROOT"; then
      fail "Refusing to remove $INSTALL_ROOT because it is not marked as managed by this installer."
    fi
    run_cmd rm -rf "$INSTALL_ROOT"
    ok "Removed $INSTALL_ROOT"
  else
    warn "No managed installation was found at $INSTALL_ROOT."
  fi

  if [ -f "$SYSTEM_LAUNCHER" ]; then
    run_cmd rm -f "$SYSTEM_LAUNCHER"
    ok "Removed launcher $SYSTEM_LAUNCHER"
  fi

  remove_path_block
  ok "Shell profile updates were removed."
}

case "$MODE" in
  install)
    deploy_install "$INSTALL_ROOT" "$SYSTEM_LAUNCHER" "install" "yes" "no"
    ;;
  test)
    deploy_install "$TEST_ROOT" "$TEST_LAUNCHER" "test" "no" "yes"
    ok "Repo-local test install is ready at $TEST_ROOT"
    info "Launcher: $TEST_LAUNCHER"
    ;;
  update)
    if ! is_managed_install "$INSTALL_ROOT"; then
      fail "No managed installation was found to update. Run install first."
    fi
    deploy_install "$INSTALL_ROOT" "$SYSTEM_LAUNCHER" "update" "yes" "no"
    ;;
  uninstall)
    uninstall_system
    ;;
  *)
    fail "Unsupported mode '$MODE'. Use install, test, uninstall, or update."
    ;;
esac
