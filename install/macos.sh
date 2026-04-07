#!/usr/bin/env bash
# SPDX-License-Identifier: Proprietary
#
# ASRFacet-Rb: Attack Surface Reconnaissance Framework
# Copyright (c) 2026 voltsparx
#
# Author: voltsparx
# Repository: https://github.com/voltsparx/ASRFacet-Rb
# Contact: voltsparx@gmail.com
# License: See LICENSE file in the project root
#
# This file is part of ASRFacet-Rb and is subject to the terms
# and conditions defined in the LICENSE file.

set -u
set -o pipefail

APP_NAME="asrfacet-rb"
ALIAS_NAME="asrfrb"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INSTALL_ROOT="$HOME/Library/Application Support/$APP_NAME"
USER_BIN_DIR="$HOME/.local/bin"
SYSTEM_LAUNCHER="$USER_BIN_DIR/$APP_NAME"
ALIAS_LAUNCHER="$USER_BIN_DIR/$ALIAS_NAME"
TEST_BASE="$SCRIPT_DIR/test-root"
TEST_ROOT="$TEST_BASE/$APP_NAME"
TEST_BIN_DIR="$TEST_BASE/bin"
TEST_LAUNCHER="$TEST_BIN_DIR/$APP_NAME"
TEST_ALIAS_LAUNCHER="$TEST_BIN_DIR/$ALIAS_NAME"
USER_CONFIG_ROOT="$HOME/.asrfacet_rb"
USER_CONFIG_PATH="$USER_CONFIG_ROOT/config.yml"
DEFAULT_OUTPUT_ROOT="$USER_CONFIG_ROOT/output"
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

log() { printf '[%s] %s\n' "$1" "$2"; }
info() { log "INFO" "$1"; }
ok() { log " OK " "$1"; }
warn() { log "WARN" "$1"; }
fail() { log "FAIL" "$1"; exit 1; }

run_cmd() {
  "$@"
  local code=$?
  if [ "$code" -ne 0 ]; then
    fail "Command failed ($code): $*"
  fi
}

confirm_action() {
  local prompt="$1"
  local default="${2:-yes}"
  if [ ! -t 0 ]; then
    return 0
  fi

  local suffix="[Y/n]"
  [ "$default" = "no" ] && suffix="[y/N]"
  printf '%s %s ' "$prompt" "$suffix"
  read -r answer
  if [ -z "$answer" ]; then
    [ "$default" = "yes" ]
    return
  fi

  case "$(printf '%s' "$answer" | tr '[:upper:]' '[:lower:]')" in
    y|yes) return 0 ;;
    *) return 1 ;;
  esac
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

  confirm_action "Bundler is required but missing. Install it now for this user?" yes || fail "Bundler installation was declined."
  info "Bundler was not found. Attempting a user-level install."
  run_cmd gem install bundler --no-document
}

manifest_path() { printf '%s/%s\n' "$1" "$MANIFEST_NAME"; }
is_managed_install() { [ -f "$(manifest_path "$1")" ]; }

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
    [ -e "$REPO_ROOT/$entry" ] && run_cmd cp -R "$REPO_ROOT/$entry" "$destination_root/"
  done

  [ -d "$REPO_ROOT/wordlists" ] && run_cmd cp -R "$REPO_ROOT/wordlists" "$destination_root/"
  if [ "$include_specs" = "yes" ] && [ -d "$REPO_ROOT/spec" ]; then
    run_cmd cp -R "$REPO_ROOT/spec" "$destination_root/"
  fi

  run_cmd mkdir -p "$destination_root/output" "$destination_root/tmp" "$destination_root/vendor"
}

bundle_setup() {
  local app_root="$1"

  ensure_bundler
  confirm_action "Install or refresh Ruby dependencies into the ASRFacet-Rb application folder?" yes || fail "Dependency installation was declined."
  info "Installing runtime dependencies into $app_root/vendor/bundle"
  (
    cd "$app_root" || exit 1
    bundle config set --local path vendor/bundle &&
      bundle config set --local without development &&
      bundle install
  )
  local code=$?
  [ "$code" -eq 0 ] || fail "bundle install failed for $app_root."
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

write_user_config() {
  run_cmd mkdir -p "$USER_CONFIG_ROOT" "$DEFAULT_OUTPUT_ROOT"
  cat >"$USER_CONFIG_PATH" <<EOF
threads:
  default: 50
output:
  directory: $DEFAULT_OUTPUT_ROOT
  format: cli
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

ensure_path_and_man_blocks() {
  run_cmd mkdir -p "$USER_BIN_DIR"
  local marker_start="# >>> asrfacet-rb >>>"
  local marker_end="# <<< asrfacet-rb <<<"
  local profile
  local written="no"

  for profile in "${PROFILE_FILES[@]}"; do
    [ -f "$profile" ] || : >"$profile" || continue
    if grep -Fq "$marker_start" "$profile" 2>/dev/null; then
      continue
    fi

    {
      printf '\n%s\n' "$marker_start"
      printf '%s\n' 'export PATH="$HOME/.local/bin:$PATH"'
      printf '%s\n' "export MANPATH=\"$INSTALL_ROOT/man:\${MANPATH:-}\""
      printf '%s\n' "$marker_end"
    } >>"$profile" || continue
    written="yes"
  done

  if [ "$written" = "yes" ]; then
    ok "Added PATH and MANPATH updates to common shell profiles."
  else
    info "Shell profile updates were already present."
  fi
}

remove_profile_block() {
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

show_install_summary() {
  local install_mode="$1"
  local app_root="$2"
  local launcher_paths="$3"
  ok "ASRFacet-Rb $install_mode completed successfully."
  info "Installed application: $app_root"
  info "System commands: $APP_NAME, $ALIAS_NAME"
  info "Launcher paths: $launcher_paths"
  info "Stored reports root: $DEFAULT_OUTPUT_ROOT"
  info "Man page path: $app_root/man"
  info "Reload your shell or run: export PATH=\"$USER_BIN_DIR:\$PATH\" && export MANPATH=\"$app_root/man:\${MANPATH:-}\""
}

write_launchers() {
  local app_root="$1"
  shift
  local launcher_path

  for launcher_path in "$@"; do
    write_launcher "$app_root" "$launcher_path"
  done
}

deploy_install() {
  local target_root="$1"
  local launcher_path="$2"
  local alias_launcher_path="$3"
  local install_mode="$4"
  local add_to_profile="$5"
  local include_specs="$6"
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

  [ -d "$target_root" ] && run_cmd mv "$target_root" "$backup_root"
  if ! mv "$stage_app" "$target_root"; then
    [ -d "$backup_root" ] && mv "$backup_root" "$target_root"
    fail "Unable to move the staged install into place."
  fi

  if ! write_launchers "$target_root" "$launcher_path" "$alias_launcher_path"; then
    rm -rf "$target_root"
    [ -d "$backup_root" ] && mv "$backup_root" "$target_root"
    fail "Unable to create launchers in $(dirname "$launcher_path")."
  fi

  if [ "$add_to_profile" = "yes" ]; then
    ensure_path_and_man_blocks
    write_user_config
  fi

  smoke_test "$launcher_path"
  smoke_test "$alias_launcher_path"
  rm -rf "$stage_root" "$backup_root"
  show_install_summary "$install_mode" "$target_root" "$launcher_path, $alias_launcher_path"
}

uninstall_system() {
  if [ -d "$INSTALL_ROOT" ]; then
    is_managed_install "$INSTALL_ROOT" || fail "Refusing to remove $INSTALL_ROOT because it is not marked as managed by this installer."
    run_cmd rm -rf "$INSTALL_ROOT"
    ok "Removed $INSTALL_ROOT"
  else
    warn "No managed installation was found at $INSTALL_ROOT."
  fi

  [ -f "$SYSTEM_LAUNCHER" ] && run_cmd rm -f "$SYSTEM_LAUNCHER" && ok "Removed launcher $SYSTEM_LAUNCHER"
  [ -f "$ALIAS_LAUNCHER" ] && run_cmd rm -f "$ALIAS_LAUNCHER" && ok "Removed launcher $ALIAS_LAUNCHER"
  remove_profile_block
  ok "Shell profile updates were removed."
}

case "$MODE" in
  install) deploy_install "$INSTALL_ROOT" "$SYSTEM_LAUNCHER" "$ALIAS_LAUNCHER" "install" "yes" "no" ;;
  test)
    deploy_install "$TEST_ROOT" "$TEST_LAUNCHER" "$TEST_ALIAS_LAUNCHER" "test" "no" "yes"
    info "Repo-local test launchers: $TEST_LAUNCHER, $TEST_ALIAS_LAUNCHER"
    ;;
  update)
    is_managed_install "$INSTALL_ROOT" || fail "No managed installation was found to update. Run install first."
    deploy_install "$INSTALL_ROOT" "$SYSTEM_LAUNCHER" "$ALIAS_LAUNCHER" "update" "yes" "no"
    ;;
  uninstall) uninstall_system ;;
  *) fail "Unsupported mode '$MODE'. Use install, test, uninstall, or update." ;;
esac
