# Part of ASRFacet-Rb - authorized testing only

require "fileutils"
require_relative "support/smoke_helper"

include ASRFacet::TestSupport

announce("Installer smoke verification started.")

install_root = File.join(ROOT, "install", "test-root")
FileUtils.rm_rf(install_root)

if windows?
  run_command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", File.join("install", "windows.ps1"), "test", unbundled: true)
  primary_launcher = File.join("install", "test-root", "bin", "asrfacet-rb.cmd").tr("/", "\\")
  alias_launcher = File.join("install", "test-root", "bin", "asrfrb.cmd").tr("/", "\\")
  primary_version = run_command("cmd", "/c", primary_launcher, "version", unbundled: true).strip
  alias_version = run_command("cmd", "/c", alias_launcher, "version", unbundled: true).strip
elsif macos?
  run_command("bash", File.join("install", "macos.sh"), "test", unbundled: true)
  primary_launcher = File.join("install", "test-root", "bin", "asrfacet-rb")
  alias_launcher = File.join("install", "test-root", "bin", "asrfrb")
  primary_version = run_command(primary_launcher, "version", unbundled: true).strip
  alias_version = run_command(alias_launcher, "version", unbundled: true).strip
else
  run_command("bash", File.join("install", "linux.sh"), "test", unbundled: true)
  primary_launcher = File.join("install", "test-root", "bin", "asrfacet-rb")
  alias_launcher = File.join("install", "test-root", "bin", "asrfrb")
  primary_version = run_command(primary_launcher, "version", unbundled: true).strip
  alias_version = run_command(alias_launcher, "version", unbundled: true).strip
end

assert(primary_version == "1.0.0", "Installed primary launcher reported #{primary_version.inspect}.")
assert(alias_version == "1.0.0", "Installed alias launcher reported #{alias_version.inspect}.")

announce("Installer smoke verification passed.")
