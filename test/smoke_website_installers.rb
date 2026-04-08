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

require_relative "support/smoke_helper"

include ASRFacet::TestSupport

def command_available?(name)
  lookup = windows? ? ["where", name] : ["which", name]
  _stdout, _stderr, status = Open3.capture3(*lookup)
  status.success?
rescue StandardError
  false
end

announce("Website installer smoke verification started.")

installers_dir = File.join(ROOT, "docs", "website", "web_assets", "installers")
linux_rel = File.join("docs", "website", "web_assets", "installers", "asrfacet-rb-installer-linux.sh")
macos_rel = File.join("docs", "website", "web_assets", "installers", "asrfacet-rb-installer-macos.sh")
windows_ps_rel = File.join("docs", "website", "web_assets", "installers", "asrfacet-rb-installer-windows.ps1")
windows_cmd_rel = File.join("docs", "website", "web_assets", "installers", "asrfacet-rb-installer-windows.cmd")
readme_rel = File.join("docs", "website", "web_assets", "installers", "README.md")

expected_files = [linux_rel, macos_rel, windows_ps_rel, windows_cmd_rel, readme_rel]
expected_files.each do |relative_path|
  full_path = File.join(ROOT, relative_path)
  assert(File.file?(full_path), "Missing website installer asset: #{relative_path}")
end

linux_text = File.read(File.join(ROOT, linux_rel))
macos_text = File.read(File.join(ROOT, macos_rel))
windows_ps_text = File.read(File.join(ROOT, windows_ps_rel))
windows_cmd_text = File.read(File.join(ROOT, windows_cmd_rel))
readme_text = File.read(File.join(ROOT, readme_rel))

%w[install test update uninstall].each do |mode|
  assert(linux_text.include?(mode), "Linux website installer is missing mode '#{mode}'.")
  assert(macos_text.include?(mode), "macOS website installer is missing mode '#{mode}'.")
  assert(windows_ps_text.include?(mode), "Windows website installer is missing mode '#{mode}'.")
end

assert(linux_text.include?("docs/images"), "Linux website installer must include docs/images sparse path.")
assert(macos_text.include?("docs/images"), "macOS website installer must include docs/images sparse path.")
assert(windows_ps_text.include?("docs/images"), "Windows website installer must include docs/images sparse path.")
assert(windows_cmd_text.include?("asrfacet-rb-installer-windows.ps1"), "Windows CMD wrapper must call the PowerShell installer.")
assert(readme_text.include?("docs/images"), "Installer README must document docs/images payload behavior.")

if command_available?("bash")
  run_command("bash", "-n", linux_rel, unbundled: true)
  run_command("bash", "-n", macos_rel, unbundled: true)
else
  announce("Skipping shell syntax checks because bash is not available on this system.")
end

windows_ps_abs = File.join(ROOT, windows_ps_rel).gsub("\\", "/")
ps_parse_command = "[void][scriptblock]::Create((Get-Content -Raw '#{windows_ps_abs.gsub("'", "''")}')); 'parse-ok'"

if windows?
  parse_output = run_command("powershell", "-NoProfile", "-Command", ps_parse_command, unbundled: true)
  assert(parse_output.include?("parse-ok"), "PowerShell parser check did not return parse-ok.")
elsif command_available?("pwsh")
  parse_output = run_command("pwsh", "-NoProfile", "-Command", ps_parse_command, unbundled: true)
  assert(parse_output.include?("parse-ok"), "pwsh parser check did not return parse-ok.")
else
  announce("Skipping PowerShell syntax check because powershell/pwsh is not available on this system.")
end

announce("Website installer smoke verification passed.")
