# frozen_string_literal: true
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

require "json"
require_relative "support/smoke_helper"

include ASRFacet::TestSupport

announce("Version alignment verification started.")

expected = expected_version

version_file = File.read(File.join(ROOT, "VERSION")).strip
assert(version_file == expected, "VERSION file reported #{version_file.inspect}, expected #{expected.inspect}.")

cli_version = run_command(*ruby_command("bin/asrfacet-rb", "--version")).strip
assert(cli_version == expected, "CLI reported #{cli_version.inspect}, expected #{expected.inspect}.")

package_json_path = File.join(ROOT, "lib", "asrfacet_rb", "output", "js", "package.json")
package_json = JSON.parse(File.read(package_json_path))
package_version = package_json.fetch("version", "").to_s.strip
assert(package_version == expected, "JS output package reported #{package_version.inspect}, expected #{expected.inspect}.")

changelog = File.read(File.join(ROOT, "CHANGELOG.md"))
assert(changelog.include?("## [#{expected}]"), "CHANGELOG.md does not contain a release section for #{expected}.")

website_pages = %w[
  docs/website/index.html
  docs/website/cli-reference.html
  docs/website/getting-started.html
  docs/website/modes.html
  docs/website/workflow.html
  docs/website/reporting.html
  docs/website/project.html
  docs/website/development.html
]

website_pages.each do |relative_path|
  content = File.read(File.join(ROOT, relative_path))
  assert(content.include?("v#{expected}"), "#{relative_path} is missing the v#{expected} site marker.")
end

announce("Version alignment verification passed.")
