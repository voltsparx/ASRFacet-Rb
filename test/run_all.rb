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

scripts = %w[
  smoke_version.rb
  smoke_cli.rb
  smoke_web.rb
  smoke_lab.rb
  smoke_install.rb
  smoke_website_installers.rb
  smoke_v2.rb
  smoke_reports.rb
]

announce("Standalone verification run started.")
scripts.each do |script|
  run_command(*ruby_command(File.join("test", script)))
end
announce("Standalone verification run passed.")
