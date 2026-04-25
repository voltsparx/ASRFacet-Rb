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

announce("CLI smoke verification started.")
version = expected_version

help_output = run_command(*ruby_command("bin/asrfacet-rb", "help"))
assert(help_output.include?("ASRFacet-Rb Help"), "CLI help output was not returned.")

version_output = run_command(*ruby_command("bin/asrfacet-rb", "--version")).strip
assert(version_output == version, "Expected version #{version}, got #{version_output.inspect}.")

alias_version = run_command(*ruby_command("bin/asrfrb", "--version")).strip
assert(alias_version == version, "Expected alias version #{version}, got #{alias_version.inspect}.")

about_output = run_command(*ruby_command("bin/asrfacet-rb", "--about"))
assert(about_output.include?("ASRFacet-Rb"), "About output did not contain the framework name.")

explain_output = run_command(*ruby_command("bin/asrfacet-rb", "--explain", "scope"))
assert(explain_output.include?("Explain: scope"), "Explain output did not contain the scope topic.")

announce("CLI smoke verification passed.")
