# Part of ASRFacet-Rb - authorized testing only

require_relative "support/smoke_helper"

include ASRFacet::TestSupport

announce("CLI smoke verification started.")

help_output = run_command(*ruby_command("bin/asrfacet-rb", "help"))
assert(help_output.include?("ASRFacet-Rb Help"), "CLI help output was not returned.")

version_output = run_command(*ruby_command("bin/asrfacet-rb", "version")).strip
assert(version_output == "1.0.0", "Expected version 1.0.0, got #{version_output.inspect}.")

alias_version = run_command(*ruby_command("bin/asrfrb", "version")).strip
assert(alias_version == "1.0.0", "Expected alias version 1.0.0, got #{alias_version.inspect}.")

about_output = run_command(*ruby_command("bin/asrfacet-rb", "--about"))
assert(about_output.include?("ASRFacet-Rb"), "About output did not contain the framework name.")

explain_output = run_command(*ruby_command("bin/asrfacet-rb", "--explain", "scope"))
assert(explain_output.include?("Explain: scope"), "Explain output did not contain the scope topic.")

announce("CLI smoke verification passed.")
