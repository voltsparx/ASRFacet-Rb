# Part of ASRFacet-Rb - authorized testing only

require_relative "support/smoke_helper"

include ASRFacet::TestSupport

scripts = %w[
  smoke_cli.rb
  smoke_web.rb
  smoke_lab.rb
  smoke_install.rb
]

announce("Standalone verification run started.")
scripts.each do |script|
  run_command(*ruby_command(File.join("test", script)))
end
announce("Standalone verification run passed.")
