# Part of ASRFacet-Rb — authorized testing only
require_relative "lib/asrfacet_rb/version"

Gem::Specification.new do |spec|
  spec.name = "asrfacet-rb"
  spec.version = ASRFacet::VERSION
  spec.authors = ["ASRFacet-Rb"]
  spec.email = ["authorized@example.com"]
  spec.summary = "Authorized attack surface reconnaissance for Ruby 3.2+."
  spec.description = "ASRFacet-Rb is an authorized penetration testing and attack surface reconnaissance toolkit."
  spec.homepage = "https://example.com/asrfacet-rb"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2"

  spec.files = Dir.glob("{bin,lib}/**/*").select { |path| File.file?(path) }
  spec.bindir = "bin"
  spec.executables = ["asrfacet"]
  spec.require_paths = ["lib"]

  spec.add_runtime_dependency "thor"
  spec.add_runtime_dependency "tty-prompt"
  spec.add_runtime_dependency "tty-spinner"
  spec.add_runtime_dependency "tty-table"
  spec.add_runtime_dependency "colorize"
  spec.add_runtime_dependency "nokogiri"
  spec.add_runtime_dependency "whois"
  spec.add_runtime_dependency "parallel"

  spec.add_development_dependency "rspec"
  spec.add_development_dependency "webmock"
  spec.add_development_dependency "rubocop"
end
