# Part of ASRFacet-Rb — authorized testing only
require_relative "lib/asrfacet_rb/version"
require_relative "lib/asrfacet_rb/metadata"

Gem::Specification.new do |spec|
  spec.name = "asrfacet-rb"
  spec.version = ASRFacet::VERSION
  spec.authors = [ASRFacet::Metadata::AUTHOR]
  spec.email = [ASRFacet::Metadata::EMAIL]
  spec.summary = "Authorized attack surface reconnaissance for Ruby 3.2+."
  spec.description = "ASRFacet-Rb is an authorized penetration testing and attack surface reconnaissance toolkit."
  spec.homepage = ASRFacet::Metadata::REPO_URL
  spec.license = "LicenseRef-Proprietary"
  spec.required_ruby_version = ">= 3.2"

  spec.files = Dir.glob("{bin,config,install,lib,man,spec,wordlists}/**/*").select { |path| File.file?(path) } + %w[Gemfile README.md LICENSE]
  spec.bindir = "bin"
  spec.executables = %w[asrfacet-rb]
  spec.require_paths = ["lib"]
  spec.metadata = {
    "source_code_uri" => ASRFacet::Metadata::REPO_URL,
    "homepage_uri" => ASRFacet::Metadata::REPO_URL,
    "documentation_uri" => "#{ASRFacet::Metadata::REPO_URL}#readme",
    "bug_tracker_uri" => "#{ASRFacet::Metadata::REPO_URL}/issues"
  }

  spec.add_runtime_dependency "thor"
  spec.add_runtime_dependency "tty-prompt"
  spec.add_runtime_dependency "tty-spinner"
  spec.add_runtime_dependency "tty-table"
  spec.add_runtime_dependency "colorize"
  spec.add_runtime_dependency "nokogiri"
  spec.add_runtime_dependency "whois"
  spec.add_runtime_dependency "parallel"
  spec.add_runtime_dependency "webrick"
  spec.add_runtime_dependency "fiddle"

  spec.add_development_dependency "rspec"
  spec.add_development_dependency "webmock"
  spec.add_development_dependency "rubocop"
  spec.add_development_dependency "ferrum"
end
