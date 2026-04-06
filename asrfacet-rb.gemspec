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
  spec.license = "Nonstandard"
  spec.required_ruby_version = ">= 3.2"

  spec.files = Dir.glob("{bin,config,lib,spec}/**/*").select { |path| File.file?(path) } + %w[Gemfile README.md LICENSE]
  spec.bindir = "bin"
  spec.executables = %w[asrfacet asrfacet-rb]
  spec.require_paths = ["lib"]
  spec.metadata = {
    "source_code_uri" => ASRFacet::Metadata::REPO_URL,
    "homepage_uri" => ASRFacet::Metadata::REPO_URL
  }

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
