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

require "fileutils"
require "rbconfig"
require "rake/clean"
require "rspec/core/rake_task"

PROJECT_ROOT = __dir__
GEM_ARTIFACT_GLOB = File.join(PROJECT_ROOT, "asrfacet-rb-*.gem")

CLEAN.include(GEM_ARTIFACT_GLOB, "tmp/test", "install/test-root")

RSpec::Core::RakeTask.new(:spec) do |task|
  task.pattern = "spec/**/*_spec.rb"
end

def ruby_exec(*args)
  ruby = RbConfig.ruby
  result = system(ruby, *args)
  raise "Command failed: #{args.join(' ')}" unless result
end

namespace :test do
  desc "Run the RSpec suite"
  task spec: :spec

  desc "Verify version alignment across runtime, docs, and packaged assets"
  task :version do
    ruby_exec(File.join("test", "smoke_version.rb"))
  end

  desc "Run CLI smoke tests"
  task :cli do
    ruby_exec(File.join("test", "smoke_cli.rb"))
  end

  desc "Run web-session smoke tests"
  task :web do
    ruby_exec(File.join("test", "smoke_web.rb"))
  end

  desc "Run local lab smoke tests"
  task :lab do
    ruby_exec(File.join("test", "smoke_lab.rb"))
  end

  desc "Run deployment smoke tests"
  task :deploy do
    ruby_exec(File.join("test", "smoke_deploy.rb"))
  end

  desc "Run installer smoke tests for the current platform"
  task :install do
    ruby_exec(File.join("test", "smoke_install.rb"))
  end

  desc "Run website installer smoke tests"
  task :website_installers do
    ruby_exec(File.join("test", "smoke_website_installers.rb"))
  end
end

namespace :build do
  desc "Build the gem package and clean the generated .gem artifact"
  task :gem do
    gem_file = nil
    sh "gem", "build", "asrfacet-rb.gemspec"
    gem_file = Dir.glob(GEM_ARTIFACT_GLOB).max_by { |path| File.mtime(path) }
    raise "Gem build failed — no .gem artifact found" unless gem_file && File.exist?(gem_file)

    puts "[BUILD] Built #{gem_file}"
  ensure
    FileUtils.rm_f(gem_file) if gem_file && File.exist?(gem_file)
  end
end

desc "Run the full release verification pass"
task verify: ["test:spec", "test:version", "test:cli", "test:web", "test:lab", "test:deploy", "test:install", "test:website_installers", "build:gem"]

task default: :verify
