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

CLEAN.include("asrfacet-rb-*.gem", "tmp/test", "install/test-root")

RSpec::Core::RakeTask.new(:spec) do |task|
  task.pattern = "spec/**/*_spec.rb"
end

def ruby_exec(*args)
  ruby = RbConfig.ruby
  sh ruby, *args
end

namespace :test do
  desc "Run the RSpec suite"
  task spec: :spec

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

  desc "Run installer smoke tests for the current platform"
  task :install do
    ruby_exec(File.join("test", "smoke_install.rb"))
  end
end

namespace :build do
  desc "Build the gem package and clean the generated .gem artifact"
  task :gem do
    gem_file = nil
    sh "gem", "build", "asrfacet-rb.gemspec"
    gem_file = Dir.glob("asrfacet-rb-*.gem").max_by { |path| File.mtime(path) }
    puts "[BUILD] Built #{gem_file}" if gem_file
  ensure
    FileUtils.rm_f(gem_file) if gem_file && File.exist?(gem_file)
  end
end

desc "Run the full release verification pass"
task verify: ["test:spec", "test:cli", "test:web", "test:lab", "test:install", "build:gem"]

task default: :verify
