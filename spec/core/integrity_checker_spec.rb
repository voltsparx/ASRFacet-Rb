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

require "spec_helper"
require "tmpdir"

RSpec.describe ASRFacet::Core::IntegrityChecker do
  it "reports ok for a complete temporary application root" do
    Dir.mktmpdir do |dir|
      %w[bin lib/asrfacet_rb config wordlists man].each do |entry|
        FileUtils.mkdir_p(File.join(dir, entry))
      end
      File.write(File.join(dir, "bin", "asrfacet-rb"), "#!/usr/bin/env ruby\n")
      File.write(File.join(dir, "bin", "asrfrb"), "#!/usr/bin/env ruby\n")
      File.write(File.join(dir, "lib", "asrfacet_rb.rb"), "module ASRFacet; end\n")
      File.write(File.join(dir, "lib", "asrfacet_rb", "version.rb"), "module ASRFacet; VERSION='1.0.0'; end\n")
      File.write(File.join(dir, "config", "default.yml"), <<~YAML)
        wordlists:
          subdomain: wordlists/subdomains_small.txt
          paths: wordlists/paths_common.txt
      YAML
      File.write(File.join(dir, "README.md"), "# temp app root\n")
      File.write(File.join(dir, "wordlists", "subdomains_small.txt"), "www\n")
      File.write(File.join(dir, "wordlists", "paths_common.txt"), "/admin\n")
      File.write(File.join(dir, "man", "asrfacet-rb.1"), ".TH asrfacet-rb 1\n")
      output_root = File.join(dir, "output")

      report = described_class.check(app_root: dir, output_root: output_root)

      expect(report[:status]).to eq("ok")
      expect(report[:issues]).to eq([])
    end
  end

  it "reports critical issues and recommendations when required files are missing" do
    Dir.mktmpdir do |dir|
      FileUtils.mkdir_p(File.join(dir, "config"))
      File.write(File.join(dir, "config", "default.yml"), "wordlists: {}\n")

      report = described_class.check(app_root: dir, output_root: File.join(dir, "output"))

      expect(report[:status]).to eq("critical")
      expect(report[:issues]).not_to be_empty
      expect(report[:recommendations].join(" ")).to include("Repair or reinstall")
    end
  end
end
