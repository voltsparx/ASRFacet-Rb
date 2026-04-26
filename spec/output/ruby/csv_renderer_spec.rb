# frozen_string_literal: true
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

RSpec.describe ASRFacet::Output::Ruby::CsvRenderer do
  it "renders five csv files with metadata headers from fixture data" do
    Dir.mktmpdir do |dir|
      path = File.join(dir, "report.csv")
      described_class.new(build_output_store, output_fixture_data[:target], build_output_options).render(path)

      findings_csv = File.join(dir, "report_findings.csv")
      expect(File.read(findings_csv)).to include("# ASRFacet-Rb Recon Report")
      expect(File.exist?(File.join(dir, "report_subdomains.csv"))).to be(true)
      expect(File.exist?(File.join(dir, "report_ips.csv"))).to be(true)
      expect(File.exist?(File.join(dir, "report_ports.csv"))).to be(true)
      expect(File.exist?(File.join(dir, "report_js_endpoints.csv"))).to be(true)
    end
  end
end
