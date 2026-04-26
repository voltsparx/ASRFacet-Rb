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
require "asrfacet_rb/output/ruby/csv_renderer"

RSpec.describe ASRFacet::Output::Ruby::CsvRenderer do
  let(:store) do
    ASRFacet::ResultStore.new.tap do |result|
      result.add_subdomain("cdn.example.com")
      result.add_ip("1.2.3.4")
      result.add_port("1.2.3.4", 80, service: "http")
      result.add_finding(title: "Open HTTP", severity: "medium", asset: "1.2.3.4")
      result.add_js_endpoint("https://cdn.example.com/app.js")
    end
  end

  it "writes csv report files" do
    Dir.mktmpdir do |dir|
      path = File.join(dir, "report.csv")

      described_class.new(store, "example.com").render(path)

      expect(File.exist?(File.join(dir, "report_subdomains.csv"))).to be(true)
      expect(File.exist?(File.join(dir, "report_ports.csv"))).to be(true)
      expect(File.exist?(File.join(dir, "report_findings.csv"))).to be(true)
    end
  end
end
