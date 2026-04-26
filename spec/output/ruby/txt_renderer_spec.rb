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
require "asrfacet_rb/output/ruby/txt_renderer"

RSpec.describe ASRFacet::Output::Ruby::TxtRenderer do
  let(:store) do
    ASRFacet::ResultStore.new.tap do |result|
      result.add_subdomain("app.example.com")
      result.add_ip("1.2.3.4")
      result.add_port("1.2.3.4", 443, service: "https", banner: "nginx")
      result.add_finding(title: "TLS", severity: "high", asset: "app.example.com", description: "Strong ciphers")
      result.add_js_endpoint("https://app.example.com/app.js")
    end
  end

  it "writes a text report" do
    Dir.mktmpdir do |dir|
      path = File.join(dir, "report.txt")

      described_class.new(store, "example.com", charts: {}).render(path)

      expect(File.read(path)).to include("ASRFacet-Rb Recon Report")
      expect(File.read(path)).to include("app.example.com")
    end
  end
end
