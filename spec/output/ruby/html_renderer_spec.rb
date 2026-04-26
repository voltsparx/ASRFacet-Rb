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
require "asrfacet_rb/output/ruby/html_renderer"

RSpec.describe ASRFacet::Output::Ruby::HtmlRenderer do
  let(:store) do
    ASRFacet::ResultStore.new.tap do |result|
      result.add_subdomain("app.example.com")
      result.add_ip("1.2.3.4")
      result.add_finding(title: "Header leak", severity: "low", asset: "app.example.com")
    end
  end

  it "writes an html report" do
    Dir.mktmpdir do |dir|
      path = File.join(dir, "report.html")

      described_class.new(store, "example.com", charts: {}).render(path)

      html = File.read(path)
      expect(html).to include("<html")
      expect(html).to include("severityChart")
      expect(html).to include("app.example.com")
    end
  end
end
