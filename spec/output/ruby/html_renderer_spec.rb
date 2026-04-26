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

RSpec.describe ASRFacet::Output::Ruby::HtmlRenderer do
  it "renders a dark single-file html dashboard from fixture data" do
    Dir.mktmpdir do |dir|
      path = File.join(dir, "report.html")
      described_class.new(build_output_store, output_fixture_data[:target], build_output_options).render(path)

      html = File.read(path)
      expect(html).to include("chart.js")
      expect(html).to include("Primary Charts")
      expect(html).to include("badge-high")
      expect(html).to include("api.lab.example.com")
    end
  end
end
