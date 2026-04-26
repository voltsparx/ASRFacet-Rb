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

require "json"
require "spec_helper"
require "tmpdir"
require "asrfacet_rb/output/ruby/json_renderer"

RSpec.describe ASRFacet::Output::Ruby::JsonRenderer do
  let(:store) do
    ASRFacet::ResultStore.new.tap do |result|
      result.add_subdomain("api.example.com")
      result.add_ip("1.2.3.4")
      result.add_error(source: "test", message: "sample")
    end
  end

  it "writes a json report" do
    Dir.mktmpdir do |dir|
      path = File.join(dir, "report.json")

      described_class.new(store, "example.com", charts: {}).render(path)

      data = JSON.parse(File.read(path))
      expect(data.dig("meta", "target")).to eq("example.com")
      expect(data.fetch("subdomains")).to include("api.example.com")
    end
  end
end
