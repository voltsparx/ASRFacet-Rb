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

RSpec.describe ASRFacet::Output::Ruby::JsonRenderer do
  it "renders pretty json with meta, stats, tables, and charts" do
    Dir.mktmpdir do |dir|
      path = File.join(dir, "report.json")
      described_class.new(build_output_store, output_fixture_data[:target], build_output_options).render(path)

      payload = JSON.parse(File.read(path))
      expect(payload.dig("meta", "target")).to eq("lab.example.com")
      expect(payload.fetch("findings").length).to eq(3)
      expect(payload.dig("charts", "service_breakdown")).not_to be_empty
    end
  end
end
