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
require "asrfacet_rb/output/base_renderer"

RSpec.describe ASRFacet::Output::BaseRenderer do
  let(:store) do
    instance_double(
      ASRFacet::ResultStore,
      findings: [
        { severity: "medium", title: "Medium finding" },
        { severity: "high", title: "High finding" }
      ]
    )
  end

  let(:renderer_class) do
    Class.new(described_class) do
      def render(_output_path)
        sorted_findings
      end
    end
  end

  it "sorts findings by severity order" do
    renderer = renderer_class.new(store, "example.com")

    expect(renderer.render(nil).map { |finding| finding[:title] }).to eq(
      ["High finding", "Medium finding"]
    )
  end
end
