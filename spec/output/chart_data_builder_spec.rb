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

RSpec.describe ASRFacet::Output::ChartDataBuilder do
  subject(:builder) { described_class.new(build_output_store) }

  it "builds all requested chart datasets from fixture data" do
    charts = builder.build

    expect(charts.keys).to contain_exactly(
      :severity_distribution,
      :port_frequency,
      :service_breakdown,
      :ip_class_distribution,
      :subdomain_source_share,
      :finding_timeline
    )
  end

  it "counts severities and sources correctly" do
    expect(builder.severity_distribution).to include(include(label: "High", value: 1))
    expect(builder.subdomain_source_share).to include(include(label: "crtsh", value: 1))
  end

  it "builds port and timeline series from fixture events" do
    expect(builder.port_frequency.first).to include(port: 22).or include(port: 80).or include(port: 443)
    expect(builder.finding_timeline.map { |row| row[:label] }).to include("2026-04-25", "2026-04-26")
  end
end
