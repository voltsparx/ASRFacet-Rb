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
require "asrfacet_rb/output/chart_data_builder"

RSpec.describe ASRFacet::Output::ChartDataBuilder do
  let(:store) do
    instance_double(
      ASRFacet::ResultStore,
      findings: [
        { severity: "high", asset: "sub.example.com" },
        { severity: "medium", asset: "api.example.com" }
      ],
      ports: {
        "1.2.3.4" => [
          { port: 80, service: "http", banner: nil },
          { port: 443, service: "https", banner: nil }
        ]
      },
      subdomains: ["sub.example.com", "api.example.com"],
      subdomains_with_sources: nil,
      ips: ["1.2.3.4", "10.0.0.1"]
    )
  end

  subject(:builder) { described_class.new(store) }

  describe "#build" do
    it "returns a hash with all chart keys" do
      result = builder.build

      expect(result.keys).to include(
        :severity_distribution,
        :port_frequency,
        :service_breakdown,
        :ip_class_distribution
      )
    end
  end

  describe "#severity_distribution" do
    it "groups findings by severity" do
      labels = builder.severity_distribution.map { |entry| entry[:label] }

      expect(labels).to include("High", "Medium")
    end
  end

  describe "#port_frequency" do
    it "returns port frequency sorted descending" do
      result = builder.port_frequency

      expect(result).not_to be_empty
      expect(result.first).to have_key(:port)
      expect(result.first).to have_key(:count)
    end
  end
end
