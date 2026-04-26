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

RSpec.describe ASRFacet::Intelligence::Enrichment::AsnEnricher do
  it "builds ip-netblock-asn relationships from bgp metadata" do
    Dir.mktmpdir do |dir|
      response = instance_double(Net::HTTPOK, body: { asn: "13335", prefix: "203.0.113.0/24", name: "Cloudflare", country: "US" }.to_json)
      client = instance_double(ASRFacet::HTTP::RetryableClient, get: response)
      graph = ASRFacet::Intelligence::AssetGraph.new("example.com", root: dir)

      result = described_class.new(http_client: client).enrich("203.0.113.10", graph: graph)

      expect(result).to include(asn: "AS13335", netblock: "203.0.113.0/24")
      expect(graph.find_by_type(:netblock).map(&:value)).to include("203.0.113.0/24")
      expect(graph.find_by_type(:asn).map(&:value)).to include("AS13335")
    end
  end

  it "returns an empty hash when no source answers are available" do
    client = instance_double(ASRFacet::HTTP::RetryableClient, get: nil)

    expect(described_class.new(http_client: client).enrich("203.0.113.10", graph: instance_double(ASRFacet::Intelligence::AssetGraph))).to eq({})
  end

  it "falls back to team cymru data when bgp.tools is unavailable" do
    Dir.mktmpdir do |dir|
      client = instance_double(ASRFacet::HTTP::RetryableClient, get: nil)
      graph = ASRFacet::Intelligence::AssetGraph.new("example.com", root: dir)
      enricher = described_class.new(
        http_client: client,
        team_cymru_lookup: ->(_ip) { { asn: "AS64500", netblock: "198.51.100.0/24", description: "Example", country: "US" } }
      )

      result = enricher.enrich("198.51.100.20", graph: graph)

      expect(result).to include(asn: "AS64500")
    end
  end
end
