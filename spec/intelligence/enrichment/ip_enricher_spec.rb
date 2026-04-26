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

RSpec.describe ASRFacet::Intelligence::Enrichment::IpEnricher do
  it "adds ptr and geolocation data to ip assets" do
    Dir.mktmpdir do |dir|
      response = instance_double(
        Net::HTTPOK,
        body: {
          status: "success",
          country: "United States",
          regionName: "California",
          city: "San Francisco",
          lat: 37.77,
          lon: -122.42,
          isp: "Example ISP",
          org: "Example Org",
          as: "AS13335"
        }.to_json
      )
      client = instance_double(ASRFacet::HTTP::RetryableClient, get: response)
      graph = ASRFacet::Intelligence::AssetGraph.new("example.com", root: dir)

      result = described_class.new(http_client: client, ptr_lookup: ->(_ip) { "ptr.example.com" }).enrich("203.0.113.10", graph: graph)

      expect(result).to include(ptr: "ptr.example.com", country: "United States")
      expect(graph.find_by_type(:location).map(&:value)).to include("San Francisco, California, United States")
    end
  end

  it "returns an empty hash when all enrichment paths fail" do
    client = instance_double(ASRFacet::HTTP::RetryableClient, get: nil)

    result = described_class.new(http_client: client, ptr_lookup: ->(_ip) { raise Resolv::ResolvError }).enrich(
      "203.0.113.10",
      graph: instance_double(ASRFacet::Intelligence::AssetGraph, add_asset: nil)
    )

    expect(result).to eq({})
  end

  it "merges new location properties into an existing ip asset" do
    Dir.mktmpdir do |dir|
      response = instance_double(Net::HTTPOK, body: { status: "success", country: "United States" }.to_json)
      client = instance_double(ASRFacet::HTTP::RetryableClient, get: response)
      graph = ASRFacet::Intelligence::AssetGraph.new("example.com", root: dir)
      graph.add_asset(ASRFacet::Intelligence::OAM.make(type: :ip_address, value: "203.0.113.10", source: "fixture", properties: { note: "existing" }))

      described_class.new(http_client: client, ptr_lookup: ->(_ip) { "" }).enrich("203.0.113.10", graph: graph)

      expect(graph.find_by_value(:ip_address, "203.0.113.10").properties).to include(note: "existing", country: "United States")
    end
  end
end
