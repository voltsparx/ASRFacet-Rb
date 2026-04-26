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

RSpec.describe ASRFacet::Intelligence::Enrichment::CertificateEnricher do
  it "adds live certificates, historical sans, and emits new subdomains" do
    Dir.mktmpdir do |dir|
      cert = double(
        subject: double(to_a: [["CN", "app.example.com", nil]]),
        issuer: double(to_s: "CN=Issuer"),
        not_before: Time.utc(2026, 1, 1),
        not_after: Time.utc(2027, 1, 1),
        serial: 12_345,
        extensions: [double(oid: "subjectAltName", value: "DNS:app.example.com, DNS:new.example.com")]
      )
      response = instance_double(Net::HTTPOK, body: [{ common_name: "old.example.com", name_value: "old.example.com" }].to_json)
      http_client = instance_double(ASRFacet::HTTP::RetryableClient, get: response)
      event_bus = instance_double(ASRFacet::EventBus, emit: true)
      graph = ASRFacet::Intelligence::AssetGraph.new("example.com", root: dir)

      result = described_class.new(
        http_client: http_client,
        event_bus: event_bus,
        cert_fetcher: ->(_host, port:) { port == 443 ? cert : nil }
      ).enrich("app.example.com", graph: graph)

      expect(result[:certificates]).not_to be_empty
      expect(result[:historical_sans]).to include("old.example.com")
      expect(graph.find_by_type(:certificate).map(&:value)).to include("3039")
      expect(event_bus).to have_received(:emit).at_least(:once)
    end
  end

  it "returns an empty structure when no live or historical data exists" do
    client = instance_double(ASRFacet::HTTP::RetryableClient, get: nil)
    event_bus = instance_double(ASRFacet::EventBus, emit: true)

    result = described_class.new(http_client: client, event_bus: event_bus, cert_fetcher: ->(_host, port:) { nil }).enrich(
      "app.example.com",
      graph: instance_double(ASRFacet::Intelligence::AssetGraph, add_asset: nil)
    )

    expect(result[:certificates]).to eq([])
  end

  it "dedupes repeated certificates across ports" do
    Dir.mktmpdir do |dir|
      cert = double(
        subject: double(to_a: [["CN", "app.example.com", nil]]),
        issuer: double(to_s: "CN=Issuer"),
        not_before: Time.utc(2026, 1, 1),
        not_after: Time.utc(2027, 1, 1),
        serial: 12_345,
        extensions: []
      )
      graph = ASRFacet::Intelligence::AssetGraph.new("example.com", root: dir)
      http_client = instance_double(ASRFacet::HTTP::RetryableClient, get: nil)

      described_class.new(
        http_client: http_client,
        cert_fetcher: ->(_host, port:) { [443, 8443].include?(port) ? cert : nil },
        ports: [443, 8443]
      ).enrich("app.example.com", graph: graph)

      expect(graph.find_by_type(:certificate).size).to eq(1)
    end
  end
end
