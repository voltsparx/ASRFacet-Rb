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

RSpec.describe ASRFacet::Intelligence::Enrichment::WhoisEnricher do
  it "extracts whois data, caches it, and adds related assets to the graph" do
    Dir.mktmpdir do |dir|
      contact = double(email: "ops@example.com")
      parser = double(
        registrar_name: "Example Registrar",
        registrant_name: "Example Org",
        nameservers: [double(name: "ns1.example.com")],
        status: ["active"],
        admin_contacts: [contact],
        technical_contacts: []
      )
      record = double(parser: parser, content: "")
      client = instance_double(Whois::Client)
      allow(client).to receive(:lookup).once.and_return(record)
      enricher = described_class.new(whois_client: client)
      graph = ASRFacet::Intelligence::AssetGraph.new("example.com", root: dir)

      first = enricher.enrich("example.com", graph: graph)
      second = enricher.enrich("example.com", graph: graph)

      expect(first[:registrar]).to eq("Example Registrar")
      expect(second[:registrant]).to eq("Example Org")
      expect(graph.find_by_type(:organization).map(&:value)).to include("Example Org")
      expect(graph.find_by_type(:email).map(&:value)).to include("ops@example.com")
    end
  end

  it "returns an empty hash on whois lookup errors" do
    client = instance_double(Whois::Client)
    allow(client).to receive(:lookup).and_raise(StandardError, "boom")

    expect(described_class.new(whois_client: client).enrich("example.com", graph: instance_double(ASRFacet::Intelligence::AssetGraph, add_asset: nil))).to eq({})
  end

  it "falls back to parsing raw whois content" do
    Dir.mktmpdir do |dir|
      record = double(
        parser: double,
        content: "Registrar: Example Registrar\nRegistrant Organization: Example Org\nName Server: ns1.example.com\nStatus: active\nEmail: ops@example.com\n"
      )
      client = instance_double(Whois::Client, lookup: record)
      graph = ASRFacet::Intelligence::AssetGraph.new("example.com", root: dir)

      data = described_class.new(whois_client: client).enrich("example.com", graph: graph)

      expect(data[:registrar]).to eq("Example Registrar")
      expect(data[:emails]).to include("ops@example.com")
    end
  end
end
