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

RSpec.describe ASRFacet::Intelligence::AssetGraph do
  it "adds fixture assets and relations and exposes graph views" do
    Dir.mktmpdir do |dir|
      graph = build_intelligence_graph(root: dir)

      fqdn = graph.find_by_value(:fqdn, "app.lab.example.com")
      expect(fqdn).not_to be_nil
      expect(graph.find_by_type(:ip_address).map(&:value)).to include("203.0.113.10")
      expect(graph.neighbors(fqdn).map(&:value)).to include("lab.example.com", "203.0.113.10", "sha256:deadbeef")
      expect(graph.relations_for(fqdn).map(&:type)).to include(:subdomain_of, :resolves_to, :has_certificate)
      expect(graph.stats[:asset_types]).to include(fqdn: 2, ip_address: 2)
      expect(graph.to_h[:nodes]).not_to be_empty
    end
  end

  it "raises when loading malformed graph json" do
    Dir.mktmpdir do |dir|
      graph = described_class.new("bad.example.com", root: dir)
      File.write(graph.graph_path, "{not-json")

      expect { graph.load_from_disk }.to raise_error(ASRFacet::ParseError, /Unable to parse/)
    end
  end

  it "dedupes assets by type and value while merging sources and properties" do
    Dir.mktmpdir do |dir|
      graph = described_class.new("merge.example.com", root: dir)
      first = graph.add_asset(ASRFacet::Intelligence::OAM.make(type: :fqdn, value: "app.merge.example.com", source: "dns", properties: { environment: "prod" }))
      second = graph.add_asset(ASRFacet::Intelligence::OAM.make(type: :fqdn, value: "APP.MERGE.EXAMPLE.COM", source: "cert", properties: { region: "us-east-1" }))

      expect(first.id).to eq(second.id)
      expect(graph.find_by_type(:fqdn).size).to eq(1)
      expect(second.properties).to include(environment: "prod", region: "us-east-1")
      expect(second.properties[:sources]).to include("dns", "cert")
    end
  end
end
