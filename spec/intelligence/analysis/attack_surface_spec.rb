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

RSpec.describe ASRFacet::Intelligence::Analysis::AttackSurface do
  it "summarizes fixture graphs into attack-surface buckets" do
    Dir.mktmpdir do |dir|
      graph = build_intelligence_graph(root: dir)
      ASRFacet::Intelligence::Analysis::RelationshipMapper.new.map(graph)
      summary = described_class.new.summarize(graph)

      expect(summary[:domains].map { |asset| asset[:value] }).to include("lab.example.com", "app.lab.example.com")
      expect(summary[:ips].map { |asset| asset[:value] }).to include("203.0.113.10")
      expect(summary[:open_ports]).to include(include(value: "443"))
      expect(summary[:third_parties]).to include(include(value: "AS13335"))
      expect(summary[:critical_assets]).to include(include(value: "443"))
    end
  end

  it "returns empty buckets for blank graphs" do
    Dir.mktmpdir do |dir|
      graph = ASRFacet::Intelligence::AssetGraph.new("empty.example.com", root: dir)
      summary = described_class.new.summarize(graph)

      expect(summary.values).to all(eq([]))
    end
  end

  it "dedupes service-derived open ports" do
    Dir.mktmpdir do |dir|
      graph = ASRFacet::Intelligence::AssetGraph.new("ports.example.com", root: dir)
      graph.add_asset(ASRFacet::Intelligence::OAM.make(type: :service, value: "https", source: "fixture", properties: { host: "203.0.113.10", port: 443 }))
      graph.add_asset(ASRFacet::Intelligence::OAM.make(type: :port, value: "443", source: "fixture", properties: { host: "203.0.113.10" }))

      summary = described_class.new.summarize(graph)

      expect(summary[:open_ports].size).to eq(1)
    end
  end
end
