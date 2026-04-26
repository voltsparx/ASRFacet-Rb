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

RSpec.describe ASRFacet::Intelligence::Analysis::RelationshipMapper do
  it "infers SAN fqdn assets, fqdn-ip-netblock chains, and third-party links" do
    Dir.mktmpdir do |dir|
      graph = build_intelligence_graph(root: dir)
      result = described_class.new.map(graph)

      expect(result[:new_assets]).to include(include(type: :fqdn, value: "new.lab.example.com"))
      expect(result[:new_relations]).to include(include(type: :contains))
      expect(result[:new_relations]).to include(include(type: :managed_by))
      expect(result[:third_parties]).to include(include(type: :asn, value: "AS13335"))
    end
  end

  it "handles empty graphs without inferring anything" do
    Dir.mktmpdir do |dir|
      graph = ASRFacet::Intelligence::AssetGraph.new("empty.example.com", root: dir)

      expect(described_class.new.map(graph)).to eq(new_assets: [], new_relations: [], third_parties: [])
    end
  end

  it "is idempotent across repeated mapping runs" do
    Dir.mktmpdir do |dir|
      graph = build_intelligence_graph(root: dir)
      mapper = described_class.new

      first = mapper.map(graph)
      second = mapper.map(graph)

      expect(first[:new_relations]).not_to be_empty
      expect(second[:new_relations]).to eq([])
    end
  end
end
