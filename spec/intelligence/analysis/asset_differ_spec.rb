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

RSpec.describe ASRFacet::Intelligence::Analysis::AssetDiffer do
  it "detects added, changed, and new relation entries between fixture graphs" do
    Dir.mktmpdir do |dir|
      previous = build_intelligence_graph("intelligence_graph_previous", root: dir)
      current = build_intelligence_graph("intelligence_graph", root: dir)
      diff = described_class.new.diff(previous, current)

      expect(diff[:new_assets]).to include(include(value: "api.lab.example.com"))
      expect(diff[:changed_assets]).to include(include(changes: include(properties: anything)))
      expect(diff[:new_relations]).to include(include(type: :has_certificate))
      expect(diff[:summary]).to include(added: be > 0, changed: be > 0)
    end
  end

  it "returns empty diffs for empty graph payloads" do
    diff = described_class.new.diff({ nodes: [], edges: [] }, { nodes: [], edges: [] })

    expect(diff).to eq(
      new_assets: [],
      removed_assets: [],
      changed_assets: [],
      new_relations: [],
      summary: { added: 0, removed: 0, changed: 0 }
    )
  end

  it "returns no changes when the same graph is compared to itself" do
    Dir.mktmpdir do |dir|
      graph = build_intelligence_graph(root: dir)
      diff = described_class.new.diff(graph, graph)

      expect(diff[:summary]).to eq(added: 0, removed: 0, changed: 0)
    end
  end
end
