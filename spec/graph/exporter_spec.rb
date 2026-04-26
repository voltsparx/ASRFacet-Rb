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

RSpec.describe ASRFacet::Graph::Exporter do
  it "exports knowledge graphs in dot, json, and mermaid forms" do
    graph = ASRFacet::Core::KnowledgeGraph.new
    graph.add_node("example.com", type: :domain, data: {})
    graph.add_node("app.example.com", type: :subdomain, data: {})
    graph.add_edge("example.com", "app.example.com", relation: :belongs_to)

    exporter = described_class.new(graph)

    expect(exporter.to_dot).to include("digraph ASRFacet")
    expect(JSON.parse(exporter.to_json_graph)).to include("nodes", "edges", "meta")
    expect(exporter.to_mermaid).to include("graph LR")
  end
end
