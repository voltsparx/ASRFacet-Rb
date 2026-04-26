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

require "json"

module IntelligenceFixture
  def intelligence_fixture_data(name = "intelligence_graph")
    JSON.parse(
      File.read(File.join(__dir__, "..", "fixtures", "#{name}.json")),
      symbolize_names: true
    )
  end

  def build_intelligence_graph(name = "intelligence_graph", root:)
    data = intelligence_fixture_data(name)
    graph = ASRFacet::Intelligence::AssetGraph.new(data[:target], root: root)
    asset_lookup = {}

    Array(data[:assets]).each do |entry|
      asset = ASRFacet::Intelligence::OAM.make(
        type: entry[:type],
        value: entry[:value],
        source: entry[:source],
        properties: entry[:properties] || {}
      )
      stored = graph.add_asset(asset)
      asset_lookup[[stored.type, stored.value]] = stored
    end

    Array(data[:relations]).each do |entry|
      from_asset = asset_lookup.fetch([entry.dig(:from, :type).to_sym, entry.dig(:from, :value)])
      to_asset = asset_lookup.fetch([entry.dig(:to, :type).to_sym, entry.dig(:to, :value)])
      graph.add_relation(
        from: from_asset,
        to: to_asset,
        type: entry[:type],
        source: entry[:source],
        properties: entry[:properties] || {}
      )
    end

    graph
  end
end

RSpec.configure do |config|
  config.include IntelligenceFixture
end
