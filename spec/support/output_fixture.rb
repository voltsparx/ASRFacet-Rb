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

module OutputFixture
  def output_fixture_data
    @output_fixture_data ||= JSON.parse(
      File.read(File.join(__dir__, "..", "fixtures", "output_fixture.json")),
      symbolize_names: true
    )
  end

  def build_output_store
    data = output_fixture_data
    ASRFacet::ResultStore.new.tap do |store|
      Array(data[:subdomains]).each { |host| store.add_subdomain(host) }
      Array(data[:subdomains_with_sources]).each { |entry| store.add(:subdomains_with_sources, entry) }
      Array(data[:ips]).each { |ip| store.add_ip(ip) }
      Array(data[:ports]).each { |entry| store.add(:open_ports, entry) }
      Array(data[:findings]).each { |entry| store.add_finding(entry) }
      Array(data[:js_endpoints]).each { |entry| store.add(:js_endpoints, entry) }
      Array(data[:errors]).each { |entry| store.add(:errors, entry) }
    end
  end

  def build_output_graph
    data = output_fixture_data
    ASRFacet::Core::KnowledgeGraph.new.tap do |graph|
      graph.add_node(data[:target], type: :domain, data: {})
      Array(data[:subdomains]).each do |host|
        graph.add_node(host, type: :subdomain, data: {})
        graph.add_edge(data[:target], host, relation: :belongs_to)
      end
      Array(data[:ips]).each do |ip|
        graph.add_node(ip, type: :ip, data: {})
      end
    end
  end

  def build_output_options
    {
      charts: ASRFacet::Output::ChartDataBuilder.new(build_output_store).build,
      asset_graph: build_output_graph,
      engine_label: "Fixture Engine"
    }
  end
end

RSpec.configure do |config|
  config.include OutputFixture
end
