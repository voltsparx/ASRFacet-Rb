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
require "time"

module ASRFacet
  module Graph
    class Exporter
      def initialize(knowledge_graph)
        @graph = knowledge_graph
      end

      def to_dot
        lines = ["digraph ASRFacet {"]
        lines << "  rankdir=LR;"
        lines << "  node [shape=box fontname=\"Helvetica\"];"
        lines << ""
        @graph.nodes.each do |node|
          label = dot_label(node)
          color = dot_color(node[:type])
          lines << "  \"#{node[:id]}\" [label=\"#{label}\" fillcolor=\"#{color}\" style=filled];"
        end
        lines << ""
        @graph.edges.each do |edge|
          lines << "  \"#{edge[:from] || edge[:from_id]}\" -> \"#{edge[:to] || edge[:to_id]}\" [label=\"#{edge[:rel] || edge[:relation] || edge[:type]}\"];"
        end
        lines << "}"
        lines.join("\n")
      end

      def to_json_graph
        JSON.pretty_generate(
          nodes: @graph.nodes,
          edges: @graph.edges,
          meta: {
            generated_at: Time.now.iso8601,
            node_count: @graph.nodes.size,
            edge_count: @graph.edges.size
          }
        )
      end

      def to_mermaid
        lines = ["graph LR"]
        @graph.edges.each do |edge|
          edge_from = edge[:from] || edge[:from_id]
          edge_to = edge[:to] || edge[:to_id]
          from = mermaid_id(edge_from)
          to = mermaid_id(edge_to)
          rel = edge[:rel] || edge[:relation] || edge[:type]
          lines << "  #{from}[\"#{edge_from}\"] -->|#{rel}| #{to}[\"#{edge_to}\"]"
        end
        lines.join("\n")
      end

      private

      def dot_label(node)
        "#{node[:value] || node[:id]}\\n(#{node[:type]})"
      end

      def dot_color(type)
        {
          domain: "#AED6F1",
          fqdn: "#A9DFBF",
          subdomain: "#A9DFBF",
          ip: "#FAD7A0",
          ip_address: "#FAD7A0",
          netblock: "#F5CBA7",
          port: "#F1948A",
          service: "#F1948A",
          asn: "#D7BDE2",
          as_desc: "#D2B4DE",
          certificate: "#F7DC6F",
          technology: "#82E0AA",
          email: "#AED6F1",
          finding: "#F9E79F"
        }.fetch(type&.to_sym, "#EAECEE")
      end

      def mermaid_id(value)
        "N#{value.to_s.gsub(/[^a-zA-Z0-9]/, "_")}"
      end
    end
  end
end
