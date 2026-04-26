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
  module Core
    class KnowledgeGraph
      NODE_TYPES = %i[domain subdomain ip asn service finding].freeze

      def initialize
        @nodes = {}
        @edges = Hash.new { |hash, key| hash[key] = [] }
        @mutex = Mutex.new
      end

      def add_node(id, type:, data: {})
        node_id = id.to_s
        return nil if node_id.empty?

        @mutex.synchronize do
          existing = @nodes[node_id] || {}
          discovered_at = existing[:discovered_at] || Time.now.iso8601
          @nodes[node_id] = {
            id: node_id,
            type: normalize_type(type),
            data: merge_hash(existing[:data], normalize_hash(data)),
            discovered_at: discovered_at,
            last_seen: Time.now.iso8601
          }
        end
      rescue StandardError
        nil
      end

      def add_edge(from_id, to_id, relation:)
        source = from_id.to_s
        target = to_id.to_s
        return nil if source.empty? || target.empty?

        timestamp = Time.now.iso8601
        @mutex.synchronize do
          existing = @edges[source].find { |entry| entry[:to] == target && entry[:relation] == relation.to_sym }
          if existing
            existing[:last_seen] = timestamp
            duplicate_value(existing.merge(from: source))
          else
            @edges[source] << {
              to: target,
              relation: relation.to_sym,
              discovered_at: timestamp,
              last_seen: timestamp
            }
            duplicate_value(@edges[source].last.merge(from: source))
          end
        end
      rescue StandardError
        nil
      end

      def neighbors(id)
        pivot(id)[:neighbors]
      rescue StandardError
        []
      end

      def pivot(id)
        node_id = id.to_s
        @mutex.synchronize do
          related_edges = flattened_edges.select { |edge| edge[:from] == node_id || edge[:to] == node_id }
          {
            node: duplicate_value(@nodes[node_id]),
            relationships: related_edges.map { |edge| duplicate_value(edge) },
            edges: related_edges.map { |edge| duplicate_value(edge) },
            neighbors: related_edges.filter_map do |edge|
              neighbor_id = edge[:from] == node_id ? edge[:to] : edge[:from]
              neighbor = @nodes[neighbor_id]
              next if neighbor.nil?

              {
                relation: edge[:relation],
                direction: edge[:from] == node_id ? :outbound : :inbound,
                node: duplicate_value(neighbor)
              }
            end.uniq { |entry| [entry[:relation], entry[:direction], entry.dig(:node, :id)] }
          }
        end
      rescue StandardError
        { node: nil, relationships: [], edges: [], neighbors: [] }
      end

      def subgraph(type:)
        node_type = type.to_sym
        @mutex.synchronize do
          nodes = @nodes.values.select { |node| node[:type] == node_type }
          ids = nodes.map { |node| node[:id] }
          {
            nodes: nodes.map { |node| duplicate_value(node) },
            edges: flattened_edges.select { |edge| ids.include?(edge[:from]) || ids.include?(edge[:to]) }.map { |edge| duplicate_value(edge) }
          }
        end
      rescue StandardError
        { nodes: [], edges: [] }
      end

      def to_h
        @mutex.synchronize do
          {
            nodes: @nodes.values.map { |node| duplicate_value(node) },
            edges: flattened_edges.map { |edge| duplicate_value(edge) }
          }
        end
      rescue StandardError
        { nodes: [], edges: [] }
      end

      def nodes
        to_h[:nodes].map do |node|
          duplicate_value(node).merge(value: node[:data].to_h[:title] || node[:id])
        end
      rescue StandardError
        []
      end

      def edges
        to_h[:edges].map do |edge|
          duplicate_value(edge).merge(rel: edge[:relation])
        end
      rescue StandardError
        []
      end

      def self.load(target, output_root: nil)
        root = output_root || File.expand_path((ASRFacet::Config.fetch("output", "directory") || "~/.asrfacet_rb/output").to_s)
        safe_target = target.to_s.downcase.gsub(/[^a-z0-9.\-_]+/, "_").tr(".", "_")
        report = Dir.glob(File.join(root, "reports", safe_target, "*", "report.json")).max_by { |path| File.mtime(path) }
        return new if report.nil?

        payload = JSON.parse(File.read(report), symbolize_names: true)
        graph = new
        normalized = payload[:graph].to_h
        Array(normalized[:nodes]).each do |node|
          graph.add_node(node[:id], type: node[:type], data: node[:data] || {})
        end
        Array(normalized[:edges]).each do |edge|
          graph.add_edge(edge[:from], edge[:to], relation: edge[:relation] || edge[:rel])
        end
        graph
      rescue StandardError
        new
      end

      private

      def flattened_edges
        @edges.each_with_object([]) do |(from, entries), memo|
          entries.each do |entry|
            memo << {
              from: from,
              to: entry[:to],
              relation: entry[:relation],
              discovered_at: entry[:discovered_at],
              last_seen: entry[:last_seen]
            }
          end
        end
      rescue StandardError
        []
      end

      def normalize_type(type)
        value = type.to_sym
        NODE_TYPES.include?(value) ? value : :service
      rescue StandardError
        :service
      end

      def normalize_hash(value)
        value.is_a?(Hash) ? value : {}
      rescue StandardError
        {}
      end

      def merge_hash(left, right)
        normalize_hash(left).merge(normalize_hash(right)) do |_key, old_value, new_value|
          if old_value.is_a?(Hash) && new_value.is_a?(Hash)
            merge_hash(old_value, new_value)
          elsif old_value.is_a?(Array) || new_value.is_a?(Array)
            (Array(old_value) + Array(new_value)).uniq
          else
            new_value
          end
        end
      rescue StandardError
        normalize_hash(right)
      end

      def duplicate_value(value)
        case value
        when Hash
          value.each_with_object({}) do |(key, nested), memo|
            memo[key] = duplicate_value(nested)
          end
        when Array
          value.map { |entry| duplicate_value(entry) }
        else
          value
        end
      rescue StandardError
        value
      end
    end
  end
end
