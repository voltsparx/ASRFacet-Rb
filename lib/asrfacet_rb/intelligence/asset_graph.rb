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

require "concurrent"
require "fileutils"
require "json"
require "time"
require_relative "open_asset_model"

module ASRFacet
  module Intelligence
    class AssetGraph
      attr_reader :target, :root

      def initialize(target, root: File.expand_path("~/.asrfacet_rb/workspaces"))
        @target = target.to_s
        @root = root
        @assets_by_key = Concurrent::Map.new
        @assets_by_id = Concurrent::Map.new
        @relations = Concurrent::Array.new
        @relation_index = Concurrent::Map.new
        @mutex = Mutex.new
        @persist_mutex = Mutex.new
        FileUtils.mkdir_p(workspace_path)
      end

      def add_asset(asset)
        candidate = normalize_asset(asset)
        stored_asset = nil
        snapshot = nil

        @mutex.synchronize do
          key = asset_key(candidate.type, candidate.value)
          stored_asset = @assets_by_key[key]
          stored_asset = stored_asset.nil? ? candidate : merge_asset(stored_asset, candidate)
          @assets_by_key[key] = stored_asset
          @assets_by_id[stored_asset.id] = stored_asset
          snapshot = build_snapshot
        end

        persist_snapshot!(snapshot)
        stored_asset
      end

      def add_relation(from:, to:, type:, source:, properties: {})
        from_asset = resolve_asset(from)
        to_asset = resolve_asset(to)
        candidate = ASRFacet::Intelligence::OAM.make_relation(
          from_id: from_asset.id,
          to_id: to_asset.id,
          type: type,
          source: source,
          properties: properties
        )

        stored_relation = nil
        snapshot = nil

        @mutex.synchronize do
          key = relation_key(candidate.from_id, candidate.to_id, candidate.type)
          stored_relation = @relation_index[key]
          if stored_relation.nil?
            stored_relation = candidate
            @relation_index[key] = stored_relation
            @relations << stored_relation
          else
            stored_relation = merge_relation(stored_relation, candidate)
            @relation_index[key] = stored_relation
            replace_relation!(key, stored_relation)
          end
          snapshot = build_snapshot
        end

        persist_snapshot!(snapshot)
        stored_relation
      end

      def find_by_value(type, value)
        @assets_by_key[asset_key(type, normalize_lookup_value(type, value))]
      rescue ASRFacet::ParseError
        nil
      end

      def find_by_type(type)
        normalized = type.to_sym
        @assets_by_id.values.select { |asset| asset.type == normalized }.sort_by { |asset| asset.value.to_s }
      rescue NoMethodError
        []
      end

      def neighbors(asset)
        pivot = resolve_asset(asset)
        ids = relations_for(pivot).flat_map do |relation|
          relation.from_id == pivot.id ? relation.to_id : relation.from_id
        end.uniq
        ids.filter_map { |id| @assets_by_id[id] }.sort_by { |entry| [entry.type.to_s, entry.value.to_s] }
      rescue ASRFacet::ParseError
        []
      end

      def relations_for(asset)
        pivot = resolve_asset(asset)
        @relations.select { |relation| relation.from_id == pivot.id || relation.to_id == pivot.id }
      rescue ASRFacet::ParseError
        []
      end

      def nodes
        @assets_by_id.values.map(&:to_h).sort_by { |asset| [asset[:type].to_s, asset[:value].to_s] }
      end

      def edges
        @relations.map(&:to_h).sort_by { |relation| [relation[:type].to_s, relation[:from_id].to_s, relation[:to_id].to_s] }
      end

      def stats
        type_counts = Hash.new(0)
        relation_counts = Hash.new(0)
        @assets_by_id.values.each { |asset| type_counts[asset.type] += 1 }
        @relations.each { |relation| relation_counts[relation.type] += 1 }

        {
          target: target,
          asset_count: @assets_by_id.size,
          relation_count: @relations.size,
          asset_types: type_counts.sort.to_h,
          relation_types: relation_counts.sort.to_h
        }
      end

      def to_h
        build_snapshot
      end

      def load_from_disk
        return self unless File.file?(graph_path)

        payload = JSON.parse(File.read(graph_path), symbolize_names: true)
        assets = Array(payload[:nodes]).map { |entry| hydrate_asset(entry) }
        relations = Array(payload[:edges]).map { |entry| hydrate_relation(entry) }

        @mutex.synchronize do
          @assets_by_key.clear
          @assets_by_id.clear
          @relations.clear
          @relation_index.clear

          assets.each do |asset|
            @assets_by_key[asset_key(asset.type, asset.value)] = asset
            @assets_by_id[asset.id] = asset
          end

          relations.each do |relation|
            key = relation_key(relation.from_id, relation.to_id, relation.type)
            @relation_index[key] = relation
            @relations << relation
          end
        end
        self
      rescue JSON::ParserError => e
        raise ASRFacet::ParseError, "Unable to parse asset graph: #{e.message}"
      rescue Errno::EACCES, Errno::ENOENT, IOError, SystemCallError => e
        raise ASRFacet::Error, e.message
      end

      def persist_async
        snapshot = @mutex.synchronize { build_snapshot }
        Thread.new do
          Thread.current.abort_on_exception = false
          persist_snapshot!(snapshot)
        rescue Errno::EACCES, Errno::ENOENT, IOError, SystemCallError
          nil
        end
      end

      def graph_path
        File.join(workspace_path, "graph.json")
      end

      private

      def workspace_path
        File.join(root, safe_target)
      end

      def safe_target
        cleaned = target.downcase.gsub(/[^a-z0-9.\-_]+/, "_").tr(".", "_")
        cleaned.empty? ? "workspace" : cleaned
      end

      def normalize_asset(asset)
        case asset
        when ASRFacet::Intelligence::OpenAssetModel::Asset
          asset
        when Hash
          ASRFacet::Intelligence::OpenAssetModel::Asset.new(
            id: asset[:id] || asset["id"] || ASRFacet::Intelligence::OAM.asset_id((asset[:type] || asset["type"]).to_sym, asset[:value] || asset["value"]),
            type: (asset[:type] || asset["type"]).to_sym,
            value: asset[:value] || asset["value"],
            properties: symbolize_hash(asset[:properties] || asset["properties"]),
            found_at: (asset[:found_at] || asset["found_at"] || Time.now.utc.iso8601).to_s,
            source: (asset[:source] || asset["source"]).to_s,
            confidence: (asset[:confidence] || asset["confidence"] || 1.0).to_f
          )
        else
          raise ASRFacet::ParseError, "Unsupported asset value: #{asset.inspect}"
        end
      end

      def resolve_asset(value)
        return value if value.is_a?(ASRFacet::Intelligence::OpenAssetModel::Asset)

        if value.is_a?(Hash)
          existing = find_by_value(value[:type] || value["type"], value[:value] || value["value"])
          return existing unless existing.nil?

          return add_asset(normalize_asset(value))
        end

        raise ASRFacet::ParseError, "Unable to resolve asset: #{value.inspect}"
      end

      def normalize_lookup_value(type, value)
        type = type.to_sym
        ASRFacet::Intelligence::OAM.send(:normalize_value, type, value)
      end

      def asset_key(type, value)
        "#{type}:#{value}"
      end

      def relation_key(from_id, to_id, type)
        "#{from_id}:#{type}:#{to_id}"
      end

      def merge_asset(existing, incoming)
        merged_properties = deep_merge(existing.properties || {}, incoming.properties || {})
        merged_properties[:sources] = compact_sources(existing, incoming)

        ASRFacet::Intelligence::OpenAssetModel::Asset.new(
          id: existing.id,
          type: existing.type,
          value: existing.value,
          properties: merged_properties,
          found_at: earliest_timestamp(existing.found_at, incoming.found_at),
          source: existing.source.to_s.empty? ? incoming.source.to_s : existing.source.to_s,
          confidence: [existing.confidence.to_f, incoming.confidence.to_f].max
        )
      end

      def merge_relation(existing, incoming)
        merged_properties = deep_merge(existing.properties || {}, incoming.properties || {})
        merged_properties[:sources] = compact_sources(existing, incoming)

        ASRFacet::Intelligence::OpenAssetModel::Relation.new(
          from_id: existing.from_id,
          to_id: existing.to_id,
          type: existing.type,
          properties: merged_properties,
          found_at: earliest_timestamp(existing.found_at, incoming.found_at),
          source: existing.source.to_s.empty? ? incoming.source.to_s : existing.source.to_s
        )
      end

      def replace_relation!(key, relation)
        index = @relations.find_index do |entry|
          relation_key(entry.from_id, entry.to_id, entry.type) == key
        end
        @relations[index] = relation unless index.nil?
      end

      def build_snapshot
        {
          target: target,
          nodes: nodes,
          edges: edges,
          stats: stats,
          persisted_at: Time.now.utc.iso8601
        }
      end

      def persist_snapshot!(snapshot)
        @persist_mutex.synchronize do
          FileUtils.mkdir_p(workspace_path)
          File.write(graph_path, JSON.pretty_generate(snapshot))
        end
      rescue Errno::EACCES, Errno::ENOENT, IOError, SystemCallError => e
        raise ASRFacet::Error, e.message
      end

      def hydrate_asset(entry)
        ASRFacet::Intelligence::OpenAssetModel::Asset.new(
          id: entry[:id].to_s,
          type: entry[:type].to_sym,
          value: entry[:value],
          properties: symbolize_hash(entry[:properties]),
          found_at: entry[:found_at].to_s,
          source: entry[:source].to_s,
          confidence: entry[:confidence].to_f
        )
      end

      def hydrate_relation(entry)
        ASRFacet::Intelligence::OpenAssetModel::Relation.new(
          from_id: entry[:from_id].to_s,
          to_id: entry[:to_id].to_s,
          type: entry[:type].to_sym,
          properties: symbolize_hash(entry[:properties]),
          found_at: entry[:found_at].to_s,
          source: entry[:source].to_s
        )
      end

      def symbolize_hash(value)
        case value
        when Hash
          value.each_with_object({}) do |(key, nested), memo|
            memo[key.to_sym] = symbolize_hash(nested)
          end
        when Array
          value.map { |entry| symbolize_hash(entry) }
        else
          value
        end
      end

      def deep_merge(left, right)
        symbolize_hash(left).merge(symbolize_hash(right)) do |_key, old_value, new_value|
          if old_value.is_a?(Hash) && new_value.is_a?(Hash)
            deep_merge(old_value, new_value)
          elsif old_value.is_a?(Array) || new_value.is_a?(Array)
            (Array(old_value) + Array(new_value)).uniq
          else
            new_value
          end
        end
      end

      def compact_sources(existing, incoming)
        ([existing.source] + [incoming.source] + Array(existing.properties.to_h[:sources]) + Array(incoming.properties.to_h[:sources]))
          .map(&:to_s)
          .reject { |value| value.empty? }
          .uniq
      end

      def earliest_timestamp(*values)
        values.map(&:to_s).reject { |value| value.empty? }.min.to_s
      end
    end
  end
end
