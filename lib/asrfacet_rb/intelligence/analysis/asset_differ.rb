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

module ASRFacet
  module Intelligence
    module Analysis
      class AssetDiffer
        def diff(previous_graph, current_graph)
          previous = normalize_graph(previous_graph)
          current = normalize_graph(current_graph)

          previous_assets = index_by_id(previous[:nodes])
          current_assets = index_by_id(current[:nodes])
          previous_relations = index_relations(previous[:edges])
          current_relations = index_relations(current[:edges])

          new_assets = (current_assets.keys - previous_assets.keys).sort.map { |id| current_assets[id] }
          removed_assets = (previous_assets.keys - current_assets.keys).sort.map { |id| previous_assets[id] }
          changed_assets = (current_assets.keys & previous_assets.keys).sort.filter_map do |id|
            before = previous_assets[id]
            after = current_assets[id]
            changes = hash_changes(before, after)
            next if changes.empty?

            { before: before, after: after, changes: changes }
          end
          new_relations = (current_relations.keys - previous_relations.keys).sort.map { |key| current_relations[key] }

          {
            new_assets: new_assets,
            removed_assets: removed_assets,
            changed_assets: changed_assets,
            new_relations: new_relations,
            summary: {
              added: new_assets.size,
              removed: removed_assets.size,
              changed: changed_assets.size
            }
          }
        end

        private

        def normalize_graph(graph)
          data = graph.respond_to?(:to_h) ? graph.to_h : graph
          symbolize_keys(data || {}).tap do |normalized|
            normalized[:nodes] ||= []
            normalized[:edges] ||= []
          end
        end

        def index_by_id(rows)
          Array(rows).each_with_object({}) do |row, memo|
            memo[row[:id].to_s] = row
          end
        end

        def index_relations(rows)
          Array(rows).each_with_object({}) do |row, memo|
            key = relation_key(row)
            memo[key] = row
          end
        end

        def relation_key(row)
          [
            row[:from_id] || row[:from],
            row[:to_id] || row[:to],
            row[:type] || row[:relation] || row[:rel]
          ].map(&:to_s).join(":")
        end

        def hash_changes(before, after)
          keys = (before.keys + after.keys).uniq
          keys.each_with_object({}) do |key, memo|
            next if before[key] == after[key]

            memo[key] = { before: before[key], after: after[key] }
          end
        end

        def symbolize_keys(value)
          case value
          when Hash
            value.each_with_object({}) do |(key, nested), memo|
              memo[key.to_sym] = symbolize_keys(nested)
            end
          when Array
            value.map { |entry| symbolize_keys(entry) }
          else
            value
          end
        end
      end
    end
  end
end
