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
  module Extensions
    class AttachableCatalog
      class << self
        def parse_selection(selection)
          Array(selection.to_s.split(",")).map { |entry| entry.to_s.strip.downcase }.reject(&:empty?).each_with_object([[], []]) do |entry, memo|
            if entry.start_with?("-", "!")
              memo[1] << entry.sub(/\A[-!]+/, "")
            else
              memo[0] << entry
            end
          end
        rescue StandardError
          [[], []]
        end

        def filter(catalog, mode: nil, category: nil, search: nil)
          normalized_mode = normalize_text(mode)
          normalized_category = normalize_text(category)
          normalized_search = normalize_text(search)
          Array(catalog).select do |entry|
            metadata = symbolize(entry)
            next false if !normalized_mode.empty? && !Array(metadata[:modes]).map { |value| normalize_text(value) }.include?(normalized_mode)
            next false if !normalized_category.empty? && normalize_text(metadata[:category]) != normalized_category
            next true if normalized_search.empty?

            haystack = [
              metadata[:name],
              metadata[:title],
              metadata[:description],
              Array(metadata[:aliases]).join(" "),
              Array(metadata[:tags]).join(" ")
            ].join(" ").downcase
            haystack.include?(normalized_search)
          end
        rescue StandardError
          []
        end

        def resolve(catalog, selection:, mode: nil, category: nil, search: nil)
          available = filter(catalog, mode: mode, category: category, search: search)
          include_tokens, exclude_tokens = parse_selection(selection)
          selected, unknown = resolve_tokens(available, include_tokens)
          excluded, excluded_unknown = resolve_tokens(available, exclude_tokens)
          selected = available if include_tokens.include?("all")
          selected = selected.reject { |entry| excluded.any? { |blocked| blocked[:name].to_s == entry[:name].to_s } }
          {
            available: available,
            selected: dedupe(selected),
            excluded: dedupe(excluded),
            unknown: (unknown + excluded_unknown).uniq,
            include_tokens: include_tokens,
            exclude_tokens: exclude_tokens
          }
        rescue StandardError
          { available: [], selected: [], excluded: [], unknown: [], include_tokens: [], exclude_tokens: [] }
        end

        def selector_help
          [
            "all",
            "name1,name2",
            "category:<name>",
            "mode:<mode>",
            "tag:<name>",
            "-name_to_disable"
          ]
        rescue StandardError
          []
        end

        private

        def resolve_tokens(catalog, tokens)
          selected = []
          unknown = []
          Array(tokens).each do |token|
            if token == "all"
              selected.concat(Array(catalog))
              next
            end

            matches = Array(catalog).select { |entry| token_matches?(symbolize(entry), token) }
            if matches.empty?
              unknown << token
            else
              selected.concat(matches)
            end
          end
          [dedupe(selected), unknown.uniq]
        rescue StandardError
          [[], Array(tokens)]
        end

        def token_matches?(entry, token)
          normalized = normalize_text(token)
          return true if normalized == normalize_text(entry[:name])
          return true if Array(entry[:aliases]).map { |value| normalize_text(value) }.include?(normalized)
          return true if normalized == "category:#{normalize_text(entry[:category])}"
          return true if normalized.start_with?("mode:") && Array(entry[:modes]).map { |value| normalize_text(value) }.include?(normalized.delete_prefix("mode:"))
          return true if normalized.start_with?("tag:") && Array(entry[:tags]).map { |value| normalize_text(value) }.include?(normalized.delete_prefix("tag:"))

          false
        rescue StandardError
          false
        end

        def normalize_text(value)
          value.to_s.strip.downcase
        rescue StandardError
          ""
        end

        def dedupe(entries)
          Array(entries).each_with_object([]) do |entry, memo|
            metadata = symbolize(entry)
            memo << metadata unless memo.any? { |existing| existing[:name].to_s == metadata[:name].to_s }
          end
        rescue StandardError
          []
        end

        def symbolize(value)
          case value
          when Hash
            value.each_with_object({}) do |(key, nested), memo|
              memo[key.to_sym] = symbolize(nested)
            end
          when Array
            value.map { |entry| symbolize(entry) }
          else
            value
          end
        rescue StandardError
          {}
        end
      end
    end
  end
end
