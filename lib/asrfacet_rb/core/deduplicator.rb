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

require "set"

module ASRFacet
  module Core
    class Deduplicator
      def initialize
        @seen = Hash.new { |hash, key| hash[key] = Set.new }
        @mutex = Mutex.new
      rescue StandardError
        @seen = {}
        @mutex = Mutex.new
      end

      def first_time?(scope, value)
        key = normalize(scope)
        fingerprint = fingerprint(value)
        return false if key.empty? || fingerprint.nil?

        @mutex.synchronize do
          scope_set = (@seen[key] ||= Set.new)
          return false if scope_set.include?(fingerprint)

          scope_set.add(fingerprint)
          true
        end
      rescue StandardError
        true
      end

      def seen?(scope, value)
        key = normalize(scope)
        fingerprint = fingerprint(value)
        return false if key.empty? || fingerprint.nil?

        @mutex.synchronize { (@seen[key] || Set.new).include?(fingerprint) }
      rescue StandardError
        false
      end

      def stats
        @mutex.synchronize do
          @seen.each_with_object({}) do |(scope, values), memo|
            memo[scope] = values.size
          end
        end
      rescue StandardError
        {}
      end

      private

      def normalize(value)
        value.to_s.strip.downcase
      rescue StandardError
        ""
      end

      def fingerprint(value)
        case value
        when Hash
          value.keys.sort.each_with_object({}) do |key, memo|
            memo[normalize(key)] = fingerprint(value[key])
          end
        when Array
          value.map { |entry| fingerprint(entry) }
        when String
          value.strip.downcase
        else
          value
        end
      rescue StandardError
        value.to_s
      end
    end
  end
end
