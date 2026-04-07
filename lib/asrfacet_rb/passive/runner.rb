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
require "thread"

module ASRFacet
  module Passive
    class Runner
      SOURCES = [
        CrtSh,
        HackerTarget,
        Wayback,
        RapidDNS,
        AlienVault,
        Shodan,
        ThreatCrowd,
        BufferOver
      ].freeze

      def initialize(domain, api_keys = {}, options = {})
        @domain = domain.to_s.downcase
        @api_keys = api_keys || {}
        @options = options || {}
        @results = Set.new
        @errors = []
        @mutex = Mutex.new
        @breakers = {}
      end

      def run
        threads = SOURCES.map do |source_class|
          Thread.new do
            source = source_class.new
            breaker = breaker_for(source)
            breaker.call do
              found = source.run(@domain, @api_keys)
              @mutex.synchronize do
                found.each { |entry| @results << entry }
              end
            end
          rescue ASRFacet::Core::CircuitBreaker::CircuitOpenError
            @mutex.synchronize do
              @errors << "#{source.name}: circuit open — skipped (rate limited)"
            end
          rescue StandardError => e
            breaker&.record_failure rescue nil
            @mutex.synchronize do
              @errors << "#{source_class.name.split('::').last}: #{e.message}"
            end
          end
        end

        threads.each do |thread|
          thread.join
        rescue StandardError
          nil
        end

        {
          subdomains: @results.to_a.sort,
          errors: @errors,
          source_count: SOURCES.size
        }
      rescue StandardError
        { subdomains: [], errors: [], source_count: SOURCES.size }
      end

      private

      def breaker_for(source)
        key = source.name.to_s
        @mutex.synchronize do
          @breakers[key] ||= ASRFacet::Core::CircuitBreaker.new(key)
        end
      rescue StandardError
        ASRFacet::Core::CircuitBreaker.new(source.name.to_s)
      end
    end
  end
end
