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
        BufferOver,
        ASRFacet::Sources::UrlscanSource,
        ASRFacet::Sources::CommoncrawlSource,
        ASRFacet::Sources::VirustotalSource,
        ASRFacet::Sources::SecuritytrailsSource
      ].freeze

      def initialize(domain, api_keys = {}, options = {}, rate_limiter: ASRFacet::RateLimiter.new, key_store: ASRFacet::KeyStore.new, logger: nil)
        @domain = domain.to_s.downcase
        @api_keys = api_keys || {}
        @options = options || {}
        @results = Set.new
        @errors = []
        @mutex = Mutex.new
        @breakers = {}
        @rate_limiter = rate_limiter
        @key_store = key_store
        @logger = logger
      end

      def run
        pool = ASRFacet::ThreadPool.new(SOURCES.size, queue_size: SOURCES.size, timeout: source_timeout)
        SOURCES.each do |source_class|
          pool.enqueue(label: source_class.name, metadata: { source: source_class.name }) do
            source = build_source(source_class)
            breaker = breaker_for(source)
            breaker.call do
              found = fetch_from_source(source)
              @mutex.synchronize do
                found.each { |entry| @results << entry }
              end
            end
          rescue ASRFacet::Core::CircuitBreaker::CircuitOpenError
            @mutex.synchronize do
              @errors << "#{source_class.name.split('::').last}: circuit open - skipped (rate limited)"
            end
          rescue ASRFacet::Error => e
            breaker&.record_failure
            @mutex.synchronize do
              @errors << "#{source_class.name.split('::').last}: #{e.message}"
            end
          end
        end

        pool.wait

        {
          subdomains: @results.to_a.sort,
          errors: @errors,
          source_count: SOURCES.size
        }
      rescue ASRFacet::Error
        { subdomains: [], errors: [], source_count: SOURCES.size }
      end

      private

      def build_source(source_class)
        if source_class <= ASRFacet::Sources::BaseSource
          source_class.new(rate_limiter: @rate_limiter, key_store: @key_store, logger: @logger)
        else
          source_class.new
        end
      rescue ASRFacet::KeyStoreError, ArgumentError, NameError => e
        raise ASRFacet::SourceError, e.message
      rescue Exception => e
        raise unless e.is_a?(StandardError)

        raise ASRFacet::SourceError, e.message
      end

      def fetch_from_source(source)
        if source.is_a?(ASRFacet::Sources::BaseSource)
          source.fetch(@domain)
        else
          source.run(@domain, merged_api_keys)
        end
      rescue ASRFacet::Error, ArgumentError, NoMethodError => e
        raise ASRFacet::SourceError, e.message
      rescue Exception => e
        raise unless e.is_a?(StandardError)

        raise ASRFacet::SourceError, e.message
      end

      def merged_api_keys
        @api_keys.merge(@key_store.all.transform_keys(&:to_sym))
      rescue ASRFacet::KeyStoreError
        @api_keys
      end

      def breaker_for(source)
        key = source.name.to_s
        @mutex.synchronize do
          @breakers[key] ||= ASRFacet::Core::CircuitBreaker.new(key)
        end
      rescue ASRFacet::PluginError
        ASRFacet::Core::CircuitBreaker.new(source.name.to_s)
      end

      def source_timeout
        timeout = @options[:timeout]
        timeout.to_f.positive? ? timeout.to_f : 30
      rescue ASRFacet::ParseError, NoMethodError, TypeError
        30
      end
    end
  end
end
