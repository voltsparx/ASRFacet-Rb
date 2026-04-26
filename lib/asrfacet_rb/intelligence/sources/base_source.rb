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
require "uri"

module ASRFacet
  module Intelligence
    module Sources
      class BaseSource
        SUBRE = "(([a-zA-Z0-9]{1}|[_a-zA-Z0-9]{1}[_a-zA-Z0-9-]{0,61}[a-zA-Z0-9]{1})[.]{1})+".freeze

        def initialize(rate_limiter:, key_store:, logger:, http_client: ASRFacet::HTTP::RetryableClient.new)
          @rate_limiter = rate_limiter
          @key_store = key_store
          @logger = logger
          @http_client = http_client
        end

        def fetch(_domain)
          raise NotImplementedError, "#{self.class} must implement #fetch"
        end

        def name
          raise NotImplementedError, "#{self.class} must implement #name"
        end

        def requires_key?
          false
        end

        def available?
          !requires_key? || !api_key.to_s.empty?
        end

        def api_key
          @key_store&.get(name)
        rescue ASRFacet::KeyStoreError
          nil
        end

        protected

        def throttle
          @rate_limiter&.throttle(name)
        rescue ASRFacet::RateLimitError => e
          log_warning(e.message)
          nil
        end

        def get_json(url, headers: {}, timeout: 10, opts: {})
          response = perform_request(url, headers: headers, timeout: timeout, opts: opts)
          return nil if response.nil?

          JSON.parse(response.body.to_s)
        rescue JSON::ParserError => e
          log_warning("JSON parse failed for #{name}: #{e.message}")
          nil
        end

        def get_text(url, headers: {}, timeout: 10, opts: {})
          response = perform_request(url, headers: headers, timeout: timeout, opts: opts)
          response&.body.to_s
        end

        def extract_subdomains(text, domain)
          return [] if text.nil?

          normalized_domain = domain.to_s.downcase
          regex = /(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+#{Regexp.escape(normalized_domain)}/i
          text.to_s.scan(regex)
              .map { |entry| entry.to_s.downcase }
              .select { |entry| entry == normalized_domain || entry.end_with?(".#{normalized_domain}") }
              .uniq
        end

        def log_warning(message)
          if @logger&.respond_to?(:warn)
            @logger.warn(message)
          elsif @logger&.respond_to?(:print_warning)
            @logger.print_warning(message)
          end
        rescue StandardError
          nil
        end

        def normalize_results(values, domain)
          normalized_domain = domain.to_s.downcase
          Array(values).flat_map { |entry| entry.to_s.split(/[\s,|]+/) }
                       .map { |entry| entry.strip.downcase }
                       .reject(&:empty?)
                       .select { |entry| entry == normalized_domain || entry.end_with?(".#{normalized_domain}") }
                       .uniq
                       .sort
        end

        private

        def perform_request(url, headers:, timeout:, opts:)
          throttle
          response = @http_client.get(url, headers: headers, timeout: timeout, opts: opts)
          return nil if response.nil?
          return response if response.code.to_i.between?(200, 299)

          log_warning("Non-success response from #{name}: HTTP #{response.code}")
          nil
        rescue StandardError => e
          log_warning("Request failed for #{name}: #{e.message}")
          nil
        end
      end
    end
  end
end
