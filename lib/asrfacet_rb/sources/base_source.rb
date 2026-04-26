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
require "net/http"
require "uri"

module ASRFacet
  module Sources
    class BaseSource
      attr_reader :name

      def initialize(rate_limiter: nil, key_store: nil, logger: nil)
        @rate_limiter = rate_limiter
        @key_store = key_store
        @logger = logger
      end

      def fetch(_domain)
        raise NotImplementedError
      end

      def api_key
        @key_store&.get(name)
      end

      def requires_key?
        false
      end

      def available?
        !requires_key? || !api_key.nil?
      end

      protected

      def throttle
        @rate_limiter&.throttle(name)
      end

      def get_json(url, headers: {}, timeout: 10)
        throttle
        uri = URI(url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == "https"
        http.read_timeout = timeout
        http.open_timeout = timeout

        req = Net::HTTP::Get.new(uri)
        req["User-Agent"] = "ASRFacet-Rb/2.0"
        headers.each { |key, value| req[key] = value }

        response = http.request(req)
        return nil unless response.code.to_i == 200

        JSON.parse(response.body)
      rescue JSON::ParserError => e
        @logger&.warn(event: :source_fetch_error, source: name, error: e.message)
        nil
      rescue Net::OpenTimeout, Net::ReadTimeout, Errno::ECONNREFUSED, SocketError => e
        @logger&.warn(event: :source_fetch_error, source: name, error: e.message)
        nil
      end

      def get_text(url, headers: {}, timeout: 10)
        throttle
        uri = URI(url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == "https"
        http.read_timeout = timeout
        http.open_timeout = timeout

        req = Net::HTTP::Get.new(uri)
        req["User-Agent"] = "ASRFacet-Rb/2.0"
        headers.each { |key, value| req[key] = value }

        response = http.request(req)
        response.code.to_i == 200 ? response.body : nil
      rescue Net::OpenTimeout, Net::ReadTimeout, Errno::ECONNREFUSED, SocketError => e
        @logger&.warn(event: :source_fetch_error, source: name, error: e.message)
        nil
      end

      def extract_subdomains(text, domain)
        return [] if text.nil?

        pattern = /(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+#{Regexp.escape(domain)}/i
        text.scan(pattern).map(&:downcase).uniq
      end
    end
  end
end
