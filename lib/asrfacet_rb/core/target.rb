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

require "resolv"

module ASRFacet
  module Core
    class Target
      attr_reader :domain, :ip

      def initialize(input)
        @domain = input.to_s.strip.downcase.sub(%r{\Ahttps?://}, "").sub(%r{/+\z}, "")
        @cache = {}
        @client = ASRFacet::HTTP::RetryableClient.new
        @ip = resolve_ip
      rescue StandardError
        @domain = input.to_s.strip.downcase
        @cache = {}
        @client = ASRFacet::HTTP::RetryableClient.new
        @ip = nil
      end

      def url(path = "")
        sanitized = path.to_s.strip.sub(%r{\A/+}, "")
        return "https://#{@domain}" if sanitized.empty?

        "https://#{@domain}/#{sanitized}".gsub(%r{(?<!:)//+}, "/")
      rescue StandardError
        "https://#{@domain}"
      end

      def get(path = "", headers: {})
        full_url = url(path)
        cache_key = [full_url, headers.to_a.sort].hash
        return @cache[cache_key] if @cache.key?(cache_key)

        @cache[cache_key] = @client.get(full_url, headers: headers)
      rescue StandardError
        nil
      end

      def homepage
        @homepage ||= get("")
      rescue StandardError
        nil
      end

      def alive?
        !homepage.nil?
      rescue StandardError
        false
      end

      def redirects_to_https?
        response = ASRFacet::HTTP::RetryableClient.new(follow_redirects: false).get("http://#{@domain}")
        response && response.code.to_i.between?(300, 399) && response["location"].to_s.start_with?("https://")
      rescue StandardError
        false
      end

      private

      def resolve_ip
        Resolv.getaddress(@domain)
      rescue StandardError
        nil
      end
    end
  end
end
