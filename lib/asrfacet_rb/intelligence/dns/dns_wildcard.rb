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
require "securerandom"

module ASRFacet
  module Intelligence
    module Dns
      class DnsWildcard
        attr_reader :wildcard_ips

        def initialize(resolver:, logger: nil, token_generator: nil)
          @resolver = resolver
          @logger = logger
          @token_generator = token_generator || -> { SecureRandom.alphanumeric(24).downcase }
          @wildcard_ips = Concurrent::Map.new
        end

        def detect(domain)
          target = domain.to_s.downcase
          samples = Array.new(3) { "#{@token_generator.call}.#{target}" }
          resolved_ips = samples.flat_map do |sample|
            answers_for(sample)
          end.uniq.sort

          @wildcard_ips[target] = resolved_ips
          {
            domain: target,
            wildcard: resolved_ips.any?,
            wildcard_ips: resolved_ips,
            samples: samples
          }
        end

        def wildcard?(domain)
          state = ensure_state(domain)
          state[:wildcard]
        end

        def filter(domain, fqdn)
          state = ensure_state(domain)
          return true unless state[:wildcard]

          (answers_for(fqdn) & state[:wildcard_ips]).empty?
        end

        private

        def ensure_state(domain)
          target = domain.to_s.downcase
          ips = @wildcard_ips[target]
          return { wildcard: false, wildcard_ips: [] } if ips.nil?

          { wildcard: ips.any?, wildcard_ips: ips }
        rescue StandardError
          detect(domain)
        end

        def answers_for(fqdn)
          responses = @resolver.resolve_types(fqdn, %i[a aaaa])
          responses.values.flat_map do |response|
            Array(response[:answers]).map { |answer| answer[:value].to_s }
          end.reject(&:empty?).uniq
        rescue StandardError
          []
        end
      end
    end
  end
end
