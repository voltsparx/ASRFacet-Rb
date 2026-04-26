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

require "resolv"
require_relative "base"

module ASRFacet
  module Plugins
    class DnsEnrichPlugin < Base
      priority 10
      handles :subdomain

      def process(asset, context, bus)
        subdomain = asset[:value].to_s
        return nil if subdomain.empty?

        resolve(subdomain).each do |ip|
          context[:result_store]&.add_ip(ip)
          bus.emit(:ip_found, value: ip, source: subdomain)
        end
      rescue Resolv::ResolvError
        nil
      rescue StandardError => e
        raise ASRFacet::PluginError, e.message
      end

      private

      def resolve(host)
        Resolv.getaddresses(host)
      end
    end
  end
end
