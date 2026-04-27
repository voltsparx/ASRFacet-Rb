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

require "ipaddr"

module ASRFacet
  module Filters
    class PrivateLeakFilter < Base
      priority 40
      filter_name "private_leak"
      category "exposure"
      description "Extracts internal-addressing indicators into dedicated categories."
      modes :scan, :dns, :enum, :intel

      def apply(context)
        store = context[:store]
        return context if store.nil?

        private_ips = Array(store.all(:ips)).select { |ip| private_ip?(ip) }
        store.replace(:private_ips, private_ips)
        private_findings = Array(store.all(:findings)).select do |entry|
          entry[:host].to_s.match?(/\A(?:10\.|172\.(?:1[6-9]|2\d|3[0-1])\.|192\.168\.)/)
        end
        store.replace(:private_surface_findings, private_findings)
        context
      rescue StandardError => e
        raise ASRFacet::PluginError, e.message
      end

      private

      def private_ip?(ip)
        IPAddr.new(ip.to_s).private?
      rescue StandardError
        false
      end
    end
  end
end
