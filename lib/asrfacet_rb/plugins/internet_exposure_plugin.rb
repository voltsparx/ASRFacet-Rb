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
  module Plugins
    class InternetExposurePlugin < Base
      priority 50
      plugin_family :session
      plugin_name "internet_exposure"
      category "exposure"
      description "Flags exposed database, management, and private-leak signals."
      modes :scan, :portscan, :ports, :enum, :dns

      HIGH_VALUE_PORTS = [22, 445, 3389, 3306, 5432, 6379, 9200, 27017, 2375, 6443].freeze

      def apply(context)
        store = context[:store]
        return context if store.nil?

        Array(store.all(:ips)).each do |ip|
          next unless private_ip?(ip)

          store.add(
            :findings,
            {
              severity: :high,
              host: ip,
              title: "Private infrastructure reference exposed",
              detail: "A private IP surfaced in collected results and may indicate internal addressing or split-horizon DNS."
            }
          )
        end

        Array(store.all(:open_ports)).each do |entry|
          next unless HIGH_VALUE_PORTS.include?(entry[:port].to_i)

          store.add(
            :findings,
            {
              severity: critical_service?(entry[:port]) ? :critical : :high,
              host: entry[:host].to_s,
              title: "High-value exposed service",
              detail: "#{entry[:host]} exposes #{entry[:service].to_s.empty? ? 'unknown' : entry[:service]} on #{entry[:port]}"
            }
          )
        end
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

      def critical_service?(port)
        [3306, 5432, 6379, 9200, 27017, 2375, 6443].include?(port.to_i)
      rescue StandardError
        false
      end
    end
  end
end
