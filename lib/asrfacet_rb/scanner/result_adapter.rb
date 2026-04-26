# frozen_string_literal: true
# For use only on systems you own or have explicit
# written authorization to test.
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
  module Scanner
    module ResultAdapter
      module_function

      def to_payload(scan_result, target:)
        store = ASRFacet::ResultStore.new
        Array(scan_result&.host_results).each do |host_result|
          add_host_asset(store, host_result.host)
          Array(host_result.ports).each do |port_result|
            entry = {
              host: host_result.host,
              port: port_result.port,
              proto: port_result.proto,
              state: port_result.state,
              service: port_result.service,
              version: port_result.version,
              extra: port_result.extra,
              cpe: port_result.cpe,
              banner: port_result.banner,
              rtt: port_result.rtt,
              retries: port_result.retries
            }
            category = case port_result.state
                       when :open then :open_ports
                       when :closed then :closed_ports
                       else :filtered_ports
                       end
            store.add(category, entry)
          end
        end

        summary = store.summary.merge(
          hosts_total: Array(scan_result&.host_results).size,
          hosts_up: Array(scan_result&.host_results).count(&:up),
          total_open: scan_result&.total_open.to_i,
          total_filtered: scan_result&.total_filtered.to_i,
          scan_type: scan_result&.scan_type.to_s
        )

        {
          store: store,
          top_assets: [],
          summary: summary,
          scan_result: scan_result&.to_h,
          execution: { stages: [], failures: [], integrity: { status: "ok", summary: "Scanner run completed.", issues: [], recommendations: [] } },
          meta: { target: target.to_s }
        }
      end

      def add_host_asset(store, host)
        if ip_address?(host)
          store.add(:ips, host)
        else
          store.add(:subdomains, host)
        end
      rescue StandardError
        nil
      end

      def ip_address?(host)
        Resolv::IPv4::Regex.match?(host.to_s) || Resolv::IPv6::Regex.match?(host.to_s)
      rescue StandardError
        false
      end
    end
  end
end
