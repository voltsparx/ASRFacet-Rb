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

module ASRFacet
  module Plugins
    class ServiceClusterPlugin < Base
      priority 40
      plugin_family :session
      plugin_name "service_cluster"
      category "classification"
      description "Clusters service exposure into operator-friendly categories."
      modes :scan, :portscan, :ports, :enum

      CLUSTERS = {
        management: [22, 3389, 5900, 2375, 6443],
        web: [80, 443, 8080, 8443, 8000, 8888],
        data: [3306, 5432, 6379, 9200, 27017, 11211],
        messaging: [25, 110, 143, 993, 995],
        infrastructure: [53, 161, 389, 445]
      }.freeze

      def apply(context)
        store = context[:store]
        return context if store.nil?

        grouped = Hash.new { |hash, key| hash[key] = [] }
        Array(store.all(:open_ports)).each do |entry|
          cluster = cluster_for(entry[:port])
          grouped[cluster] << {
            host: entry[:host].to_s,
            port: entry[:port].to_i,
            service: entry[:service].to_s
          }
        end
        store.replace(:service_clusters, grouped.map { |name, entries| { name: name, entries: entries } })
        context
      rescue StandardError => e
        raise ASRFacet::PluginError, e.message
      end

      private

      def cluster_for(port)
        CLUSTERS.each do |name, ports|
          return name if ports.include?(port.to_i)
        end
        :general
      rescue StandardError
        :general
      end
    end
  end
end
