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
  module Filters
    class ScopeGuardFilter < Base
      priority 10
      filter_name "scope_guard"
      category "scope"
      description "Keeps results aligned with the configured scope."
      modes :scan, :passive, :dns, :ports, :portscan, :enum, :intel

      def apply(context)
        store = context[:store]
        scope = context[:scope]
        return context if store.nil? || scope.nil?

        store.replace(:subdomains, Array(store.all(:subdomains)).select { |host| scope.in_scope?(host) })
        store.replace(:ips, Array(store.all(:ips)).select { |ip| scope.in_scope?(ip) })
        store.replace(:open_ports, Array(store.all(:open_ports)).select { |entry| scope.in_scope?(entry[:host]) })
        store.replace(:findings, Array(store.all(:findings)).select { |entry| entry[:host].to_s.empty? || scope.in_scope?(entry[:host]) })
        context
      rescue StandardError => e
        raise ASRFacet::PluginError, e.message
      end
    end
  end
end
