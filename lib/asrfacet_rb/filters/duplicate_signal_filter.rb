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
    class DuplicateSignalFilter < Base
      priority 20
      filter_name "duplicate_signal"
      category "hygiene"
      description "Collapses duplicate findings, ports, and notes."
      modes :scan, :passive, :dns, :ports, :portscan, :enum, :intel

      def apply(context)
        store = context[:store]
        return context if store.nil?

        store.replace(:findings, uniq_by(Array(store.all(:findings))) { |entry| [entry[:host], entry[:title], entry[:severity]] })
        store.replace(:open_ports, uniq_by(Array(store.all(:open_ports))) { |entry| [entry[:host], entry[:port], entry[:service]] })
        store.replace(:attack_paths, uniq_by(Array(store.all(:attack_paths))) { |entry| entry[:path] || entry })
        context
      rescue StandardError => e
        raise ASRFacet::PluginError, e.message
      end

      private

      def uniq_by(items)
        seen = {}
        items.each_with_object([]) do |entry, memo|
          key = yield(entry)
          next if seen[key]

          seen[key] = true
          memo << entry
        end
      rescue StandardError
        items
      end
    end
  end
end
