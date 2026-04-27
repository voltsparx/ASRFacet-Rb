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
    class CertificateAtlasPlugin < Base
      priority 30
      plugin_family :session
      plugin_name "certificate_atlas"
      category "tls"
      description "Highlights SAN pivots, issuer reuse, and certificate coverage."
      modes :scan, :enum, :intel, :dns

      def apply(context)
        store = context[:store]
        return context if store.nil?

        certs = Array(store.all(:certs))
        return context if certs.empty?

        atlas = certs.map do |entry|
          sans = Array(entry[:sans]).map(&:to_s).reject(&:empty?).uniq.sort
          {
            host: entry[:host].to_s,
            common_name: entry[:cn].to_s,
            issuer: entry[:issuer].to_s,
            san_count: sans.count,
            sans: sans
          }
        end
        store.replace(:certificate_atlas, atlas)

        atlas.select { |entry| entry[:san_count] >= 3 }.each do |entry|
          store.add(
            :findings,
            {
              severity: :medium,
              host: entry[:host],
              title: "Certificate SAN pivot surface",
              detail: "#{entry[:san_count]} SAN entries observed under issuer #{entry[:issuer]}"
            }
          )
        end
        context
      rescue StandardError => e
        raise ASRFacet::PluginError, e.message
      end
    end
  end
end
