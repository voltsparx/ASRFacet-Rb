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

module ASRFacet
  module Scanner
    module Results
      class PortResult
        RedTeamHint = Struct.new(
          :cve,
          :title,
          :severity,
          :operator_action,
          :technique,
          :tools,
          :reference,
          :affected,
          :note,
          keyword_init: true
        ) do
          def to_h
            {
              cve: cve,
              title: title,
              severity: severity,
              operator_action: operator_action,
              technique: technique,
              tools: Array(tools),
              reference: reference,
              affected: affected,
              note: note
            }
          end
        end

        attr_accessor :port, :proto, :state, :service, :version, :extra, :cpe, :banner, :rtt, :retries, :redteam_hints

        def initialize(port:, proto:, state:, service: nil, version: nil, extra: nil, cpe: nil, banner: nil, rtt: nil, retries: 0, redteam_hints: [])
          @port = port.to_i
          @proto = proto.to_sym
          @state = state.to_sym
          @service = service
          @version = version
          @extra = extra
          @cpe = cpe
          @banner = banner
          @rtt = rtt
          @retries = retries.to_i
          @redteam_hints = Array(redteam_hints)
        end

        def open?
          state == :open
        end

        def filtered?
          %i[filtered open_filtered].include?(state)
        end

        def to_h
          {
            port: port,
            proto: proto,
            state: state,
            service: service,
            version: version,
            extra: extra,
            cpe: cpe,
            banner: banner,
            rtt: rtt,
            retries: retries,
            redteam_hints: redteam_hints.map { |hint| hint.respond_to?(:to_h) ? hint.to_h : hint }
          }
        end
      end
    end
  end
end
