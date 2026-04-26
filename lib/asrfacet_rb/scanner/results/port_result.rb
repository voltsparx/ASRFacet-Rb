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
        attr_accessor :port, :proto, :state, :service, :version, :extra, :cpe, :banner, :rtt, :retries

        def initialize(port:, proto:, state:, service: nil, version: nil, extra: nil, cpe: nil, banner: nil, rtt: nil, retries: 0)
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
            retries: retries
          }
        end
      end
    end
  end
end
