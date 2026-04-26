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
    module ScanTypes
      class PingScan < BaseScan
        def host_up?(target)
          return true if @context.icmp_prober.echo(host: target, timeout: rtt_timeout)
          return true if @context.tcp_prober.send_probe(host: target, port: 80, flags: %i[syn], timeout: rtt_timeout)[:reply] == :syn_ack

          @context.tcp_prober.send_probe(host: target, port: 443, flags: %i[ack], timeout: rtt_timeout)[:reply] == :rst
        end

        def probe(host, _port = nil)
          build_result(port: 0, proto: :icmp, state: host_up?(host) ? :open : :filtered, service: "host-discovery")
        end
      end
    end
  end
end
