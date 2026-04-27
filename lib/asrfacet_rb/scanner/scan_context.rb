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
    class ScanContext
      attr_reader :timing, :logger, :terminal, :probe_db, :tcp_prober,
                  :udp_prober, :icmp_prober, :version_detector, :fingerprint_engine

      def initialize(timing:, logger:, probe_db:, tcp_prober:, udp_prober:, icmp_prober:, version_detector:, fingerprint_engine:, terminal: nil)
        @timing = timing
        @logger = logger
        @terminal = terminal
        @probe_db = probe_db
        @tcp_prober = tcp_prober
        @udp_prober = udp_prober
        @icmp_prober = icmp_prober
        @version_detector = version_detector
        @fingerprint_engine = fingerprint_engine
      end
    end
  end
end
