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
    module Privilege
      RAW_SCAN_TYPES = %i[syn ack fin null xmas window maimon].freeze

      module_function

      def raw_scan_type?(scan_type)
        RAW_SCAN_TYPES.include?(scan_type.to_sym)
      rescue StandardError
        false
      end

      def elevated?
        return false if Gem.win_platform?
        return false unless Process.respond_to?(:uid)

        Process.uid.zero?
      rescue StandardError
        false
      end

      def raw_socket_capable?(tcp_prober)
        return false unless tcp_prober.respond_to?(:raw_socket_capable?)

        tcp_prober.raw_socket_capable?
      rescue StandardError
        false
      end

      def validate!(scan_type:, tcp_prober:)
        return true unless raw_scan_type?(scan_type)

        raise ASRFacet::ScanError, unsupported_message(scan_type) unless raw_socket_capable?(tcp_prober)
        raise ASRFacet::ScanError, privilege_message(scan_type) unless elevated?

        true
      end

      def unsupported_message(scan_type)
        "#{scan_type} scans need a raw-capable TCP prober and elevated privileges. " \
          "The bundled scanner backend is connect-oriented, so sudo alone will not make #{scan_type} behave like a real raw scan."
      rescue StandardError
        "This scan type needs a raw-capable TCP prober and elevated privileges."
      end

      def privilege_message(scan_type)
        "#{scan_type} scans need elevated privileges. Re-run as root or with sudo after providing a raw-capable TCP prober backend."
      rescue StandardError
        "This scan type needs elevated privileges."
      end
    end
  end
end
