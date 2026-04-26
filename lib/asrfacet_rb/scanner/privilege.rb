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

require "rbconfig"

module ASRFacet
  module Scanner
    module Privilege
      RAW_SCAN_TYPES = %i[syn ack fin null xmas window maimon].freeze
      ELEVATION_MARKER = "ASRFACET_RB_ELEVATED_RELAUNCH".freeze

      module_function

      def raw_scan_type?(scan_type)
        RAW_SCAN_TYPES.include?(scan_type.to_sym)
      rescue StandardError
        false
      end

      def elevated?
        ASRFacet::Scanner::Platform.elevated?
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

      def maybe_relaunch!(scan_type:, tcp_prober:, argv:, requested: false)
        return false unless requested
        return false unless raw_scan_type?(scan_type)
        return false unless raw_socket_capable?(tcp_prober)
        return false if elevated?
        raise ASRFacet::ScanError, elevation_loop_message(scan_type) if ENV[ELEVATION_MARKER] == "1"
        raise ASRFacet::ScanError, unsupported_elevation_message(scan_type) unless ASRFacet::Scanner::Platform.elevation_supported?

        relaunch_with_elevation!(Array(argv))
        true
      end

      def unsupported_message(scan_type)
        "#{scan_type} scans need a raw-capable TCP prober backend such as Nping. " \
          "On #{ASRFacet::Scanner::Platform.host_label}, raw scans require #{ASRFacet::Scanner::Platform.raw_backend_requirements}."
      rescue StandardError
        "This scan type needs a raw-capable TCP prober and elevated privileges."
      end

      def privilege_message(scan_type)
        "#{scan_type} scans need elevated privileges. Re-run with #{ASRFacet::Scanner::Platform.privilege_label} on #{ASRFacet::Scanner::Platform.host_label}, or pass --sudo so ASRFacet-Rb can relaunch itself."
      rescue StandardError
        "This scan type needs elevated privileges."
      end

      def relaunch_with_elevation!(argv)
        return relaunch_windows!(argv) if ASRFacet::Scanner::Platform.windows?

        relaunch_posix!(argv)
      end

      def relaunch_posix!(argv)
        ENV[ELEVATION_MARKER] = "1"
        exec("sudo", "-E", RbConfig.ruby, File.expand_path($PROGRAM_NAME), *argv)
      rescue SystemCallError => e
        raise ASRFacet::ScanError, "Unable to relaunch with sudo: #{e.message}"
      end

      def relaunch_windows!(argv)
        ENV[ELEVATION_MARKER] = "1"
        script_path = File.expand_path($PROGRAM_NAME)
        ruby_path = RbConfig.ruby
        ruby_literal = powershell_literal(ruby_path)
        argument_items = ([script_path] + Array(argv)).map { |item| powershell_literal(item) }.join(", ")
        command = "$proc = Start-Process -Verb RunAs -FilePath #{ruby_literal} -ArgumentList @(" \
                  "#{argument_items}) -Wait -PassThru; exit $proc.ExitCode"
        system("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command)
        exit($?.respond_to?(:exitstatus) ? $?.exitstatus.to_i : 0)
      rescue SystemCallError => e
        raise ASRFacet::ScanError, "Unable to relaunch with Administrator privileges: #{e.message}"
      end

      def powershell_literal(text)
        "'#{text.to_s.gsub("'", "''")}'"
      rescue StandardError
        "''"
      end

      def unsupported_elevation_message(scan_type)
        "#{scan_type} scans need elevation, but this host does not have an available #{ASRFacet::Scanner::Platform.privilege_label} workflow."
      rescue StandardError
        "This scan type needs elevation, but no supported elevation workflow is available."
      end

      def elevation_loop_message(scan_type)
        "#{scan_type} scan relaunch already attempted, but the elevated process still does not have usable raw-scan privileges."
      rescue StandardError
        "An elevated relaunch was already attempted."
      end
    end
  end
end
