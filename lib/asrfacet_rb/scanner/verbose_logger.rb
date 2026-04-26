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
    class VerboseLogger
      def initialize(level: 0, stream: $stdout)
        @level = [[level.to_i, 0].max, 3].min
        @stream = stream
      end

      def start_scan(targets, scan_type:, timing:, ports:)
        write(0, "Starting ASRFacet scan (#{scan_type}) against #{Array(targets).join(', ')}")
        write(1, "Timing template: #{timing.name} (T#{timing.level})")
        write(1, "Ports: #{ports.count}")
      end

      def host_up(host)
        write(1, "Host is up: #{host}")
      end

      def host_down(host)
        write(1, "Host seems down: #{host}")
      end

      def port_open(host, port_result)
        write(1, "#{host}: #{format_port(port_result)} open")
      end

      def port_closed(host, port_result)
        write(2, "#{host}: #{format_port(port_result)} closed")
      end

      def port_filtered(host, port_result)
        write(2, "#{host}: #{format_port(port_result)} #{port_result.state}")
      end

      def probe_sent(host, port, probe_name)
        write(3, "#{host}:#{port} probe sent #{probe_name}")
      end

      def probe_received(host, port, bytes)
        write(3, "#{host}:#{port} probe received #{bytes.to_i} bytes")
      end

      def scan_complete(result)
        write(0, "Scan complete in #{format('%.2f', result.elapsed || 0.0)}s")
      end

      def version_detected(host, port, version)
        write(1, "#{host}:#{port} version #{version}")
      end

      def os_detected(host, os_result)
        write(1, "#{host} OS guess: #{os_result[:os]} (#{os_result[:accuracy]}%)")
      end

      def script_result(host, script_name, output)
        write(2, "#{host} #{script_name}: #{output}")
      end

      def print_port_table(host_result)
        visible = host_result.ports.select { |entry| @level >= 2 || entry.open? || entry.state == :unfiltered }
        return if visible.empty?

        @stream.puts("PORT      STATE   SERVICE    VERSION")
        visible.sort_by(&:port).each do |entry|
          @stream.puts(
            [
              format_port(entry).ljust(10),
              entry.state.to_s.ljust(8),
              entry.service.to_s.ljust(10),
              [entry.version, entry.extra].compact.join(" ").strip
            ].join(" ")
          )
        end
      end

      def print_summary(result)
        @stream.puts("Scanned #{result.targets.count} target(s) in #{format('%.2f', result.elapsed || 0.0)}s")
        @stream.puts("Open ports: #{result.total_open}")
        @stream.puts("Filtered ports: #{result.total_filtered}")
      end

      private

      def format_port(port_result)
        "#{port_result.port}/#{port_result.proto}"
      end

      def write(required_level, message)
        return if @level < required_level

        @stream.puts(message)
      end
    end
  end
end
