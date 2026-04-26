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

require "open3"
require "timeout"

module ASRFacet
  module Scanner
    module Probes
      class NpingRawAdapter
        DEFAULT_TIMEOUT_PADDING = 2
        FLAG_MAP = {
          ack: "ack",
          cwr: "cwr",
          ecn: "ecn",
          fin: "fin",
          psh: "psh",
          rst: "rst",
          syn: "syn",
          urg: "urg"
        }.freeze

        def initialize(command_path: "nping", runner: nil, platform: ASRFacet::Scanner::Platform)
          @command_path = command_path
          @runner = runner || method(:capture_command)
          @platform = platform
        end

        def raw_socket_capable?
          @platform.nping_available?
        rescue StandardError
          false
        end

        def call(host:, port:, flags:, timeout:)
          raise ASRFacet::ScanError, missing_backend_message unless raw_socket_capable?

          output, status = with_timeout(timeout) do
            @runner.call(*build_command(host: host, port: port, flags: flags))
          end
          parsed = parse_output(output)
          return parsed if status.to_i.zero? || parsed[:reply] != :timeout

          raise ASRFacet::ScanError, privilege_error_message(output) if privilege_error?(output)

          { reply: :timeout, window: 0 }
        rescue Timeout::Error
          { reply: :timeout, window: 0 }
        end

        private

        def build_command(host:, port:, flags:)
          [
            @command_path,
            "--tcp",
            "-c", "1",
            "--delay", "0",
            "--rate", "1",
            "--flags", flags_argument(flags),
            "-p", port.to_s,
            host.to_s
          ]
        end

        def flags_argument(flags)
          mapped = Array(flags).map { |flag| FLAG_MAP.fetch(flag.to_sym, flag.to_s.downcase) }
          mapped.empty? ? "0" : mapped.join(",")
        rescue StandardError
          "0"
        end

        def capture_command(*command)
          stdout, stderr, status = Open3.capture3(*command)
          ["#{stdout}\n#{stderr}", status.exitstatus.to_i]
        rescue StandardError => e
          ["#{e.class}: #{e.message}", 1]
        end

        def with_timeout(timeout)
          Timeout.timeout(timeout.to_f + DEFAULT_TIMEOUT_PADDING) { yield }
        end

        def parse_output(output)
          response_line = output.to_s.each_line.find { |line| line.start_with?("RCVD ") && line.include?(" TCP ") }
          return { reply: :timeout, window: 0 } if response_line.to_s.empty?

          elapsed = response_line[/RCVD \(([\d.]+)s\)/, 1]
          flags = response_line[/>\s+\S+\s+([A-Z]+)\b/, 1].to_s
          window = response_line[/\bwin=(\d+)/, 1].to_i
          reply = if flags.include?("S") && flags.include?("A")
                    :syn_ack
                  elsif flags.include?("R")
                    :rst
                  else
                    :unknown
                  end
          {
            reply: reply,
            window: window,
            rtt: elapsed.to_f * 1000.0,
            flags: flags
          }
        rescue StandardError
          { reply: :timeout, window: 0 }
        end

        def privilege_error?(output)
          text = output.to_s.downcase
          text.include?("requires root") ||
            text.include?("requires administrator") ||
            text.include?("not enough privileges") ||
            text.include?("privileged") ||
            text.include?("npcap")
        rescue StandardError
          false
        end

        def missing_backend_message
          "Raw TCP scanning needs Nping. Install Nping first. On #{@platform.host_label}, raw scans require #{@platform.raw_backend_requirements}."
        rescue StandardError
          "Raw TCP scanning needs Nping."
        end

        def privilege_error_message(output)
          details = output.to_s.strip
          base = "Nping is available but raw packet privileges are missing. Use #{@platform.privilege_label} on #{@platform.host_label}."
          details.empty? ? base : "#{base} Nping said: #{details}"
        rescue StandardError
          "Nping is available but raw packet privileges are missing."
        end
      end
    end
  end
end
