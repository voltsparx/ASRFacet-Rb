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

require "socket"

module ASRFacet
  module Scanner
    class VersionDetector
      DEFAULT_INTENSITY = 7

      def initialize(probe_db:, intensity: DEFAULT_INTENSITY, socket_factory: nil, udp_socket_class: UDPSocket)
        @probe_db = probe_db
        @intensity = [[intensity.to_i, 0].max, 9].min
        @socket_factory = socket_factory || method(:default_tcp_socket)
        @udp_socket_class = udp_socket_class
      end

      def detect(host, port, proto: :tcp)
        soft_result = nil

        @probe_db.probes_for(port, proto).each do |probe|
          next if probe.rarity > @intensity && !probe.matches_port?(port)

          response = transmit(host, port, proto, probe)
          next if response.nil?

          full_match = detect_match(probe.matches, response)
          return build_result(full_match, response) if full_match

          soft_match = detect_match(probe.softmatches, response)
          soft_result ||= build_result(soft_match, response) if soft_match
        end

        soft_result
      end

      private

      def default_tcp_socket(host, port, timeout)
        TCPSocket.new(host, port, connect_timeout: timeout)
      end

      def transmit(host, port, proto, probe)
        timeout = probe.wait_ms.to_f / 1000.0
        return transmit_udp(host, port, timeout, probe.probe_str) if proto.to_sym == :udp

        socket = @socket_factory.call(host, port, timeout)
        socket.write(probe.probe_str) unless probe.probe_str.empty?
        readable = IO.select([socket], nil, nil, timeout)
        return "".b if probe.null_probe? && readable.nil?
        return nil if readable.nil?

        socket.readpartial(8192)
      rescue EOFError
        "".b
      rescue Errno::ECONNREFUSED, Errno::ETIMEDOUT, IOError, SystemCallError
        nil
      ensure
        socket&.close
      end

      def transmit_udp(host, port, timeout, payload)
        socket = @udp_socket_class.new
        socket.connect(host, port)
        socket.write(payload.to_s)
        readable = IO.select([socket], nil, nil, timeout)
        return nil unless readable

        socket.recvfrom_nonblock(8192).first
      rescue IO::WaitReadable, Errno::ECONNREFUSED, Errno::ETIMEDOUT, IOError, SystemCallError
        nil
      ensure
        socket&.close
      end

      def detect_match(catalog, response)
        catalog.find do |entry|
          regex = compile_regex(entry[:pattern_source], entry[:pattern_flags])
          regex && regex.match?(response)
        end&.then do |entry|
          regex = compile_regex(entry[:pattern_source], entry[:pattern_flags])
          match = regex.match(response)
          entry.merge(match_data: match)
        end
      end

      def compile_regex(pattern, flags)
        options = 0
        options |= Regexp::IGNORECASE if flags.include?("i")
        options |= Regexp::MULTILINE if flags.include?("s") || flags.include?("m")
        Regexp.new(pattern, options)
      rescue RegexpError
        nil
      end

      def build_result(entry, response)
        metadata = entry[:metadata]
        match = entry[:match_data]
        extra = [replace_captures(metadata[:product], match), replace_captures(metadata[:extra], match)].compact.join(" ").strip
        {
          service: entry[:service],
          version: replace_captures(metadata[:version], match),
          extra: extra.empty? ? nil : extra,
          cpe: Array(metadata[:cpes]).map { |value| replace_captures(value, match) }.first,
          banner: response
        }
      end

      def replace_captures(value, match)
        return nil if value.to_s.empty?

        value.gsub(/\$(\d+)/) { match[Regexp.last_match(1).to_i].to_s }
      end
    end
  end
end
