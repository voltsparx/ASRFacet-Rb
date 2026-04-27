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
      DEFAULT_INTENSITY = 5

      def initialize(probe_db:, intensity: DEFAULT_INTENSITY, socket_factory: nil, udp_socket_class: UDPSocket)
        @probe_db = probe_db
        @intensity = [[intensity.to_i, 0].max, 9].min
        @socket_factory = socket_factory || method(:default_tcp_socket)
        @udp_socket_class = udp_socket_class
      end

      def detect(host, port, proto: :tcp)
        filtered_probes = @probe_db.probes_for(port, proto, intensity: @intensity).sort_by(&:rarity)
        filtered_probes = filtered_probes.select do |probe|
          threshold = ASRFacet::Scanner::ProbeDB::INTENSITY_THRESHOLDS.fetch(@intensity, nil)
          threshold.nil? || probe.rarity.to_i <= threshold || probe.matches_port?(port)
        end
        return nil if filtered_probes.empty?

        banner = initial_banner(host, port, proto)
        if banner
          matched = banner_match(banner, port, proto)
          return build_result(matched, banner) if matched && matched[:confidence].to_i == 10
        end

        soft_result = banner && banner_match(banner, port, proto)
        filtered_probes.each do |probe|
          response = transmit(host, port, proto, probe)
          next if response.nil?

          matched = banner_match(response, port, proto)
          return build_result(matched, response) if matched && matched[:confidence].to_i == 10
          soft_result ||= matched if matched
        end

        return build_result(soft_result, banner) if soft_result
        nil
      end

      private

      def default_tcp_socket(host, port, timeout)
        TCPSocket.new(host, port, connect_timeout: timeout)
      end

      def initial_banner(host, port, proto)
        if proto.to_sym == :udp
          transmit_udp(host, port, 2.0, "".b)
        else
          socket = @socket_factory.call(host, port, 2.0)
          readable = IO.select([socket], nil, nil, 2.0)
          return nil unless readable

          socket.readpartial(1024)
        end
      rescue EOFError
        "".b
      rescue Errno::ECONNREFUSED, Errno::ETIMEDOUT, IOError, SystemCallError
        nil
      ensure
        socket&.close
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

      def build_result(entry, response)
        {
          service: entry[:service],
          version: entry[:version],
          extra: entry[:info],
          extra_info: entry[:info],
          cpe: entry[:cpe],
          confidence: entry[:confidence].to_i,
          banner: response
        }
      end

      def banner_match(banner, port, proto)
        return @probe_db.match_banner(banner, port, proto, intensity: @intensity) if @probe_db.respond_to?(:match_banner)

        manual_match(Array(@probe_db.probes_for(port, proto, intensity: @intensity)), banner)
      rescue StandardError
        manual_match(Array(@probe_db.probes_for(port, proto, intensity: @intensity)), banner)
      end

      def manual_match(probes, banner)
        Array(probes).each do |probe|
          Array(probe.matches).each do |entry|
            regex = Regexp.new(entry[:pattern_source], Regexp::MULTILINE)
            next unless regex.match?(banner.to_s)

            metadata = entry[:metadata] || {}
            return {
              service: entry[:service],
              version: metadata[:version],
              info: [metadata[:product], metadata[:extra]].compact.join(" ").strip,
              cpe: Array(metadata[:cpes]).first,
              confidence: 10
            }
          end
        end
        nil
      rescue StandardError
        nil
      end
    end
  end
end
