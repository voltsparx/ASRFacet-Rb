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
    class FingerprintEngine
      FP_SCALE = [
        [-20, 0.0416667],
        [0, 0.00520833],
        [-64, 0.0052356],
        [-20, 0.0416667],
        [0, 0.00520833],
        [-64, 0.0052356],
        [-20, 0.05],
        [0, 0.00520833],
        [-64, 0.0052356],
        [-20, 0.0416667],
        [0, 0.00520833],
        [-64, 0.0052356],
        [-20, 0.0416667],
        [0, 0.00520833],
        [-64, 0.0052356],
        [-20, 0.05],
        [0, 0.00520833],
        [-64, 0.0052356],
        [-128, 0.0333333],
        [0, 1],
        [-64, 0.0052356],
        [-80, 0.0625],
        [0, 1],
        [-64, 0.0052356],
        [-24, 0.125],
        [0, 0.00416667],
        [-255, 1],
        [-356, 0.125],
        [0, 0.03125],
        [-64, 0.0052356],
        [-20, 0.0833333],
        [0, 0.00520833],
        [-64, 0.0052356],
        [-20, 0.0147059],
        [0, 0.00520833],
        [-64, 0.0052356],
        [-20, 0.0147059],
        [0, 0.00520833],
        [-64, 0.0052356],
        [-20, 0.030303],
        [0, 0.00520833],
        [-64, 0.0052356],
        [-20, 0.03125],
        [0, 0.00520833],
        [-64, 0.0052356],
        [-20, 0.030303],
        [0, 0.00520833],
        [-64, 0.0052356],
        [-20, 0.0147059],
        [0, 0.00520833],
        [-64, 0.0052356],
        [-562176, 1.65005e-11],
        [0, 1.5259e-05]
      ].freeze

      def initialize(tcp_prober:, timeout: 1.0)
        @tcp_prober = tcp_prober
        @timeout = timeout
      end

      def omit_submission?(scan_delay:, timing_level:, open_tcp_port:, closed_tcp_port:, closed_udp_port:, distance:, max_timing_ratio:, incomplete:, has_udp_scan:)
        return "Scan delay (#{scan_delay}) is greater than 500" if scan_delay.to_i > 500
        return "Timing level 5 (Insane) used" if timing_level.to_i > 4
        return "Missing an open TCP port so results incomplete" if open_tcp_port.to_i <= 0
        return "Missing a closed TCP port so results incomplete" if closed_tcp_port.to_i <= 0
        return format("Host distance (%d network hops) appears to be negative", distance.to_i) if distance.to_i < -1
        return format("Host distance (%d network hops) is greater than five", distance.to_i) if distance.to_i > 5
        return format("maxTimingRatio (%e) is greater than 1.4", max_timing_ratio.to_f) if max_timing_ratio.to_f > 1.4
        return "Didn't receive UDP response. Please try again with -sSU" if closed_udp_port.to_i.negative? && !has_udp_scan
        return "Some probes failed to send so results incomplete" if incomplete

        nil
      end

      def classify(responses)
        normalized = normalize_responses(responses)
        ttl = quantize_ttl(normalized[:initial_ttl] || normalized[:ttl], distance: normalized[:distance])
        window = normalized[:tcp_window].to_i
        options = Array(normalized[:tcp_options]).map(&:to_s)
        guesses = []

        if ttl == 64
          guesses << os_guess("Linux", "Linux", "Linux", "general purpose", 94, "cpe:/o:linux:linux_kernel:5", generation: "5.x")
          guesses << os_guess("Linux", "Linux", "Linux", "general purpose", 87, "cpe:/o:linux:linux_kernel:4", generation: "4.x")
        elsif ttl == 128
          guesses << os_guess("Windows", "Microsoft", "Windows", "general purpose", 90, "cpe:/o:microsoft:windows_10", generation: "10 / Server 2019")
          guesses << os_guess("Windows", "Microsoft", "Windows", "general purpose", 80, "cpe:/o:microsoft:windows_7", generation: "7 / Server 2008 R2")
        elsif ttl == 255
          guesses << os_guess("Network appliance", "Unknown", "Embedded", "network infrastructure", 72, nil)
        else
          guesses << os_guess("Unknown TCP/IP stack", "Unknown", "Unknown", "unknown", 20, nil)
        end

        guesses.first[:accuracy] += 2 if window >= 29_200
        guesses.first[:accuracy] += 1 if options.any? { |entry| entry.include?("timestamp") }
        deduplicate_os_classes(guesses).sort_by { |entry| -entry[:accuracy].to_i }
      end

      def best_guess(responses)
        classify(responses).first
      end

      def detect_os_for(target)
        fingerprint = @tcp_prober.fingerprint(host: target, timeout: @timeout)
        return unknown unless fingerprint

        best_guess(fingerprint) || unknown
      end

      def deduplicate_os_classes(guesses)
        seen = {}
        Array(guesses).each_with_object([]) do |guess, memo|
          key = [guess[:vendor], guess[:family], guess[:device_type], guess[:generation]]
          next if seen[key]

          seen[key] = true
          memo << guess
        end
      end

      def quantize_ttl(ttl, distance: nil)
        value = ttl.to_i
        er_lim = distance.nil? || distance.to_i.negative? ? 20 : 5
        return 32 if value.between?(32 - er_lim, 37)
        return 64 if value.between?(64 - er_lim, 69)
        return 128 if value.between?(128 - er_lim, 133)
        return 255 if value.between?(255 - er_lim, 260)

        -1
      end

      private

      def normalize_responses(responses)
        if responses.respond_to?(:to_h)
          responses.to_h
        else
          {}
        end
      rescue StandardError
        {}
      end

      def unknown
        {
          os: "unknown",
          vendor: "unknown",
          family: "unknown",
          generation: nil,
          device_type: "unknown",
          accuracy: 0,
          cpe: nil
        }
      end

      def os_guess(os, vendor, family, device_type, accuracy, cpe, generation: nil)
        {
          os: os,
          vendor: vendor,
          family: family,
          generation: generation || os[/(\d+(?:\.\d+)*)/, 1],
          device_type: device_type,
          accuracy: accuracy,
          cpe: cpe
        }
      end
    end
  end
end
