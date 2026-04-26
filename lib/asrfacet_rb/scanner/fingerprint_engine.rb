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
      def initialize(tcp_prober:, timeout: 1.0)
        @tcp_prober = tcp_prober
        @timeout = timeout
      end

      def detect_os_for(target)
        fingerprint = @tcp_prober.fingerprint(host: target, timeout: @timeout)
        return unknown unless fingerprint

        ttl = normalize_ttl(fingerprint[:ttl].to_i)
        window = fingerprint[:window].to_i
        options = Array(fingerprint[:tcp_options]).map(&:to_sym)
        rst_behavior = fingerprint[:rst_behavior].to_sym
        ip_pattern = classify_ip_id(Array(fingerprint[:ip_id_sequence]))

        if ttl <= 64
          linux_guess(window, options, ip_pattern, rst_behavior)
        elsif ttl <= 128
          windows_guess(window, options, ip_pattern, rst_behavior)
        else
          network_guess(window, options, ip_pattern, rst_behavior)
        end
      end

      private

      def unknown
        { os: "unknown", accuracy: 0, type: "unknown", vendor: "unknown", family: "unknown", cpe: nil }
      end

      def normalize_ttl(ttl)
        return 32 if ttl.positive? && ttl <= 32
        return 64 if ttl <= 64
        return 128 if ttl <= 128

        255
      end

      def classify_ip_id(sequence)
        return :unknown if sequence.length < 2

        deltas = sequence.each_cons(2).map { |left, right| right.to_i - left.to_i }
        return :incremental if deltas.all? { |delta| delta == 1 }
        return :random_positive if deltas.all?(&:positive?) && deltas.uniq.length > 1

        :randomized
      end

      def linux_guess(window, options, ip_pattern, rst_behavior)
        accuracy = 70
        accuracy += 10 if options.include?(:timestamp)
        accuracy += 5 if ip_pattern == :incremental
        accuracy += 5 if rst_behavior == :rst
        accuracy += 5 if window >= 29_200
        { os: "Linux", accuracy: accuracy, type: "general purpose", vendor: "Linux", family: "Linux", cpe: "cpe:/o:linux:linux_kernel" }
      end

      def windows_guess(window, options, ip_pattern, rst_behavior)
        accuracy = 68
        accuracy += 10 if window >= 8_192
        accuracy += 7 if options.include?(:window_scale)
        accuracy += 5 if rst_behavior == :rst
        accuracy += 5 if ip_pattern != :randomized
        { os: "Windows", accuracy: accuracy, type: "general purpose", vendor: "Microsoft", family: "Windows", cpe: "cpe:/o:microsoft:windows" }
      end

      def network_guess(window, options, ip_pattern, rst_behavior)
        accuracy = 60
        accuracy += 10 if window.zero?
        accuracy += 8 if options.include?(:mss)
        accuracy += 5 if ip_pattern == :incremental
        accuracy += 5 if rst_behavior == :rst
        { os: "Network device", accuracy: accuracy, type: "network infrastructure", vendor: "Unknown", family: "Embedded", cpe: nil }
      end
    end
  end
end
