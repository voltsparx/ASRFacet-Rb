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

require "spec_helper"

RSpec.describe ASRFacet::Scanner::FingerprintEngine do
  let(:engine) { described_class.new(tcp_prober: tcp_prober) }
  let(:tcp_prober) { instance_double(ASRFacet::Scanner::Probes::TCPProber, fingerprint: nil) }

  it "classifies a Linux-like fingerprint" do
    tcp_prober = instance_double(
      ASRFacet::Scanner::Probes::TCPProber,
      fingerprint: { ttl: 58, window: 29_200, tcp_options: %i[mss sack timestamp nop window_scale], ip_id_sequence: [1, 2, 3], rst_behavior: :rst }
    )

    result = described_class.new(tcp_prober: tcp_prober).detect_os_for("example.com")

    expect(result[:os]).to eq("Linux")
    expect(result[:family]).to eq("Linux")
  end

  it "classifies a Windows-like fingerprint" do
    tcp_prober = instance_double(
      ASRFacet::Scanner::Probes::TCPProber,
      fingerprint: { ttl: 120, window: 8192, tcp_options: %i[mss nop window_scale], ip_id_sequence: [9, 10, 11], rst_behavior: :rst }
    )

    result = described_class.new(tcp_prober: tcp_prober).detect_os_for("example.com")

    expect(result[:os]).to eq("Windows")
    expect(result[:vendor]).to eq("Microsoft")
  end

  it "returns unknown when no fingerprint data is available" do
    tcp_prober = instance_double(ASRFacet::Scanner::Probes::TCPProber, fingerprint: nil)

    result = described_class.new(tcp_prober: tcp_prober).detect_os_for("example.com")

    expect(result[:os]).to eq("unknown")
    expect(result[:accuracy]).to eq(0)
  end

  it "implements the fingerprint quality gate in the source order" do
    expect(
      engine.omit_submission?(
        scan_delay: 600,
        timing_level: 3,
        open_tcp_port: 80,
        closed_tcp_port: 81,
        closed_udp_port: 53,
        distance: 1,
        max_timing_ratio: 1.0,
        incomplete: false,
        has_udp_scan: true
      )
    ).to include("greater than 500")

    expect(
      engine.omit_submission?(
        scan_delay: 0,
        timing_level: 5,
        open_tcp_port: 80,
        closed_tcp_port: 81,
        closed_udp_port: 53,
        distance: 1,
        max_timing_ratio: 1.0,
        incomplete: false,
        has_udp_scan: true
      )
    ).to eq("Timing level 5 (Insane) used")
  end

  it "exposes the expected FP scaling anchors" do
    expect(described_class::FP_SCALE[0]).to eq([-20, 0.0416667])
    expect(described_class::FP_SCALE[1]).to eq([0, 0.00520833])
    expect(described_class::FP_SCALE[2]).to eq([-64, 0.0052356])
  end

  it "quantizes TTL values into the expected buckets" do
    expect(engine.quantize_ttl(62, distance: 1)).to eq(64)
    expect(engine.quantize_ttl(127, distance: 1)).to eq(128)
    expect(engine.quantize_ttl(220, distance: nil)).to eq(-1)
  end

  it "deduplicates equivalent OS classes using vendor/family/type/generation" do
    guesses = [
      { os: "Linux", vendor: "Linux", family: "Linux", device_type: "general purpose", generation: "5.x", accuracy: 95, cpe: "cpe:/o:linux:linux_kernel:5" },
      { os: "Linux", vendor: "Linux", family: "Linux", device_type: "general purpose", generation: "5.x", accuracy: 91, cpe: "cpe:/o:linux:linux_kernel:5" },
      { os: "Windows", vendor: "Microsoft", family: "Windows", device_type: "general purpose", generation: "10", accuracy: 88, cpe: "cpe:/o:microsoft:windows_10" }
    ]

    expect(engine.deduplicate_os_classes(guesses).length).to eq(2)
  end
end
