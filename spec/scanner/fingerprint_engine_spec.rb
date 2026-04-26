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
end
