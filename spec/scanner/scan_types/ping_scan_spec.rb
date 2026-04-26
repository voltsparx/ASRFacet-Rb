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

RSpec.describe ASRFacet::Scanner::ScanTypes::PingScan do
  let(:timing) { ASRFacet::Scanner::Timing.get(3) }
  let(:probe_db) { instance_double(ASRFacet::Scanner::ProbeDB, service_for: "host-discovery") }

  it "returns true when ICMP succeeds" do
    context = instance_double(
      ASRFacet::Scanner::ScanContext,
      timing: timing,
      probe_db: probe_db,
      icmp_prober: instance_double(ASRFacet::Scanner::Probes::ICMPProber, echo: true),
      tcp_prober: instance_double(ASRFacet::Scanner::Probes::TCPProber)
    )

    expect(described_class.new(context).host_up?("example.com")).to be(true)
  end

  it "falls back to TCP probes when ICMP fails" do
    tcp_prober = instance_double(ASRFacet::Scanner::Probes::TCPProber)
    allow(tcp_prober).to receive(:send_probe).with(host: "example.com", port: 80, flags: %i[syn], timeout: kind_of(Float)).and_return(reply: :timeout)
    allow(tcp_prober).to receive(:send_probe).with(host: "example.com", port: 443, flags: %i[ack], timeout: kind_of(Float)).and_return(reply: :rst)
    context = instance_double(
      ASRFacet::Scanner::ScanContext,
      timing: timing,
      probe_db: probe_db,
      icmp_prober: instance_double(ASRFacet::Scanner::Probes::ICMPProber, echo: false),
      tcp_prober: tcp_prober
    )

    expect(described_class.new(context).host_up?("example.com")).to be(true)
  end

  it "returns false when no probe gets a response" do
    tcp_prober = instance_double(ASRFacet::Scanner::Probes::TCPProber, send_probe: { reply: :timeout })
    context = instance_double(
      ASRFacet::Scanner::ScanContext,
      timing: timing,
      probe_db: probe_db,
      icmp_prober: instance_double(ASRFacet::Scanner::Probes::ICMPProber, echo: false),
      tcp_prober: tcp_prober
    )

    expect(described_class.new(context).host_up?("example.com")).to be(false)
  end
end
