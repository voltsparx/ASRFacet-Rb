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

RSpec.describe ASRFacet::Scanner::ScanTypes::UdpScan do
  let(:probe_db) { instance_double(ASRFacet::Scanner::ProbeDB, service_for: "domain") }
  let(:timing) { ASRFacet::Scanner::Timing.get(3) }

  it "marks a UDP reply as open" do
    context = instance_double(ASRFacet::Scanner::ScanContext, timing: timing, probe_db: probe_db, udp_prober: instance_double(ASRFacet::Scanner::Probes::UDPProber, send_probe: { reply: :udp, data: "ok" }))

    result = described_class.new(context).probe("example.com", 53)

    expect(result.state).to eq(:open)
    expect(result.banner).to eq("ok")
  end

  it "maps ICMP port unreachable to closed" do
    context = instance_double(ASRFacet::Scanner::ScanContext, timing: timing, probe_db: probe_db, udp_prober: instance_double(ASRFacet::Scanner::Probes::UDPProber, send_probe: { reply: :icmp_port_unreachable }))

    result = described_class.new(context).probe("example.com", 53)

    expect(result.state).to eq(:closed)
  end

  it "maps no reply to open_filtered" do
    context = instance_double(ASRFacet::Scanner::ScanContext, timing: timing, probe_db: probe_db, udp_prober: instance_double(ASRFacet::Scanner::Probes::UDPProber, send_probe: { reply: :timeout }))

    result = described_class.new(context).probe("example.com", 53)

    expect(result.state).to eq(:open_filtered)
  end
end
