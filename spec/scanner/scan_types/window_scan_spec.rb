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

RSpec.describe ASRFacet::Scanner::ScanTypes::WindowScan do
  let(:probe_db) { instance_double(ASRFacet::Scanner::ProbeDB, service_for: "http") }
  let(:timing) { ASRFacet::Scanner::Timing.get(3) }

  it "maps an RST with a positive window to open" do
    context = instance_double(ASRFacet::Scanner::ScanContext, timing: timing, probe_db: probe_db, tcp_prober: instance_double(ASRFacet::Scanner::Probes::TCPProber, send_probe: { reply: :rst, window: 1024 }))

    result = described_class.new(context).probe("example.com", 80)

    expect(result.state).to eq(:open)
  end

  it "maps an RST with a zero window to closed" do
    context = instance_double(ASRFacet::Scanner::ScanContext, timing: timing, probe_db: probe_db, tcp_prober: instance_double(ASRFacet::Scanner::Probes::TCPProber, send_probe: { reply: :rst, window: 0 }))

    result = described_class.new(context).probe("example.com", 80)

    expect(result.state).to eq(:closed)
  end

  it "maps no reply to filtered" do
    context = instance_double(ASRFacet::Scanner::ScanContext, timing: timing, probe_db: probe_db, tcp_prober: instance_double(ASRFacet::Scanner::Probes::TCPProber, send_probe: { reply: :timeout, window: 0 }))

    result = described_class.new(context).probe("example.com", 80)

    expect(result.state).to eq(:filtered)
  end
end
