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

RSpec.describe ASRFacet::Scanner::Probes::NpingRawAdapter do
  let(:platform) do
    double(
      "platform",
      nping_available?: true,
      host_label: "Linux",
      privilege_label: "sudo",
      raw_backend_requirements: "Nping and an elevated shell such as sudo"
    )
  end

  it "parses SYN-ACK replies from nping output" do
    runner = lambda do |*_args|
      ["RCVD (0.1810s) TCP 192.0.2.10:80 > 198.51.100.50:50091 SA ttl=53 id=0 iplen=44 seq=1 win=5840\n", 0]
    end

    result = described_class.new(runner: runner, platform: platform).call(host: "192.0.2.10", port: 80, flags: %i[syn], timeout: 1)

    expect(result[:reply]).to eq(:syn_ack)
    expect(result[:window]).to eq(5840)
    expect(result[:rtt]).to be_within(0.1).of(181.0)
  end

  it "parses RST replies from nping output" do
    runner = lambda do |*_args|
      ["RCVD (0.0520s) TCP 192.0.2.10:80 > 198.51.100.50:50091 RA ttl=53 id=0 iplen=44 seq=1 win=0\n", 0]
    end

    result = described_class.new(runner: runner, platform: platform).call(host: "192.0.2.10", port: 80, flags: %i[ack], timeout: 1)

    expect(result[:reply]).to eq(:rst)
    expect(result[:window]).to eq(0)
  end

  it "raises a clear privilege error when nping reports missing privileges" do
    runner = lambda do |*_args|
      ["Nping requires root privileges for raw packet operations.\n", 1]
    end

    expect do
      described_class.new(runner: runner, platform: platform).call(host: "192.0.2.10", port: 80, flags: %i[fin], timeout: 1)
    end.to raise_error(ASRFacet::ScanError, /Nping is available but raw packet privileges are missing/i)
  end
end
