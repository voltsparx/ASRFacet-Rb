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

RSpec.describe ASRFacet::Scanner::ScanTypes::ConnectScan do
  let(:probe_db) { instance_double(ASRFacet::Scanner::ProbeDB, service_for: "ssh") }
  let(:context) do
    instance_double(
      ASRFacet::Scanner::ScanContext,
      timing: ASRFacet::Scanner::Timing.get(3),
      probe_db: probe_db
    )
  end

  it "marks a successful TCP connect as open" do
    socket = instance_double(TCPSocket, close: true)
    socket_class = class_double(TCPSocket, new: socket)

    result = described_class.new(context, socket_class: socket_class).probe("example.com", 22)

    expect(result.state).to eq(:open)
    expect(result.service).to eq("ssh")
  end

  it "maps ECONNREFUSED to closed" do
    socket_class = class_double(TCPSocket)
    allow(socket_class).to receive(:new).and_raise(Errno::ECONNREFUSED)

    result = described_class.new(context, socket_class: socket_class).probe("example.com", 22)

    expect(result.state).to eq(:closed)
  end

  it "maps ETIMEDOUT to filtered" do
    socket_class = class_double(TCPSocket)
    allow(socket_class).to receive(:new).and_raise(Errno::ETIMEDOUT)

    result = described_class.new(context, socket_class: socket_class).probe("example.com", 22)

    expect(result.state).to eq(:filtered)
  end
end
