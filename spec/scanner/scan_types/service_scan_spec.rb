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

RSpec.describe ASRFacet::Scanner::ScanTypes::ServiceScan do
  let(:probe_db) { instance_double(ASRFacet::Scanner::ProbeDB, service_for: "http") }
  let(:version_detector) { instance_double(ASRFacet::Scanner::VersionDetector) }
  let(:context) do
    instance_double(
      ASRFacet::Scanner::ScanContext,
      timing: ASRFacet::Scanner::Timing.get(3),
      probe_db: probe_db,
      version_detector: version_detector
    )
  end

  it "annotates an open TCP port with version metadata" do
    socket = instance_double(TCPSocket, close: true)
    socket_class = class_double(TCPSocket, new: socket)
    allow(version_detector).to receive(:detect).and_return(service: "http", version: "Apache 2.4.57", extra: "server", cpe: "cpe:/a:apache:http_server:2.4.57", banner: "HTTP/1.1 200 OK")

    result = described_class.new(context, socket_class: socket_class).probe("example.com", 80)

    expect(result.state).to eq(:open)
    expect(result.version).to eq("Apache 2.4.57")
    expect(result.cpe).to eq("cpe:/a:apache:http_server:2.4.57")
  end

  it "does not attempt version detection for a closed port" do
    socket_class = class_double(TCPSocket)
    allow(socket_class).to receive(:new).and_raise(Errno::ECONNREFUSED)
    allow(version_detector).to receive(:detect)

    result = described_class.new(context, socket_class: socket_class).probe("example.com", 80)

    expect(result.state).to eq(:closed)
    expect(version_detector).not_to have_received(:detect)
  end
end
