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

RSpec.describe ASRFacet::Scanner::VersionDetector do
  let(:probe) do
    ASRFacet::Scanner::ProbeDB::Probe.new(
      name: "HTTPOptions",
      proto: :tcp,
      probe_str: "OPTIONS / HTTP/1.0\r\n\r\n",
      rarity: 1,
      wait_ms: 100,
      ports: [80],
      ssl_ports: [],
      matches: [
        {
          service: "http",
          pattern_source: "^HTTP/1\\.[01] 200",
          pattern_flags: "",
          metadata: { product: "Apache", version: "2.4.57", extra: "server", cpes: ["a:apache:http_server:2.4.57"] }
        }
      ],
      softmatches: []
    )
  end

  it "returns version data on a full match" do
    socket = instance_double(TCPSocket, write: 0, readpartial: "HTTP/1.1 200 OK\r\nServer: Apache\r\n", close: true)
    socket_factory = ->(_host, _port, _timeout) { socket }
    probe_db = instance_double(ASRFacet::Scanner::ProbeDB, probes_for: [probe])
    allow(IO).to receive(:select).and_return([[socket], nil, nil])

    result = described_class.new(probe_db: probe_db, intensity: 7, socket_factory: socket_factory).detect("example.com", 80, proto: :tcp)

    expect(result[:service]).to eq("http")
    expect(result[:version]).to eq("2.4.57")
    expect(result[:extra]).to include("Apache")
  end

  it "respects rarity thresholds at lower intensity" do
    probe_db = instance_double(ASRFacet::Scanner::ProbeDB, probes_for: [probe.dup.tap { |entry| entry.rarity = 9; entry.ports = [] }])

    result = described_class.new(probe_db: probe_db, intensity: 0, socket_factory: ->(*_args) { raise "unused" }).detect("example.com", 80, proto: :tcp)

    expect(result).to be_nil
  end

  it "returns nil when the socket read times out" do
    socket = instance_double(TCPSocket, write: 0, close: true)
    probe_db = instance_double(ASRFacet::Scanner::ProbeDB, probes_for: [probe])
    allow(IO).to receive(:select).and_return(nil)

    result = described_class.new(probe_db: probe_db, intensity: 7, socket_factory: ->(*_args) { socket }).detect("example.com", 80, proto: :tcp)

    expect(result).to be_nil
  end
end
