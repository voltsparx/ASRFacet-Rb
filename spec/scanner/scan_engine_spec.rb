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
require "stringio"

RSpec.describe ASRFacet::Scanner::ScanEngine do
  let(:probe_db) do
    instance_double(
      ASRFacet::Scanner::ProbeDB,
      top_ports: [{ port: 80, proto: :tcp, service: "http", frequency: 1.0 }, { port: 443, proto: :tcp, service: "https", frequency: 0.9 }],
      service_for: "http",
      probes_for: []
    )
  end
  let(:tcp_prober) do
    instance_double(
      ASRFacet::Scanner::Probes::TCPProber,
      send_probe: { reply: :syn_ack, window: 0 },
      fingerprint: { ttl: 64, window: 29_200, tcp_options: %i[mss sack timestamp], ip_id_sequence: [1, 2, 3], rst_behavior: :rst },
      raw_socket_capable?: false
    )
  end
  let(:udp_prober) { instance_double(ASRFacet::Scanner::Probes::UDPProber, send_probe: { reply: :udp, data: "ok" }) }
  let(:icmp_prober) { instance_double(ASRFacet::Scanner::Probes::ICMPProber, echo: true) }
  let(:stream) { StringIO.new }
  let(:logger) { ASRFacet::Scanner::VerboseLogger.new(level: 0, stream: stream) }

  before do
    socket = instance_double(TCPSocket, close: true)
    allow(TCPSocket).to receive(:new).and_return(socket)
    allow(IO).to receive(:select).and_return([[socket], nil, nil])
    allow(socket).to receive(:write).and_return(0)
    allow(socket).to receive(:readpartial).and_return("HTTP/1.1 200 OK\r\n")
  end

  it "scans a target and records open ports" do
    result = described_class.new(
      scan_type: :connect,
      timing: 3,
      verbosity: 0,
      version_detection: false,
      os_detection: false,
      version_intensity: 7,
      ports: "80,443",
      logger: logger,
      probe_db: probe_db,
      tcp_prober: tcp_prober,
      udp_prober: udp_prober,
      icmp_prober: icmp_prober
    ).scan("example.com")

    expect(result.host_results.first.open_ports.map(&:port)).to match_array([80, 443])
  end

  it "runs version and OS detection when enabled" do
    allow(probe_db).to receive(:probes_for).and_return(
      [
        ASRFacet::Scanner::ProbeDB::Probe.new(
          name: "HTTPOptions",
          proto: :tcp,
          probe_str: "OPTIONS / HTTP/1.0\r\n\r\n",
          rarity: 1,
          wait_ms: 100,
          ports: [80],
          ssl_ports: [],
          matches: [{ service: "http", pattern_source: "^HTTP/1\\.[01] 200", pattern_flags: "", metadata: { product: "Apache", version: "2.4.57", extra: nil, cpes: ["a:apache:http_server:2.4.57"] } }],
          softmatches: []
        )
      ]
    )

    result = described_class.new(
      scan_type: :service,
      timing: 3,
      verbosity: 0,
      version_detection: true,
      os_detection: true,
      version_intensity: 7,
      ports: "80",
      logger: logger,
      probe_db: probe_db,
      tcp_prober: tcp_prober,
      udp_prober: udp_prober,
      icmp_prober: icmp_prober
    ).scan("example.com")

    host = result.host_results.first
    expect(host.os).to eq("Linux")
    expect(host.open_ports.first.version).to eq("2.4.57")
  end

  it "marks a host down when ping discovery fails" do
    down_icmp = instance_double(ASRFacet::Scanner::Probes::ICMPProber, echo: false)
    silent_tcp = instance_double(ASRFacet::Scanner::Probes::TCPProber, send_probe: { reply: :timeout, window: 0 }, fingerprint: nil)

    result = described_class.new(
      scan_type: :connect,
      timing: 3,
      verbosity: 0,
      version_detection: false,
      os_detection: false,
      version_intensity: 7,
      ports: "80",
      logger: logger,
      probe_db: probe_db,
      tcp_prober: silent_tcp,
      udp_prober: udp_prober,
      icmp_prober: down_icmp
    ).scan("example.com")

    expect(result.host_results.first.up).to be(false)
  end

  {
    syn: { tcp_reply: { reply: :syn_ack, window: 0 }, expected_state: :open },
    ack: { tcp_reply: { reply: :rst, window: 0 }, expected_state: :unfiltered },
    fin: { tcp_reply: { reply: :timeout, window: 0 }, expected_state: :open_filtered },
    null: { tcp_reply: { reply: :rst, window: 0 }, expected_state: :closed },
    xmas: { tcp_reply: { reply: :timeout, window: 0 }, expected_state: :open_filtered },
    window: { tcp_reply: { reply: :rst, window: 1024 }, expected_state: :open },
    maimon: { tcp_reply: { reply: :timeout, window: 0 }, expected_state: :open_filtered }
  }.each do |scan_type, config|
    it "runs #{scan_type} through the scan engine with #{config[:expected_state]} semantics" do
      allow(ASRFacet::Scanner::Privilege).to receive(:elevated?).and_return(true)
      typed_tcp_prober = instance_double(
        ASRFacet::Scanner::Probes::TCPProber,
        send_probe: config[:tcp_reply],
        fingerprint: { ttl: 64, window: 29_200, tcp_options: %i[mss sack timestamp], ip_id_sequence: [1, 2, 3], rst_behavior: :rst },
        raw_socket_capable?: true
      )

      result = described_class.new(
        scan_type: scan_type,
        timing: 3,
        verbosity: 0,
        version_detection: false,
        os_detection: false,
        version_intensity: 7,
        ports: "80",
        logger: logger,
        probe_db: probe_db,
        tcp_prober: typed_tcp_prober,
        udp_prober: udp_prober,
        icmp_prober: icmp_prober
      ).scan("example.com")

      expect(result.host_results.first.ports.first.state).to eq(config[:expected_state])
    end
  end

  it "fails fast for raw scan types when the bundled TCP backend is not raw-capable" do
    expect do
      described_class.new(
        scan_type: :xmas,
        timing: 3,
        verbosity: 0,
        version_detection: false,
        os_detection: false,
        version_intensity: 7,
        ports: "80",
        logger: logger,
        probe_db: probe_db,
        tcp_prober: tcp_prober,
        udp_prober: udp_prober,
        icmp_prober: icmp_prober
      ).scan("example.com")
    end.to raise_error(ASRFacet::ScanError, /xmas scans need a raw-capable tcp prober backend such as nping/i)
  end

  it "runs a UDP scan through the scan engine with UDP semantics" do
    typed_udp_prober = instance_double(ASRFacet::Scanner::Probes::UDPProber, send_probe: { reply: :icmp_port_unreachable, data: nil })

    result = described_class.new(
      scan_type: :udp,
      timing: 3,
      verbosity: 0,
      version_detection: false,
      os_detection: false,
      version_intensity: 7,
      ports: "53",
      logger: logger,
      probe_db: probe_db,
      tcp_prober: tcp_prober,
      udp_prober: typed_udp_prober,
      icmp_prober: icmp_prober
    ).scan("example.com")

    expect(result.host_results.first.ports.first.state).to eq(:closed)
    expect(result.host_results.first.ports.first.proto).to eq(:udp)
  end

  it "runs a ping scan through the scan engine as host discovery" do
    result = described_class.new(
      scan_type: :ping,
      timing: 3,
      verbosity: 0,
      version_detection: false,
      os_detection: false,
      version_intensity: 7,
      ports: "80",
      logger: logger,
      probe_db: probe_db,
      tcp_prober: tcp_prober,
      udp_prober: udp_prober,
      icmp_prober: icmp_prober
    ).scan("example.com")

    host = result.host_results.first
    expect(host.up).to be(true)
    expect(host.ports.first.port).to eq(0)
    expect(host.ports.first.proto).to eq(:icmp)
    expect(host.ports.first.state).to eq(:open)
  end
end
