# frozen_string_literal: true
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

RSpec.describe ASRFacet::Scanner::TerminalOutput do
  let(:stream) { StringIO.new }
  let(:terminal) { described_class.new(verbosity: verbosity, stream: stream) }
  let(:verbosity) { 0 }
  let(:timing) { ASRFacet::Scanner::Timing.get(3) }
  let(:hint) do
    ASRFacet::Scanner::Results::PortResult::RedTeamHint.new(
      cve: "CVE-2011-2523",
      title: "vsftpd 2.3.4 backdoor",
      severity: :critical,
      operator_action: "Trigger the smiley-user backdoor.",
      technique: "T1190",
      tools: ["manual shell validation workflow"],
      reference: "https://nvd.nist.gov/vuln/detail/CVE-2011-2523",
      affected: true,
      note: "Detected version 2.3.4 appears affected."
    )
  end
  let(:port_result) do
    ASRFacet::Scanner::Results::PortResult.new(
      port: 21,
      proto: :tcp,
      state: :open,
      service: "ftp",
      version: "2.3.4",
      redteam_hints: [hint]
    )
  end
  let(:host_result) do
    ASRFacet::Scanner::Results::HostResult.new(
      host: "example.com",
      up: true,
      ports: [port_result]
    )
  end
  let(:scan_result) do
    ASRFacet::Scanner::Results::ScanResult.new(
      targets: ["example.com"],
      scan_type: :connect,
      scan_mode: :active,
      timing: timing,
      started_at: Time.now.utc - 5,
      finished_at: Time.now.utc,
      host_results: [host_result]
    )
  end

  it "gates discovered port output by verbosity" do
    terminal.print_port_discovered("example.com", 80, :tcp, :closed, service: "http")
    expect(stream.string).to eq("")

    described_class.new(verbosity: 2, stream: stream).print_port_discovered("example.com", 80, :tcp, :closed, service: "http")
    expect(stream.string).to include("CLOSED")
  end

  it "renders a portscan-style completion block" do
    terminal.print_scan_complete(scan_result)

    expect(stream.string).to include("SCAN COMPLETE")
    expect(stream.string).to include("OPEN PORTS")
    expect(stream.string).to include("RED TEAM FINDINGS")
  end

  it "renders enum-only sections when a result store is present" do
    store = ASRFacet::ResultStore.new
    store.add(:subdomains, "api.example.com")
    store.add(:dns, { host: "example.com", type: :mx, value: "mail.example.com" })
    payload = { store: store, meta: { mode: :passive, target: "example.com" } }

    terminal.print_scan_complete(nil, enum_result: payload)

    expect(stream.string).to include("Discovered Subdomains")
    expect(stream.string).to include("DNS Records")
  end

  it "never renders charts or graphs" do
    terminal.print_scan_complete(scan_result)

    expect(stream.string.downcase).not_to include("chart")
    expect(stream.string.downcase).not_to include("graph")
  end
end
