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

RSpec.describe ASRFacet::Scanner::ResultAdapter do
  let(:timing) do
    Struct.new(:name) do
      def to_h
        { name: name }
      end
    end.new("Normal")
  end

  it "maps scanner host and port results into a framework payload" do
    host = ASRFacet::Scanner::Results::HostResult.new(host: "app.example.com", up: true)
    host.add_port(ASRFacet::Scanner::Results::PortResult.new(port: 443, proto: :tcp, state: :open, service: "https", version: "nginx"))
    host.add_port(ASRFacet::Scanner::Results::PortResult.new(port: 80, proto: :tcp, state: :closed, service: "http"))
    host.add_port(ASRFacet::Scanner::Results::PortResult.new(port: 53, proto: :udp, state: :open_filtered, service: "domain"))
    scan_result = ASRFacet::Scanner::Results::ScanResult.new(
      targets: ["example.com"],
      scan_type: :syn,
      timing: timing,
      started_at: Time.utc(2026, 4, 27, 10, 0, 0),
      finished_at: Time.utc(2026, 4, 27, 10, 0, 2),
      host_results: [host]
    )

    payload = described_class.to_payload(scan_result, target: "example.com")
    store = payload[:store].to_h

    expect(store[:subdomains]).to include("app.example.com")
    expect(store[:open_ports]).to include(include(host: "app.example.com", port: 443, service: "https"))
    expect(store[:closed_ports]).to include(include(port: 80))
    expect(store[:filtered_ports]).to include(include(port: 53, proto: :udp))
    expect(payload[:summary]).to include(hosts_total: 1, hosts_up: 1, total_open: 1, total_filtered: 1, scan_type: "syn")
    expect(payload[:scan_result]).to include(scan_type: :syn)
  end

  it "stores IP hosts in the IP bucket instead of the subdomain bucket" do
    host = ASRFacet::Scanner::Results::HostResult.new(host: "192.0.2.10", up: true)
    scan_result = ASRFacet::Scanner::Results::ScanResult.new(
      targets: ["192.0.2.10"],
      scan_type: :connect,
      timing: timing,
      started_at: Time.utc(2026, 4, 27, 10, 0, 0),
      host_results: [host]
    )

    payload = described_class.to_payload(scan_result, target: "192.0.2.10")
    store = payload[:store].to_h

    expect(store[:ips]).to include("192.0.2.10")
    expect(Array(store[:subdomains])).to be_empty
  end

  it "returns a safe payload when the scan result is empty" do
    payload = described_class.to_payload(nil, target: "example.com")

    expect(payload[:store]).to be_a(ASRFacet::ResultStore)
    expect(payload[:summary]).to include(hosts_total: 0, hosts_up: 0, total_open: 0, total_filtered: 0)
    expect(payload[:meta]).to include(target: "example.com")
  end
end
