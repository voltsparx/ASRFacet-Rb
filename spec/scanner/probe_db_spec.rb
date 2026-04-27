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

RSpec.describe ASRFacet::Scanner::ProbeDB do
  subject(:probe_db) { described_class.new }

  it "loads the top 1000 ports from nmap-services" do
    expect(described_class::TOP_PORTS.length).to eq(1000)
    expect(described_class::TOP_PORTS.first).to include(:port, :proto, :service, :frequency)
  end

  it "returns matching probes before the broader fallback list" do
    probes = probe_db.probes_for(80, :tcp)

    expect(probes.first.name).to eq("NULL")
    expect(probes.map(&:name)).to include("HTTPOptions", "GenericLines", "RTSPRequest", "SSLSessionReq")
  end

  it "looks up a service name for a known TCP port" do
    expect(probe_db.service_for(22, :tcp)).to eq("ssh")
  end

  it "supports the requested source-derived service families" do
    expect(probe_db.supports_service?("SSHSessionReq", proto: :tcp)).to be(true)
    expect(probe_db.supports_service?("SMTPRequest", proto: :tcp)).to be(true)
    expect(probe_db.supports_service?("FTPRequest", proto: :tcp)).to be(true)
    expect(probe_db.supports_service?("MSSQLQuery", proto: :udp)).to be(true)
    expect(probe_db.supports_service?("MySQLRequest", proto: :tcp)).to be(true)
    expect(probe_db.supports_service?("PostgresRequest", proto: :tcp)).to be(true)
    expect(probe_db.supports_service?("RedisRequest", proto: :tcp)).to be(true)
    expect(probe_db.supports_service?("MongoDBRequest", proto: :tcp)).to be(true)
    expect(probe_db.supports_service?("DNSQuery")).to be(true)
    expect(probe_db.supports_service?("SIPOptions")).to be(true)
  end

  it "falls back to bundled defaults when the Nmap data files are unavailable" do
    allow(File).to receive(:file?).and_call_original
    allow(File).to receive(:file?).with(described_class::SERVICES_PATH).and_return(false)
    allow(File).to receive(:file?).with(described_class::PROBES_PATH).and_return(false)

    top_ports, lookup = described_class.send(:load_services)
    probes = described_class.send(:load_probes)

    expect(top_ports.length).to eq(1000)
    expect(lookup[[22, :tcp]]).to eq("ssh")
    expect(lookup[[53, :udp]]).to eq("domain")
    expect(probes.map(&:name)).to include("NULL", "HTTPOptions", "SSLSessionReq", "SIPOptions")
  end
end
