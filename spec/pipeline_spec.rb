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
require "tmpdir"

RSpec.describe ASRFacet::Pipeline do
  let(:target) { instance_double(ASRFacet::Core::Target, domain: "example.com", ip: nil) }
  let(:streamer) { instance_double(ASRFacet::Output::JsonlStream, write: true, path: File.join(Dir.tmpdir, "example_com.jsonl")) }
  let(:memory) { instance_double(ASRFacet::Core::ReconMemory, known?: false, record_failure: nil, record_scan: nil) }
  let(:passive_runner) { instance_double(ASRFacet::Passive::Runner, run: { subdomains: ["app.example.com"], errors: [] }) }
  let(:dns_engine) { instance_double(ASRFacet::Engines::DnsEngine) }
  let(:cert_engine) { instance_double(ASRFacet::Engines::CertEngine, analyze_cert: {}, new_subdomains: []) }
  let(:dns_buster) { instance_double(ASRFacet::Busters::DnsBuster, run: []) }
  let(:port_engine) { instance_double(ASRFacet::Engines::PortEngine, scan: []) }
  let(:http_engine) { instance_double(ASRFacet::Engines::HttpEngine, probe: nil) }
  let(:crawl_engine) { instance_double(ASRFacet::Engines::CrawlEngine) }
  let(:js_engine) { instance_double(ASRFacet::Engines::JsEndpointEngine) }
  let(:correlation_engine) { instance_double(ASRFacet::Engines::CorrelationEngine, run: []) }
  let(:asset_scorer) { instance_double(ASRFacet::Engines::AssetScorer, score_all: []) }
  let(:whois_engine) { instance_double(ASRFacet::Engines::WhoisEngine, run: { data: { registrar: "Example Registrar" } }) }
  let(:asn_engine) { instance_double(ASRFacet::Engines::AsnEngine, run: { data: {} }) }
  let(:vuln_engine) { instance_double(ASRFacet::Engines::VulnEngine, run: []) }
  let(:monitoring_engine) { instance_double(ASRFacet::Engines::MonitoringEngine, diff: {}) }
  let(:probabilistic_engine) { instance_double(ASRFacet::Engines::ProbabilisticSubdomainEngine, top_candidates: []) }

  before do
    allow(ASRFacet::Core::Target).to receive(:new).and_return(target)
    allow(ASRFacet::Output::JsonlStream).to receive(:new).and_return(streamer)
    allow(ASRFacet::Core::ReconMemory).to receive(:new).and_return(memory)
    allow(ASRFacet::Passive::Runner).to receive(:new).and_return(passive_runner)
    allow(ASRFacet::Engines::DnsEngine).to receive(:new).and_return(dns_engine)
    allow(ASRFacet::Engines::CertEngine).to receive(:new).and_return(cert_engine)
    allow(ASRFacet::Busters::DnsBuster).to receive(:new).and_return(dns_buster)
    allow(ASRFacet::Engines::PortEngine).to receive(:new).and_return(port_engine)
    allow(ASRFacet::Engines::HttpEngine).to receive(:new).and_return(http_engine)
    allow(ASRFacet::Engines::CrawlEngine).to receive(:new).and_return(crawl_engine)
    allow(ASRFacet::Engines::JsEndpointEngine).to receive(:new).and_return(js_engine)
    allow(ASRFacet::Engines::CorrelationEngine).to receive(:new).and_return(correlation_engine)
    allow(ASRFacet::Engines::AssetScorer).to receive(:new).and_return(asset_scorer)
    allow(ASRFacet::Engines::WhoisEngine).to receive(:new).and_return(whois_engine)
    allow(ASRFacet::Engines::AsnEngine).to receive(:new).and_return(asn_engine)
    allow(ASRFacet::Engines::VulnEngine).to receive(:new).and_return(vuln_engine)
    allow(ASRFacet::Engines::MonitoringEngine).to receive(:new).and_return(monitoring_engine)
    allow(ASRFacet::Engines::ProbabilisticSubdomainEngine).to receive(:new).and_return(probabilistic_engine)

    allow(dns_engine).to receive(:run) do |host|
      ip = host == "example.com" ? "198.51.100.10" : "198.51.100.20"
      {
        status: :success,
        data: {
          a: [ip],
          aaaa: [],
          mx: [],
          ns: [],
          txt: [],
          cname: [],
          soa: [],
          wildcard: false,
          wildcard_ips: [],
          zone_transfer: []
        },
        errors: []
      }
    end
  end

  it "keeps discovered subdomains in scope and stores their DNS relationships" do
    result = described_class.new("example.com", threads: 5).run
    store = result[:store].to_h
    graph = result[:graph].to_h

    expect(store[:subdomains]).to include("example.com", "app.example.com")
    expect(store[:ips]).to include("198.51.100.10", "198.51.100.20")
    expect(store[:whois]).to include(include(registrar: "Example Registrar"))
    expect(graph[:edges]).to include(include(from: "example.com", to: "app.example.com", relation: :belongs_to))
    expect(graph[:edges]).to include(include(from: "app.example.com", to: "198.51.100.20", relation: :resolves_to))
  end
end
