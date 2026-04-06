# Part of ASRFacet-Rb — authorized testing only
require "spec_helper"

RSpec.describe ASRFacet::Engines::DnsEngine do
  let(:dns_double) { instance_double(Resolv::DNS, close: nil) }

  before do
    allow(Resolv::DNS).to receive(:new).and_return(dns_double)
    allow(dns_double).to receive(:getresources).and_return([])
  end

  it "returns standardized DNS data for successful lookups" do
    allow(dns_double).to receive(:getresources).with("example.com", Resolv::DNS::Resource::IN::A).and_return([double(address: "1.2.3.4")])
    allow(dns_double).to receive(:getresources).with("example.com", Resolv::DNS::Resource::IN::MX).and_return([double(exchange: "mail.example.com")])
    allow(dns_double).to receive(:getresources).with("example.com", Resolv::DNS::Resource::IN::TXT).and_return([double(data: "v=spf1")])
    allow(dns_double).to receive(:getresources).with("example.com", Resolv::DNS::Resource::IN::NS).and_return([double(name: "ns1.example.com")])
    allow(dns_double).to receive(:getresources).with("example.com", Resolv::DNS::Resource::IN::CNAME).and_return([])
    allow(dns_double).to receive(:getresources).with("example.com", Resolv::DNS::Resource::IN::AAAA).and_return([])
    allow(dns_double).to receive(:getresources).with("example.com", Resolv::DNS::Resource::IN::SOA).and_return([])

    engine = described_class.new
    allow(engine).to receive(:dns_lookup).and_return([])
    allow(engine).to receive(:attempt_zone_transfer).and_return([])

    result = engine.run("example.com")

    expect(result[:engine]).to eq("dns_engine")
    expect(result[:status]).to eq(:success)
    expect(result[:data][:a]).to eq(["1.2.3.4"])
    expect(result[:data][:mx]).to eq(["mail.example.com"])
    expect(result[:data][:txt]).to eq(["v=spf1"])
  end

  it "marks wildcard DNS when random subdomains resolve" do
    engine = described_class.new
    allow(engine).to receive(:dns_lookup).and_return(["10.10.10.10"])
    allow(engine).to receive(:attempt_zone_transfer).and_return([])

    result = engine.run("example.com")

    expect(result[:data][:wildcard]).to eq(true)
    expect(result[:data][:wildcard_ips]).to eq(["10.10.10.10"])
  end

  it "attempts a zone transfer during the run" do
    engine = described_class.new
    allow(engine).to receive(:dns_lookup).and_return([])
    allow(engine).to receive(:attempt_zone_transfer).with("example.com").and_return([])

    engine.run("example.com")

    expect(engine).to have_received(:attempt_zone_transfer).with("example.com")
  end

  it "returns a failed result when resolution errors occur" do
    allow(Resolv::DNS).to receive(:new).and_raise(StandardError, "dns timeout")

    result = described_class.new.run("example.com")

    expect(result[:status]).to eq(:failed)
    expect(result[:data][:a]).to eq([])
    expect(result[:errors]).not_to be_empty
  end
end
