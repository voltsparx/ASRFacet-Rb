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

RSpec.describe ASRFacet::Intelligence::Dns::ZoneTransfer do
  let(:logger) { instance_double(ASRFacet::Logger, info: true, warn: true) }

  it "returns structured records for successful zone transfers" do
    transfer = described_class.new(logger: logger)
    allow(transfer).to receive(:lookup_nameservers).and_return(["ns1.example.com"])
    allow(transfer).to receive(:perform_axfr).and_return([{ name: "www.example.com", type: "A", data: "203.0.113.10", ttl: 60 }])

    result = transfer.attempt("example.com")

    expect(result).to contain_exactly(
      include(domain: "example.com", nameserver: "ns1.example.com", success: true, records: [include(name: "www.example.com")])
    )
  end

  it "records failures without raising" do
    transfer = described_class.new(logger: logger)
    allow(transfer).to receive(:lookup_nameservers).and_return(["ns1.example.com"])
    allow(transfer).to receive(:perform_axfr).and_raise(IOError, "denied")

    result = transfer.attempt("example.com")

    expect(result.first).to include(success: false, error: "denied")
  end

  it "returns an empty array when no nameservers are present" do
    transfer = described_class.new(logger: logger)
    allow(transfer).to receive(:lookup_nameservers).and_return([])

    expect(transfer.attempt("example.com")).to eq([])
  end
end
