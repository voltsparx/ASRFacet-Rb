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

RSpec.describe ASRFacet::Core::Deduplicator do
  it "deduplicates values per scope using normalized keys" do
    dedupe = described_class.new

    expect(dedupe.first_time?(:subdomain, "API.EXAMPLE.COM")).to be(true)
    expect(dedupe.first_time?(:subdomain, "api.example.com")).to be(false)
    expect(dedupe.first_time?(:ip, "api.example.com")).to be(true)
    expect(dedupe.seen?(:subdomain, "api.example.com")).to be(true)
    expect(dedupe.stats).to include("subdomain" => 1, "ip" => 1)
  end

  it "normalizes hashes and arrays for stable fingerprints" do
    dedupe = described_class.new
    first = { host: "example.com", ports: [443, 80] }
    second = { "ports" => [443, 80], "host" => "EXAMPLE.COM" }

    expect(dedupe.first_time?(:service, first)).to be(true)
    expect(dedupe.first_time?(:service, second)).to be(false)
  end
end
