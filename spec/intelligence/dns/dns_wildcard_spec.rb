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

RSpec.describe ASRFacet::Intelligence::Dns::DnsWildcard do
  let(:resolver) { instance_double(ASRFacet::Intelligence::Dns::DnsResolver) }

  it "detects wildcard dns and filters wildcard-backed discoveries" do
    detector = described_class.new(
      resolver: resolver,
      token_generator: Enumerator.new { |y| %w[a b c].each { |value| y << value } }.to_enum.method(:next)
    )

    allow(resolver).to receive(:resolve_types).and_return(
      a: { answers: [{ value: "203.0.113.5" }] },
      aaaa: { answers: [] }
    )

    result = detector.detect("example.com")

    expect(result).to include(wildcard: true, wildcard_ips: ["203.0.113.5"])
    expect(detector.filter("example.com", "api.example.com")).to be(false)
  end

  it "returns false when no wildcard addresses are found" do
    detector = described_class.new(resolver: resolver, token_generator: -> { "seedvalue" })
    allow(resolver).to receive(:resolve_types).and_return(a: { answers: [] }, aaaa: { answers: [] })

    expect(detector.detect("example.com")).to include(wildcard: false)
  end

  it "allows candidates when wildcard detection did not trigger" do
    detector = described_class.new(resolver: resolver, token_generator: -> { "seedvalue" })
    allow(resolver).to receive(:resolve_types).and_return(a: { answers: [] }, aaaa: { answers: [] })
    detector.detect("example.com")

    expect(detector.filter("example.com", "api.example.com")).to be(true)
  end
end
