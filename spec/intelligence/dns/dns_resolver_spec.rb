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

RSpec.describe ASRFacet::Intelligence::Dns::DnsResolver do
  FakeA = Struct.new(:address, :ttl)
  FakePTR = Struct.new(:name, :ttl)

  class FakeDnsClient
    def initialize(resources: [], error: nil)
      @resources = resources
      @error = error
    end

    def getresources(_name, _klass)
      raise @error unless @error.nil?

      @resources
    end

    def close; end
  end

  it "resolves records with ttl data and rotates across resolvers" do
    dns_factory = lambda do |resolver|
      resources = resolver == "8.8.8.8" ? [FakeA.new("203.0.113.10", 300)] : []
      FakeDnsClient.new(resources: resources)
    end

    resolver = described_class.new(trusted_resolvers: [], dns_factory: dns_factory, sleeper: ->(_duration) {}, clock: -> { 1.0 })
    result = resolver.resolve("app.example.com", :a)

    expect(result).to include(status: :success, resolver: "8.8.8.8", ttl: 300)
    expect(result[:answers]).to include(include(value: "203.0.113.10", ttl: 300))
  end

  it "retries with exponential backoff on timeout and tracks reliability" do
    calls = Hash.new(0)
    sleeps = []
    dns_factory = lambda do |resolver|
      calls[resolver] += 1
      if resolver == "8.8.8.8" && calls[resolver] == 1
        FakeDnsClient.new(error: Resolv::ResolvTimeout.new)
      else
        FakeDnsClient.new(resources: [FakeA.new("203.0.113.20", 120)])
      end
    end

    resolver = described_class.new(
      trusted_resolvers: ["8.8.8.8"],
      dns_factory: dns_factory,
      sleeper: ->(duration) { sleeps << duration },
      clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }
    )
    result = resolver.resolve("api.example.com", :a)

    expect(result[:status]).to eq(:success)
    expect(result[:attempts]).to be > 1
    expect(sleeps).not_to be_empty
    expect(resolver.reliability_scores["8.8.8.8"]).to be < 1.0
  end

  it "converts ptr lookups into reverse names and parses ptr answers" do
    dns_factory = ->(_resolver) { FakeDnsClient.new(resources: [FakePTR.new("host.example.com", 60)]) }
    resolver = described_class.new(dns_factory: dns_factory, sleeper: ->(_duration) {}, clock: -> { 1.0 })

    result = resolver.resolve("203.0.113.10", :ptr)

    expect(result[:query_name]).to eq("10.113.0.203.in-addr.arpa")
    expect(result[:answers]).to include(include(value: "host.example.com"))
  end
end
