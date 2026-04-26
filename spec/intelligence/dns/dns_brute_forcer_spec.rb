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
require "tmpdir"

RSpec.describe ASRFacet::Intelligence::Dns::DnsBruteForcer do
  let(:resolver) { instance_double(ASRFacet::Intelligence::Dns::DnsResolver) }
  let(:wildcard_detector) { instance_double(ASRFacet::Intelligence::Dns::DnsWildcard, detect: { wildcard: false }) }
  let(:permutator) { instance_double(ASRFacet::Intelligence::Dns::DnsPermutator) }
  let(:event_bus) { instance_double(ASRFacet::EventBus, emit: true) }

  it "runs wildcard detection, resolves candidates, and emits discoveries" do
    Dir.mktmpdir do |dir|
      wordlist = File.join(dir, "subs.txt")
      File.write(wordlist, "www\n")
      allow(permutator).to receive(:generate).and_return(["dev.example.com"])
      allow(wildcard_detector).to receive(:filter).and_return(true)
      allow(resolver).to receive(:resolve_types) do |fqdn, _types|
        if %w[www.example.com dev.example.com].include?(fqdn)
          { a: { answers: [{ value: "203.0.113.10" }] } }
        else
          { a: { answers: [] } }
        end
      end

      brute_forcer = described_class.new(
        resolver: resolver,
        wildcard_detector: wildcard_detector,
        permutator: permutator,
        event_bus: event_bus,
        wordlist_path: wordlist,
        max_parallelism: 2
      )

      results = brute_forcer.run("example.com", ["app.example.com"])

      expect(results).to eq(%w[dev.example.com www.example.com])
      expect(event_bus).to have_received(:emit).at_least(:once)
    end
  end

  it "returns an empty array when nothing resolves" do
    allow(permutator).to receive(:generate).and_return([])
    allow(wildcard_detector).to receive(:filter).and_return(true)
    allow(resolver).to receive(:resolve_types).and_return(a: { answers: [] })

    brute_forcer = described_class.new(
      resolver: resolver,
      wildcard_detector: wildcard_detector,
      permutator: permutator,
      event_bus: event_bus,
      max_parallelism: 1
    )

    expect(brute_forcer.run("example.com")).to eq([])
  end

  it "filters out wildcard-backed candidates" do
    Dir.mktmpdir do |dir|
      wordlist = File.join(dir, "subs.txt")
      File.write(wordlist, "api\n")
      allow(permutator).to receive(:generate).and_return([])
      allow(resolver).to receive(:resolve_types).and_return(a: { answers: [{ value: "203.0.113.10" }] })
      allow(wildcard_detector).to receive(:filter).and_return(false)

      brute_forcer = described_class.new(
        resolver: resolver,
        wildcard_detector: wildcard_detector,
        permutator: permutator,
        event_bus: event_bus,
        wordlist_path: wordlist
      )

      expect(brute_forcer.run("example.com")).to eq([])
    end
  end
end
