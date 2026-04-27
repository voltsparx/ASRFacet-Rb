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

RSpec.describe ASRFacet::Filters::Engine do
  let(:scope) do
    ASRFacet::Core::ScopeEngine.new(
      allowed_domains: ["example.com", "*.example.com"],
      allowed_ips: ["198.51.100.0/24"]
    )
  end

  it "lists the built-in session filters" do
    engine = described_class.new(selection: "all")

    expect(engine.names).to include(
      "scope_guard",
      "duplicate_signal",
      "interesting_asset",
      "private_leak",
      "noise_suppressor"
    )
  end

  it "applies selected filters and produces focused result categories" do
    store = ASRFacet::ResultStore.new
    store.add(:subdomains, "admin.example.com")
    store.add(:subdomains, "outside.test")
    store.add(:ips, "198.51.100.10")
    store.add(:ips, "10.0.0.7")
    store.add(:open_ports, { host: "admin.example.com", port: 443, service: "https" })
    store.add(:findings, { host: "admin.example.com", title: "Login panel", severity: :medium })
    store.add(:findings, { host: "admin.example.com", title: "Login panel", severity: :medium })

    runtime = described_class.new(selection: "scope_guard,duplicate_signal,interesting_asset,private_leak").apply(
      target: "example.com",
      store: store,
      scope: scope,
      summary: store.summary
    )

    expect(runtime[:store].all(:subdomains)).to eq(["admin.example.com"])
    expect(runtime[:store].all(:findings).count).to eq(1)
    expect(runtime[:store].all(:interesting_subdomains)).to eq(["admin.example.com"])
    expect(runtime[:store].all(:private_ips)).to eq([])
  end

  it "resolves filter selectors by category, mode, and exclusion tokens" do
    plan = described_class.new(selection: "mode:scan,-duplicate_signal").resolve(mode: :scan)

    expect(plan[:selected].map { |entry| entry[:name] }).to include("scope_guard")
    expect(plan[:selected].map { |entry| entry[:name] }).not_to include("duplicate_signal")
    expect(plan[:excluded].map { |entry| entry[:name] }).to include("duplicate_signal")
  end

  it "reports unknown filter selectors during resolution" do
    plan = described_class.new(selection: "nonexistent_filter").resolve(mode: :scan)

    expect(plan[:unknown]).to eq(["nonexistent_filter"])
    expect(plan[:selected]).to eq([])
  end
end
