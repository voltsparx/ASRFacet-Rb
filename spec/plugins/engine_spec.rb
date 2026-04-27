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

RSpec.describe ASRFacet::Plugins::Engine do
  it "lists the built-in session plugins" do
    engine = described_class.new(selection: "all")

    expect(engine.names).to include(
      "exposure_score",
      "attack_path",
      "certificate_atlas",
      "service_cluster",
      "internet_exposure"
    )
  end

  it "applies selected plugins and enriches the session store" do
    store = ASRFacet::ResultStore.new
    store.add(:open_ports, { host: "app.example.com", port: 22, service: "ssh" })
    store.add(:open_ports, { host: "db.example.com", port: 3306, service: "mysql" })
    store.add(:ips, "10.0.0.10")
    store.add(:certs, { host: "app.example.com", cn: "app.example.com", issuer: "Example CA", sans: %w[app.example.com api.example.com dev.example.com] })

    runtime = described_class.new(selection: "exposure_score,attack_path,certificate_atlas,internet_exposure").apply(
      target: "example.com",
      store: store,
      summary: store.summary
    )

    expect(runtime[:store].all(:plugin_priority_targets)).not_to be_empty
    expect(runtime[:store].all(:attack_paths)).to include(include(path: include("remote access surface")))
    expect(runtime[:store].all(:certificate_atlas)).to include(include(common_name: "app.example.com", san_count: 3))
    expect(runtime[:store].all(:findings)).to include(include(title: "Private infrastructure reference exposed"))
  end

  it "resolves plugin selectors by category, mode, and exclusion tokens" do
    plan = described_class.new(selection: "mode:scan,-attack_path").resolve(mode: :scan)

    expect(plan[:selected].map { |entry| entry[:name] }).to include("service_cluster")
    expect(plan[:selected].map { |entry| entry[:name] }).not_to include("attack_path")
    expect(plan[:excluded].map { |entry| entry[:name] }).to include("attack_path")
  end

  it "reports unknown plugin selectors during resolution" do
    plan = described_class.new(selection: "nonexistent_plugin").resolve(mode: :scan)

    expect(plan[:unknown]).to eq(["nonexistent_plugin"])
    expect(plan[:selected]).to eq([])
  end
end
