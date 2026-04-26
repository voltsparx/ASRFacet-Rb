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

RSpec.describe ASRFacet::Intelligence::OpenAssetModel do
  it "builds normalized assets through OAM.make" do
    asset = described_class.make(
      type: :fqdn,
      value: "API.LAB.EXAMPLE.COM",
      source: "fixture",
      properties: { confidence: 0.75, environment: "prod" }
    )

    expect(asset.type).to eq(:fqdn)
    expect(asset.value).to eq("api.lab.example.com")
    expect(asset.source).to eq("fixture")
    expect(asset.confidence).to eq(0.75)
    expect(asset.id).not_to be_empty
  end

  it "raises on unsupported asset types" do
    expect do
      described_class.make(type: :widget, value: "x", source: "fixture")
    end.to raise_error(ASRFacet::ParseError, /Unsupported/)
  end

  it "clamps confidence values and builds relations" do
    asset = described_class.make(
      type: :ip_address,
      value: "203.0.113.10",
      source: "fixture",
      properties: { confidence: 9.0 }
    )
    relation = described_class.make_relation(
      from_id: "a1",
      to_id: "a2",
      type: :resolves_to,
      source: "fixture",
      properties: { inferred: true }
    )

    expect(asset.confidence).to eq(1.0)
    expect(relation.to_h).to include(from_id: "a1", to_id: "a2", type: :resolves_to)
  end
end
