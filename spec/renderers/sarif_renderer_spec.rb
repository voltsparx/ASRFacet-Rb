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

RSpec.describe ASRFacet::Renderers::SarifRenderer do
  it "renders discovered subdomains and findings as SARIF" do
    store = ASRFacet::ResultStore.new
    store.add_subdomain("app.example.com")
    store.add_finding(title: "Exposed admin", severity: :high, host: "app.example.com")

    rendered = JSON.parse(described_class.new(store, "example.com").render)

    expect(rendered["version"]).to eq("2.1.0")
    expect(rendered.dig("runs", 0, "results")).not_to be_empty
  end
end
