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

RSpec.describe ASRFacet::UI::Console do
  let(:console) { described_class.new }

  it "builds a full scan wizard plan with educational notes" do
    profile = ASRFacet::UI::Manual::WIZARD_PROFILES["Balanced"]

    plan = console.send(
      :build_wizard_plan,
      target: "example.com",
      goal: "Map the full web-facing attack surface",
      profile_name: "Balanced",
      profile: profile,
      output_format: "html",
      scope: "example.com,api.example.com",
      exclude: "dev.example.com",
      shodan_key: "secret-key"
    )

    expect(plan[:command]).to include("scan", "example.com", "--format", "html")
    expect(plan[:command]).to include("--scope", "example.com,api.example.com")
    expect(plan[:command]).to include("--exclude", "dev.example.com")
    expect(plan[:command]).to include("--shodan-key", "secret-key")
    expect(plan[:teaching_points].join(" ")).to include("attack-surface")
  end

  it "explains console help topics" do
    explanation = console.send(:console_explanation, "workflow")

    expect(explanation).to include("Explain: show workflow")
    expect(explanation).to include("Usage:")
  end

  it "explains the about topic inside the console" do
    explanation = console.send(:console_explanation, "about")

    expect(explanation).to include("Explain: about")
    expect(explanation).to include("framework overview")
  end
end
