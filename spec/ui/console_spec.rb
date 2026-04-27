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

  it "uses asrfrb as the console prompt label" do
    rendered = console.send(:prompt)
    plain = rendered.gsub(/\e\[[\d;]*m/, "")

    expect(plain).to eq("asrfrb > ")
  end

  it "tracks an active extension mode and stores plugin selectors for that mode" do
    console.send(:use_console_mode, "portscan")
    console.send(:handle_extension_command, "select plugins mode:portscan,-internet_exposure")
    state = console.instance_variable_get(:@extension_state)

    expect(state.active_mode).to eq("portscan")
    expect(state.spec_for(:plugins)).to include("mode:portscan")
    expect(state.review[:plugins][:selected].map { |entry| entry[:name] }).to include("attack_path")
  end

  it "injects stored console attachables into matching CLI commands" do
    allow(ASRFacet::UI::CLI).to receive(:start)
    console.send(:use_console_mode, "scan")
    console.send(:handle_extension_command, "select plugins exposure_score")
    console.send(:handle_extension_command, "select filters scope_guard")

    console.send(:dispatch_cli, "scan example.com")

    expect(ASRFacet::UI::CLI).to have_received(:start).with(include("scan", "example.com", "--plugins", "exposure_score", "--filters", "scope_guard"))
  end
end
