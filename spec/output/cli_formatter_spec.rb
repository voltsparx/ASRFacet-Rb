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

RSpec.describe ASRFacet::Output::CliFormatter do
  it "renders wide tables without emitting tty-table width warnings" do
    formatter = described_class.new
    store = ASRFacet::ResultStore.new
    store.add(:subdomains, "very-long-hostname-for-example-one.example.com")
    store.add(:subdomains, "very-long-hostname-for-example-two.example.com")
    store.add(:http_responses, {
      host: "very-long-hostname-for-example-two.example.com",
      status: 200,
      title: "Extremely Long Demo Title For Rendering",
      technologies: ["ruby", "nginx", "graphql", "api-gateway"]
    })

    payload = {
      store: store,
      top_assets: [],
      summary: store.summary,
      meta: {
        generated_at: Time.now.utc.iso8601,
        output_directory: "C:/tmp/asrfacet-rb"
      }
    }

    allow($stdout).to receive(:tty?).and_return(false)
    allow(TTY::Screen).to receive(:width).and_return(40)

    expect do
      output = formatter.format(payload)
      expect(output).to include("Scan Overview", "Subdomains", "HTTP Exposure")
    end.not_to output(/currently set width|vertical orientation/i).to_stderr
  end

  it "does not recommend integrity remediation when no integrity status is present" do
    formatter = described_class.new
    store = ASRFacet::ResultStore.new
    store.add(:subdomains, "scanme.nmap.org")

    payload = {
      store: store,
      top_assets: [],
      summary: store.summary,
      meta: {
        generated_at: Time.now.utc.iso8601,
        output_directory: "C:/tmp/asrfacet-rb"
      }
    }

    output = formatter.format(payload)
    expect(output).not_to include("Resolve the framework integrity findings before the next run")
  end
end
