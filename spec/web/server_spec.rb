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
require "json"

RSpec.describe ASRFacet::Web::Server do
  it "renders the branded dashboard shell with external assets and workspace views" do
    html = described_class.new.send(:dashboard_html)

    expect(html).to include("/assets/icon")
    expect(html).to include("/assets/dashboard.css")
    expect(html).to include("/assets/dashboard.js")
    expect(html).to include("ASRFacet-Rb")
    expect(html).to include("Session Builder")
    expect(html).to include("Activity Drawer")
    expect(html).to include("About ASRFacet-Rb")
    expect(html).to include("Documentation")
    expect(html).to include("Scanner engine")
    expect(html).to include("Scan Type")
    expect(html).to include("Version Intensity (0-9)")
    expect(html).to include("Select a node to see its linked assets")
    expect(html).to include("report-summary")
  end

  it "exposes scanner and multi-format capabilities through bootstrap" do
    session_store = instance_double(ASRFacet::Web::SessionStore, root: "/tmp/sessions", list_sessions: [])
    response_class = Class.new do
      attr_accessor :status, :body

      def initialize
        @headers = {}
      end

      def []=(key, value)
        @headers[key] = value
      end
    end
    response = response_class.new

    described_class.new(session_store: session_store).send(:handle_bootstrap, response)
    payload = JSON.parse(response.body)

    expect(response.status).to eq(200)
    expect(payload.dig("capabilities", "modes")).to include("portscan")
    expect(payload.dig("capabilities", "formats")).to include("pdf", "docx", "all", "sarif")
    expect(payload.dig("capabilities", "scan_types")).to include("syn", "udp", "service")
    expect(payload.dig("capabilities", "scan_timings")).to eq([0, 1, 2, 3, 4, 5])
  end

  it "starts a saved session when the run id is passed in the POST query string" do
    session_store = instance_double(ASRFacet::Web::SessionStore)
    session_runner = instance_double(ASRFacet::Web::SessionRunner)
    response_class = Class.new do
      attr_accessor :status, :body

      def initialize
        @headers = {}
      end

      def []=(key, value)
        @headers[key] = value
      end

      def [](key)
        @headers[key]
      end
    end
    request = Struct.new(:request_method, :query, :query_string, :request_uri, :body).new(
      "POST",
      {},
      "id=session-123",
      URI("http://127.0.0.1/api/run?id=session-123"),
      ""
    )
    response = response_class.new

    allow(session_store).to receive(:root).and_return("/tmp/sessions")
    allow(session_store).to receive(:fetch).with("session-123").and_return({ id: "session-123" })
    allow(session_store).to receive(:append_event)
    allow(session_runner).to receive(:start).with("session-123").and_return(true)

    described_class.new(session_store: session_store, session_runner: session_runner).send(:handle_run, request, response)

    expect(response.status).to eq(200)
    expect(JSON.parse(response.body)).to include("ok" => true, "session_id" => "session-123")
    expect(session_store).to have_received(:append_event).with("session-123", hash_including(type: "system"))
  end
end
