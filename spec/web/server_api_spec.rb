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

require "json"
require "spec_helper"
require "tmpdir"

RSpec.describe ASRFacet::Web::Server do
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

  let(:response) { response_class.new }
  let(:session_store) { instance_double(ASRFacet::Web::SessionStore, root: "/tmp/sessions") }
  let(:session_runner) { instance_double(ASRFacet::Web::SessionRunner) }
  let(:server) { described_class.new(session_store: session_store, session_runner: session_runner) }

  it "saves normalized session payloads through the sessions API" do
    request = Struct.new(:request_method, :body).new(
      "POST",
      JSON.generate(
        name: "  Scanner Draft  ",
        config: {
          target: " example.com ",
          mode: "PORTSCAN",
          format: "PDF",
          scan_type: "SYN",
          scan_timing: 4
        }
      )
    )
    stored_session = {
      id: "session-1",
      name: "Scanner Draft",
      config: ASRFacet::Web::SessionStore.normalize_config(
        target: " example.com ",
        mode: "PORTSCAN",
        format: "PDF",
        scan_type: "SYN",
        scan_timing: 4
      )
    }

    expect(session_store).to receive(:create_or_update).with(
      hash_including(
        name: "Scanner Draft",
        config: hash_including(target: "example.com", mode: "portscan", format: "pdf", scan_type: "syn", scan_timing: 4)
      )
    ).and_return(stored_session)

    server.send(:handle_sessions, request, response)
    payload = JSON.parse(response.body)

    expect(response.status).to eq(200)
    expect(payload.dig("session", "name")).to eq("Scanner Draft")
  end

  it "returns saved session summaries through the sessions GET API" do
    request = Struct.new(:request_method).new("GET")
    allow(session_store).to receive(:list_sessions).and_return(
      [
        {
          id: "session-1",
          name: "Example",
          status: "completed",
          running: false,
          config: { target: "example.com", mode: "scan" },
          summary: { subdomains: 2 }
        }
      ]
    )

    server.send(:handle_sessions, request, response)
    payload = JSON.parse(response.body)

    expect(response.status).to eq(200)
    expect(payload.fetch("sessions")).to include(include("id" => "session-1", "target" => "example.com", "mode" => "scan"))
  end

  it "returns not found from the session lookup API when a session does not exist" do
    request = Struct.new(:query, :query_string, :request_uri).new({}, "id=missing", URI("http://127.0.0.1/api/session?id=missing"))
    allow(session_store).to receive(:fetch).with("missing").and_return(nil)

    server.send(:handle_session_lookup, request, response)

    expect(response.status).to eq(404)
    expect(JSON.parse(response.body)).to include("error" => "not_found")
  end

  it "serves report artifacts with the correct content type" do
    Dir.mktmpdir do |dir|
      artifact_path = File.join(dir, "report.csv")
      File.write(artifact_path, "host,port\nexample.com,443\n")
      request = Struct.new(:path).new("/reports/session-123/csv_ports_report")

      allow(session_store).to receive(:fetch).with("session-123").and_return(
        { artifacts: { csv_ports_report: artifact_path } }
      )

      server.send(:handle_reports, request, response)

      expect(response.status).to eq(200)
      expect(response["Content-Type"]).to eq("text/csv; charset=utf-8")
      expect(response.body).to include("example.com")
    end
  end
end
