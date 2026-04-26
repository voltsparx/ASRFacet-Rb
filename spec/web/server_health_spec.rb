# frozen_string_literal: true
# For use only on systems you own or have explicit
# written authorization to test.
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

  it "returns a healthy web status payload" do
    Dir.mktmpdir do |dir|
      session_store = instance_double(ASRFacet::Web::SessionStore, root: dir)
      allow(ASRFacet::Config).to receive(:fetch).and_call_original
      allow(ASRFacet::Config).to receive(:fetch).with("output", "directory").and_return(dir)
      server = described_class.new(session_store: session_store)
      server.instance_variable_set(:@server, Object.new)

      server.send(:handle_health, response)
      payload = JSON.parse(response.body)

      expect(response.status).to eq(200)
      expect(payload).to include("service" => "web", "status" => "ok")
    end
  end

  it "returns ready when the session and report directories exist" do
    Dir.mktmpdir do |dir|
      session_store = instance_double(ASRFacet::Web::SessionStore, root: dir)
      allow(ASRFacet::Config).to receive(:fetch).and_call_original
      allow(ASRFacet::Config).to receive(:fetch).with("output", "directory").and_return(dir)
      server = described_class.new(session_store: session_store)
      server.instance_variable_set(:@server, Object.new)

      server.send(:handle_readiness, response)
      payload = JSON.parse(response.body)

      expect(response.status).to eq(200)
      expect(payload).to include("service" => "web", "status" => "ready")
    end
  end
end
