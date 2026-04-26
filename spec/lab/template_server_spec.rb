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

RSpec.describe ASRFacet::Lab::TemplateServer do
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

  it "renders a local lab landing page with safe template descriptions" do
    html = described_class.new.send(:index_page)

    expect(html).to include("ASRFacet Local Validation Lab")
    expect(html).to include("/app")
    expect(html).to include("/browse/")
    expect(html).to include("safe placeholder surfaces")
  end

  it "returns health and readiness payloads for deploy orchestration" do
    server = described_class.new
    server.instance_variable_set(:@server, Object.new)
    health_response = response_class.new
    ready_response = response_class.new

    server.send(:health, health_response)
    server.send(:readiness, ready_response)

    expect(health_response.status).to eq(200)
    expect(JSON.parse(health_response.body)).to include("service" => "lab", "status" => "ok")
    expect(ready_response.status).to eq(200)
    expect(JSON.parse(ready_response.body)).to include("service" => "lab", "status" => "ready")
  end
end
