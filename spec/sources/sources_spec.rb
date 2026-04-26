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

RSpec.describe "v2 passive sources" do
  it "parses VirusTotal subdomains" do
    source = ASRFacet::Sources::VirustotalSource.new(key_store: instance_double(ASRFacet::KeyStore, get: "key"))
    allow(source).to receive(:get_json).and_return("data" => [{ "id" => "app.example.com" }])

    expect(source.fetch("example.com")).to eq(["app.example.com"])
  end

  it "parses URLScan results" do
    source = ASRFacet::Sources::UrlscanSource.new
    allow(source).to receive(:get_json).and_return("results" => [{ "page" => { "domain" => "api.example.com" } }])

    expect(source.fetch("example.com")).to eq(["api.example.com"])
  end

  it "parses CommonCrawl results" do
    source = ASRFacet::Sources::CommoncrawlSource.new
    allow(source).to receive(:get_text).and_return("{\"url\":\"https://cdn.example.com/app.js\"}\n")

    expect(source.fetch("example.com")).to eq(["cdn.example.com"])
  end

  it "parses SecurityTrails subdomains" do
    source = ASRFacet::Sources::SecuritytrailsSource.new(key_store: instance_double(ASRFacet::KeyStore, get: "key"))
    allow(source).to receive(:get_json).and_return("subdomains" => %w[api dev])

    expect(source.fetch("example.com")).to eq(%w[api.example.com dev.example.com])
  end
end
