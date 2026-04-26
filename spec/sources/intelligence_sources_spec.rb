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

require "base64"
require "spec_helper"

RSpec.describe "intelligence passive sources" do
  let(:rate_limiter) { instance_double(ASRFacet::RateLimiter, throttle: true) }
  let(:key_store) { instance_double(ASRFacet::KeyStore) }
  let(:logger) { instance_double(ASRFacet::StructuredLogger, warn: nil) }

  def build_source(klass, key: nil)
    allow(key_store).to receive(:get).and_return(key)
    klass.new(rate_limiter: rate_limiter, key_store: key_store, logger: logger)
  end

  it "exposes base source helpers for availability and subdomain extraction" do
    helper_class = Class.new(ASRFacet::Intelligence::Sources::BaseSource) do
      def name = :fixture
      def requires_key? = true
      def fetch(domain) = extract_subdomains("www.#{domain} cdn.#{domain} cdn.#{domain} other.test", domain)
    end

    source = helper_class.new(rate_limiter: rate_limiter, key_store: key_store, logger: logger)
    allow(key_store).to receive(:get).with(:fixture).and_return(nil, "secret")

    expect(source.available?).to be(false)
    expect(source.fetch("example.com")).to match_array(%w[cdn.example.com www.example.com])
    expect(source.available?).to be(true)
  end

  it "returns an empty result when a required source key is unavailable" do
    source = build_source(ASRFacet::Intelligence::Sources::VirustotalSource, key: nil)

    expect(source.fetch("example.com")).to eq([])
  end

  it "parses GitHub and DNSDumpster text sources into normalized subdomains" do
    github = build_source(ASRFacet::Intelligence::Sources::GithubSource)
    dnsdumpster = build_source(ASRFacet::Intelligence::Sources::DnsdumpsterSource)

    allow(github).to receive(:get_text).and_return("api.example.com docs.example.com unrelated.test")
    allow(dnsdumpster).to receive(:get_text).and_return("<a>app.example.com</a><span>cdn.example.com</span>")

    expect(github.fetch("example.com")).to eq(%w[api.example.com docs.example.com])
    expect(dnsdumpster.fetch("example.com")).to eq(%w[app.example.com cdn.example.com])
  end

  it "sends the expected authorization header for Censys and normalizes names" do
    source = build_source(ASRFacet::Intelligence::Sources::CensysSource, key: "id:secret")

    expect(source).to receive(:get_json).with(
      "https://search.censys.io/api/v2/certificates/search?q=example.com",
      headers: { "Authorization" => "Basic #{Base64.strict_encode64('id:secret')}" }
    ).and_return(
      "result" => {
        "hits" => [
          { "name" => "app.example.com", "names" => ["api.example.com", "app.example.com"] },
          { "name" => "ignored.other.test", "names" => [] }
        ]
      }
    )

    expect(source.fetch("example.com")).to eq(%w[api.example.com app.example.com])
  end

  it "parses WhoisXML API result shapes into normalized subdomains" do
    source = build_source(ASRFacet::Intelligence::Sources::WhoisxmlapiSource, key: "key")
    allow(source).to receive(:get_json).and_return(
      "result" => [
        { "name" => "portal.example.com" },
        { "domain" => ["dev.example.com", "portal.example.com"] },
        "static.example.com"
      ]
    )

    expect(source.fetch("example.com")).to eq(%w[dev.example.com portal.example.com static.example.com])
  end
end
