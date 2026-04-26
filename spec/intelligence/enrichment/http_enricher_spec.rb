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
require "tmpdir"

RSpec.describe ASRFacet::Intelligence::Enrichment::HttpEnricher do
  def fake_response(code:, body:, headers: {})
    instance_double(
      Net::HTTPOK,
      code: code.to_s,
      body: body,
      each_header: headers
    )
  end

  it "extracts titles, server hints, robots, sitemap, and technologies" do
    Dir.mktmpdir do |dir|
      client = instance_double(ASRFacet::HTTP::RetryableClient)
      allow(client).to receive(:get) do |url, **_kwargs|
        case url
        when "https://app.example.com/"
          fake_response(
            code: 200,
            body: "<html><title>App</title><script>React</script></html>",
            headers: { "server" => "nginx", "x-powered-by" => "Rails" }
          )
        when "https://app.example.com/robots.txt", "https://app.example.com/sitemap.xml"
          fake_response(code: 200, body: "", headers: {})
        else
          nil
        end
      end
      graph = ASRFacet::Intelligence::AssetGraph.new("example.com", root: dir)

      result = described_class.new(http_client: client).enrich("app.example.com", graph: graph, ports: [443])

      expect(result[:responses].first).to include(title: "App", server: "nginx", robots: true, sitemap: true)
      expect(result[:technologies]).to include("React", "Rails")
      expect(graph.find_by_type(:technology).map(&:value)).to include("react", "rails")
    end
  end

  it "returns an empty response list when nothing is reachable" do
    client = instance_double(ASRFacet::HTTP::RetryableClient, get: nil)
    result = described_class.new(http_client: client).enrich(
      "app.example.com",
      graph: instance_double(ASRFacet::Intelligence::AssetGraph, add_asset: nil),
      ports: [443]
    )

    expect(result[:responses]).to eq([])
  end

  it "supports non-standard ports when building endpoint urls" do
    Dir.mktmpdir do |dir|
      client = instance_double(ASRFacet::HTTP::RetryableClient)
      allow(client).to receive(:get) do |url, **_kwargs|
        case url
        when "http://app.example.com:8080/"
          fake_response(code: 200, body: "<title>Admin</title><script>Vue</script>", headers: {})
        when "http://app.example.com:8080/robots.txt", "http://app.example.com:8080/sitemap.xml"
          fake_response(code: 404, body: "", headers: {})
        else
          nil
        end
      end
      graph = ASRFacet::Intelligence::AssetGraph.new("example.com", root: dir)

      result = described_class.new(http_client: client).enrich("app.example.com", graph: graph, ports: [8080])

      expect(result[:responses].first[:url]).to eq("http://app.example.com:8080/")
      expect(result[:technologies]).to include("Vue")
    end
  end
end
