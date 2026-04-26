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

require "net/http"
require "socket"
require "spec_helper"
require "tmpdir"

RSpec.describe ASRFacet::Deployment::Stack do
  def free_port
    TCPServer.open("127.0.0.1", 0) { |server| server.addr[1] }
  end

  it "starts the web and lab services, writes a manifest, and answers health checks" do
    Dir.mktmpdir do |home|
      original_home = ENV["HOME"]
      original_userprofile = ENV["USERPROFILE"]
      ENV["HOME"] = home
      ENV["USERPROFILE"] = home

      web_port = free_port
      lab_port = free_port
      manifest_path = File.join(home, "runtime", "deploy.json")

      stack = described_class.new(
        web_port: web_port,
        lab_port: lab_port,
        manifest_path: manifest_path
      )

      begin
        manifest = stack.start(wait: false)
        web_response = Net::HTTP.get_response(URI("http://127.0.0.1:#{web_port}/healthz"))
        lab_response = Net::HTTP.get_response(URI("http://127.0.0.1:#{lab_port}/healthz"))

        expect(manifest[:status]).to eq("ready")
        expect(File).to exist(manifest_path)
        expect(web_response.code.to_i).to eq(200)
        expect(lab_response.code.to_i).to eq(200)
      ensure
        stack.stop
        ENV["HOME"] = original_home
        ENV["USERPROFILE"] = original_userprofile
      end
    end
  end

  it "binds to public interfaces when requested while keeping local reachability in the manifest URLs" do
    stack = described_class.new(public: true, with_lab: false, web_port: 4567, manifest_path: "tmp/deploy-manifest.json")
    payload = stack.send(:manifest_payload, status: "ready")

    expect(payload.dig(:services, :web, :bind)).to eq("0.0.0.0:4567")
    expect(payload.dig(:services, :web, :url)).to eq("http://127.0.0.1:4567")
    expect(payload.dig(:services, :lab, :enabled)).to be(false)
  end
end
