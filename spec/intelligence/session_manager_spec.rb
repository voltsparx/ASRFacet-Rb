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

RSpec.describe ASRFacet::Intelligence::SessionManager do
  it "creates, loads, lists, and exports workspace state" do
    Dir.mktmpdir do |dir|
      manager = described_class.new(root: dir)
      manager.create("lab.example.com")
      build_intelligence_graph(root: dir)

      workspace = manager.load("lab.example.com")
      export_path = manager.export("lab.example.com", format: "json")

      expect(workspace.dig(:session, :status)).to eq("active")
      expect(manager.list.map { |entry| entry[:target] }).to include("lab.example.com")
      expect(JSON.parse(File.read(export_path))).to include("session", "graph")
      expect(manager.resume?("lab.example.com")).to be(true)
    end
  end

  it "raises for unknown workspace exports" do
    Dir.mktmpdir do |dir|
      manager = described_class.new(root: dir)

      expect { manager.export("missing.example.com", format: "json") }.to raise_error(ASRFacet::Error, /Workspace not found/)
    end
  end

  it "deletes workspaces and reports missing targets safely" do
    Dir.mktmpdir do |dir|
      manager = described_class.new(root: dir)
      manager.create("lab.example.com")

      expect(manager.delete("lab.example.com")).to be(true)
      expect(manager.resume?("lab.example.com")).to be(false)
      expect(manager.delete("lab.example.com")).to be(false)
    end
  end
end
