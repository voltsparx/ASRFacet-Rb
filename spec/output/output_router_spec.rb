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

RSpec.describe ASRFacet::Output::OutputRouter do
  subject(:router) { described_class.new(build_output_store, output_fixture_data[:target], asset_graph: build_output_graph) }

  it "raises on an unknown format" do
    expect { router.render("xml", File.join(Dir.tmpdir, "report.xml")) }.to raise_error(ASRFacet::Error, /Unknown format/)
  end

  it "reports the active engine label" do
    allow(ASRFacet::Output::RuntimeDetector).to receive(:node_available?).and_return(false)

    expect(router.engine_info).to include("Ruby")
  end

  it "renders all ruby-native formats into a directory" do
    allow(ASRFacet::Output::RuntimeDetector).to receive(:node_available?).and_return(false)

    Dir.mktmpdir do |dir|
      router.render_all(dir)

      expect(Dir.glob(File.join(dir, "*.txt"))).not_to be_empty
      expect(Dir.glob(File.join(dir, "*.html"))).not_to be_empty
      expect(Dir.glob(File.join(dir, "*.json"))).not_to be_empty
      expect(Dir.glob(File.join(dir, "*_findings.csv"))).not_to be_empty
    end
  end
end
