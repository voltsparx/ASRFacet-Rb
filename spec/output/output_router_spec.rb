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
require "asrfacet_rb/output/output_router"

RSpec.describe ASRFacet::Output::OutputRouter do
  let(:store) do
    instance_double(
      ASRFacet::ResultStore,
      stats: { subdomains: 2, ips: 1, findings: 1, js_endpoints: 0, errors: 0 },
      subdomains: ["sub.example.com"],
      ips: ["1.2.3.4"],
      ports: {},
      findings: [],
      js_endpoints: [],
      errors: [],
      subdomains_with_sources: nil
    )
  end

  subject(:router) { described_class.new(store, "example.com") }

  describe "#render" do
    it "raises on unknown format" do
      expect { router.render("xml", File.join(Dir.tmpdir, "out.xml")) }
        .to raise_error(ASRFacet::Error, /Unknown format/)
    end
  end

  describe "#engine_info" do
    it "returns a label string" do
      expect(router.engine_info).to be_a(String)
      expect(router.engine_info).not_to be_empty
    end
  end
end
