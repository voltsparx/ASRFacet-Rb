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

RSpec.describe ASRFacet::Output::Ruby::TxtRenderer do
  it "renders a 72-column ascii report from fixture data" do
    Dir.mktmpdir do |dir|
      path = File.join(dir, "report.txt")
      described_class.new(build_output_store, output_fixture_data[:target], build_output_options).render(path)

      body = File.read(path)
      expect(body).to include("ASRFacet-Rb Reconnaissance Report")
      expect(body).to include("SEVERITY DISTRIBUTION")
      expect(body.lines.map { |line| line.chomp.length }.max).to be <= 72
    end
  end
end
