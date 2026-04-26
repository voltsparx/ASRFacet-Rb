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
require "asrfacet_rb/output/runtime_detector"

RSpec.describe ASRFacet::Output::RuntimeDetector do
  describe ".node_available?" do
    it "returns a boolean" do
      expect(described_class.node_available?).to be(true).or be(false)
    end
  end

  describe ".js_dir" do
    it "points to an existing directory" do
      expect(File.directory?(described_class.js_dir)).to be(true)
    end
  end
end
