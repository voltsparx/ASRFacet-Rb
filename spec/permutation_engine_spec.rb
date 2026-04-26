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

RSpec.describe ASRFacet::PermutationEngine do
  it "builds prefix, suffix, and numbered candidates from discoveries" do
    candidates = described_class.new(%w[api.example.com app.example.com], "example.com").generate

    expect(candidates).to include("dev.example.com", "api-v2.example.com", "api2.example.com", "app-dev.example.com")
    expect(candidates).not_to include("api.example.com")
  end
end
