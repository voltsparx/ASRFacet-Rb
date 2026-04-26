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

require "spec_helper"

RSpec.describe ASRFacet::Scanner::Timing do
  it "returns the exact T5 values derived from nmap.cc and NmapOps.cc" do
    template = described_class.get(5)

    expect(template.name).to eq("insane")
    expect(template.min_rtt_timeout).to eq(50)
    expect(template.max_rtt_timeout).to eq(300)
    expect(template.initial_rtt_timeout).to eq(250)
    expect(template.max_retries).to eq(2)
    expect(template.host_timeout).to eq(900_000)
    expect(template.max_scan_delay).to eq(5)
  end

  it "resolves a timing template by name" do
    expect(described_class.from_name("aggressive").level).to eq(4)
  end

  it "falls back to normal for an unknown template" do
    expect(described_class.from_name("mystery").level).to eq(3)
  end
end
