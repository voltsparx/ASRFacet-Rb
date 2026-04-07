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

RSpec.describe ASRFacet::Busters::BaseBuster do
  subject(:buster) { described_class.new }

  it "derives a bounded queue size from worker count" do
    expect(buster.send(:bounded_queue_size, 40)).to eq(160)
    expect(buster.send(:bounded_queue_size, 2)).to eq(16)
    expect(buster.send(:bounded_queue_size, 10, multiplier: 3, minimum: 12)).to eq(30)
  end

  it "falls back safely for invalid values" do
    expect(buster.send(:bounded_queue_size, nil)).to eq(16)
    expect(buster.send(:bounded_queue_size, 0)).to eq(16)
  end
end
