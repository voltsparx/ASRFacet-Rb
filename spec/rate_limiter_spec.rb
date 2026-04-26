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

RSpec.describe ASRFacet::RateLimiter do
  it "sleeps when a source is called faster than its configured qps" do
    limiter = described_class.new(crtsh: 2.0)
    allow(Process).to receive(:clock_gettime).and_return(100.0, 100.1)
    allow(limiter).to receive(:sleep)

    limiter.throttle(:crtsh)
    limiter.throttle(:crtsh)

    expect(limiter).to have_received(:sleep).with(be_within(0.01).of(0.4))
  end
end
