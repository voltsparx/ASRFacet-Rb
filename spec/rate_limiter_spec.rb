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
  it "throttles repeated calls for the same source" do
    now = 100.0
    sleeps = []
    limiter = described_class.new(
      { crtsh: 2.0 },
      clock: -> { now },
      sleeper: lambda do |duration|
        sleeps << duration
        now += duration
      end
    )

    limiter.throttle(:crtsh)
    now += 0.1
    limiter.throttle(:crtsh)

    expect(sleeps).to contain_exactly(be_within(0.001).of(0.4))
  end

  it "raises a rate limit error for invalid qps values" do
    limiter = described_class.new

    expect { limiter.set_qps(:crtsh, 0) }.to raise_error(ASRFacet::RateLimitError, /QPS must be positive/)
  end

  it "keeps sources independent and uses the default qps for unknown sources" do
    now = 200.0
    sleeps = []
    limiter = described_class.new(
      {},
      clock: -> { now },
      sleeper: lambda do |duration|
        sleeps << duration
        now += duration
      end
    )

    limiter.throttle(:custom_source)
    now += 0.25
    limiter.throttle(:crtsh)
    now += 0.25
    limiter.throttle(:custom_source)

    expect(sleeps).to contain_exactly(be_within(0.001).of(0.5))
  end
end
