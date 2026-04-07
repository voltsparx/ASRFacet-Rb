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

RSpec.describe ASRFacet::EventBus do
  it "tracks queue depth and dispatch stats" do
    bus = described_class.new(max_queue: 2)
    received = []

    bus.subscribe(:subdomain) { |data| received << data[:host] }
    bus.emit(:subdomain, { host: "app.example.com" })

    expect(bus.stats).to include(emitted: 1, dispatched: 0, queue_depth: 1, max_queue: 2)

    bus.process_all

    expect(received).to eq(["app.example.com"])
    expect(bus.stats).to include(emitted: 1, dispatched: 1, queue_depth: 0)
  end

  it "can drop low-priority events when non-blocking mode is requested" do
    bus = described_class.new(max_queue: 1)

    bus.emit(:subdomain, { host: "one.example.com" })
    expect(bus.emit(:subdomain, { host: "two.example.com" }, non_block: true)).to be_nil
    expect(bus.stats[:dropped]).to eq(1)
  end
end
