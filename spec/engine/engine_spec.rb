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

RSpec.describe ASRFacet::Engine::Engine do
  let(:plugin_class) do
    Class.new(ASRFacet::Plugins::Base) do
      priority 5
      handles :subdomain

      def process(asset, context, bus)
        context[:seen] << asset[:value]
        bus.emit(:ip_found, value: "198.51.100.10")
      end
    end
  end

  it "registers plugins and dispatches events through the dispatcher" do
    engine = described_class.new
    engine.registry.register(plugin_class)
    seen = []
    ips = []
    engine.bus.on(:ip_found) { |payload| ips << payload[:value] }

    engine.dispatcher.dispatch(:subdomain, { value: "app.example.com" }, seen: seen)

    expect(seen).to eq(["app.example.com"])
    expect(ips).to eq(["198.51.100.10"])
  end
end
