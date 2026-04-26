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

RSpec.describe ASRFacet::ResultStore do
  it "supports both convenience methods and legacy category access" do
    store = described_class.new

    store.add_subdomain("App.EXAMPLE.com")
    store.add_ip("198.51.100.10")
    store.add_port("198.51.100.10", 443, service: "https")
    store.add_finding(title: "Open admin", severity: :medium, host: "app.example.com")
    store.add_js_endpoint("/api/v1/users")
    store.add_error(source: "spec", message: "test")

    expect(store.subdomains).to eq(["app.example.com"])
    expect(store.ips).to eq(["198.51.100.10"])
    expect(store.ports["198.51.100.10"]).to include(include(port: 443, service: "https"))
    expect(store.all(:open_ports)).to include(include(host: "198.51.100.10", port: 443))
    expect(store.stats).to include(subdomains: 1, ips: 1, open_ports: 1, findings: 1)
  end
end
