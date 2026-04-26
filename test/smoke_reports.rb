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

require_relative "support/smoke_helper"
require_relative "../lib/asrfacet_rb"

include ASRFacet::TestSupport

announce("Dynamic report smoke verification started.")

report_dir = File.join(TMP_ROOT, "report-engine")
FileUtils.rm_rf(report_dir)
FileUtils.mkdir_p(report_dir)

store = ASRFacet::ResultStore.new
store.add_subdomain("app.example.com")
store.add_subdomain("api.example.com")
store.add(:subdomains_with_sources, { host: "app.example.com", source: :crtsh })
store.add_ip("1.2.3.4")
store.add_port("1.2.3.4", 443, service: "https", banner: "nginx")
store.add_finding(
  title: "Weak Header Posture",
  severity: "medium",
  asset: "app.example.com",
  description: "Missing HSTS on primary host."
)
store.add_js_endpoint("https://app.example.com/app.js")

router = ASRFacet::Output::OutputRouter.new(store, "example.com")
router.render_all(report_dir)

assert(File.exist?(File.join(report_dir, "example_com.txt")), "TXT report was not created.")
assert(File.exist?(File.join(report_dir, "example_com.html")), "HTML report was not created.")
assert(File.exist?(File.join(report_dir, "example_com.json")), "JSON report was not created.")
assert(File.exist?(File.join(report_dir, "example_com_subdomains.csv")), "CSV subdomain report was not created.")

announce("Dynamic report smoke verification passed.")
