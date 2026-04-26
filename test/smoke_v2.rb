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

include ASRFacet::TestSupport

announce("V2 smoke verification started.")

home = File.join(TMP_ROOT, "v2-home")
FileUtils.rm_rf(home)
FileUtils.mkdir_p(home)
env = { "HOME" => home, "USERPROFILE" => home }

dry_run_output = run_command(*ruby_command("bin/asrfacet-rb", "scan", "example.com", "--dry-run", "--profile", "balanced"), env: env)
assert(dry_run_output.include?("DRY RUN"), "Dry-run output did not render.")
assert(dry_run_output.include?("Passive sources that would run"), "Dry-run output did not list passive sources.")

run_command(*ruby_command("bin/asrfacet-rb", "keys", "set", "shodan", "abc123"), env: env)
keys_list = run_command(*ruby_command("bin/asrfacet-rb", "keys", "list"), env: env)
assert(keys_list.include?("shodan"), "Stored key name was not listed.")
key_value = run_command(*ruby_command("bin/asrfacet-rb", "keys", "get", "shodan"), env: env).strip
assert(key_value == "abc123", "Stored key value was not returned.")
run_command(*ruby_command("bin/asrfacet-rb", "keys", "delete", "shodan"), env: env)

report_dir = File.join(home, ".asrfacet_rb", "output", "reports", "example_com", "2026-01-01T00-00-00Z")
FileUtils.mkdir_p(report_dir)
File.write(
  File.join(report_dir, "report.json"),
  JSON.pretty_generate(
    graph: {
      nodes: [
        { id: "example.com", type: "domain", data: {} },
        { id: "app.example.com", type: "subdomain", data: {} }
      ],
      edges: [
        { from: "example.com", to: "app.example.com", relation: "belongs_to" }
      ]
    }
  )
)

dot_output = run_command(*ruby_command("bin/asrfacet-rb", "graph", "dot", "example.com"), env: env)
assert(dot_output.include?("digraph ASRFacet"), "Graph dot export did not render.")
mermaid_output = run_command(*ruby_command("bin/asrfacet-rb", "graph", "mermaid", "example.com"), env: env)
assert(mermaid_output.include?("graph LR"), "Graph mermaid export did not render.")

announce("V2 smoke verification passed.")
