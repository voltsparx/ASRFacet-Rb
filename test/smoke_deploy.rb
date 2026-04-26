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

require_relative "support/smoke_helper"

include ASRFacet::TestSupport

announce("Deploy smoke verification started.")

web_port = 4591
lab_port = 9397
pid = nil
stdout = nil
stderr = nil
home = File.join(TMP_ROOT, "deploy-home")
manifest_path = File.join(home, "runtime", "deploy.json")
FileUtils.rm_rf(home)
FileUtils.mkdir_p(home)
env = { "HOME" => home, "USERPROFILE" => home }

begin
  pid, stdout, stderr = spawn_command(
    *ruby_command(
      "bin/asrfacet-rb",
      "deploy",
      "--web-port", web_port.to_s,
      "--lab-port", lab_port.to_s,
      "--manifest", manifest_path
    ),
    name: "deploy",
    env: env
  )

  web_response = wait_for_http("http://127.0.0.1:#{web_port}/healthz")
  lab_response = wait_for_http("http://127.0.0.1:#{lab_port}/healthz")
  manifest_deadline = Time.now + 10
  sleep 0.25 until File.file?(manifest_path) || Time.now >= manifest_deadline

  assert(web_response.code.to_i == 200, "Expected deploy web health 200, got #{web_response.code}.")
  assert(lab_response.code.to_i == 200, "Expected deploy lab health 200, got #{lab_response.code}.")
  assert(File.file?(manifest_path), "Expected deploy manifest at #{manifest_path}.")

  manifest = JSON.parse(File.read(manifest_path))
  assert(manifest["status"] == "ready", "Expected deploy manifest status ready, got #{manifest["status"]}.")
  assert(manifest.dig("services", "web", "url").to_s.include?(web_port.to_s), "Expected manifest to include web port #{web_port}.")
  assert(manifest.dig("services", "lab", "url").to_s.include?(lab_port.to_s), "Expected manifest to include lab port #{lab_port}.")

  announce("Deploy smoke verification passed.")
ensure
  stop_process(pid, stdout, stderr)
end
