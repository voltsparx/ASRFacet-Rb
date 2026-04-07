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

announce("Lab smoke verification started.")

port = 9395
pid = nil
stdout = nil
stderr = nil

begin
  pid, stdout, stderr = spawn_command(*ruby_command("bin/asrfacet-rb", "lab", "--port", port.to_s), name: "lab")

  root_response = wait_for_http("http://127.0.0.1:#{port}/")
  app_response = wait_for_http("http://127.0.0.1:#{port}/app")
  js_response = wait_for_http("http://127.0.0.1:#{port}/assets/app.js")
  cors_response = wait_for_http("http://127.0.0.1:#{port}/cors/profile")

  assert(root_response.code.to_i == 200, "Expected lab root 200, got #{root_response.code}.")
  assert(app_response.code.to_i == 200, "Expected lab app 200, got #{app_response.code}.")
  assert(js_response.body.include?("/api/v1/users"), "Lab JavaScript did not expose the expected API-looking route.")
  assert(js_response.body.include?("/graphql"), "Lab JavaScript did not expose the expected GraphQL-looking route.")
  assert(cors_response["Access-Control-Allow-Origin"] == "*", "Expected permissive CORS header from lab profile route.")

  announce("Lab smoke verification passed.")
ensure
  stop_process(pid, stdout, stderr)
end
