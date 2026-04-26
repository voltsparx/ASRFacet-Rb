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

announce("Web-session smoke verification started.")

port = 4589
pid = nil
stdout = nil
stderr = nil
home = File.join(TMP_ROOT, "web-home")
FileUtils.rm_rf(home)
FileUtils.mkdir_p(home)
env = { "HOME" => home, "USERPROFILE" => home }

begin
  pid, stdout, stderr = spawn_command(*ruby_command("bin/asrfacet-rb", "--web-session", "--web-port", port.to_s), name: "web-session", env: env)

  root_response = wait_for_http("http://127.0.0.1:#{port}/")
  bootstrap_response = wait_for_http("http://127.0.0.1:#{port}/api/bootstrap")
  bootstrap = parse_json_response(bootstrap_response)

  assert(root_response.code.to_i == 200, "Expected web root 200, got #{root_response.code}.")
  assert(root_response.body.include?("About ASRFacet-Rb"), "Web root did not render the About section.")
  assert(root_response.body.include?("Documentation"), "Web root did not render the Documentation section.")
  assert(bootstrap["docs"].is_a?(Array) && !bootstrap["docs"].empty?, "Web bootstrap docs payload was empty.")

  announce("Web-session smoke verification passed.")
ensure
  stop_process(pid, stdout, stderr)
end
