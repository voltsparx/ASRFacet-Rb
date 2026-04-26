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

require "spec_helper"

RSpec.describe ASRFacet::UI::CLI do
  before do
    allow(ASRFacet::Core::IntegrityChecker).to receive(:check).and_return(status: "ok", summary: "ok", issues: [], recommendations: [])
  end

  it "dispatches the deploy command to the deployment stack with requested ports and manifest" do
    stack = instance_double(ASRFacet::Deployment::Stack, start: true)
    allow(ASRFacet::Deployment::Stack).to receive(:new).and_return(stack)

    described_class.start([
      "deploy",
      "--public",
      "--web-port", "8080",
      "--lab-port", "9393",
      "--manifest", "tmp/deploy.json"
    ])

    expect(ASRFacet::Deployment::Stack).to have_received(:new).with(
      hash_including(public: true, with_lab: true, web_port: 8080, lab_port: 9393, manifest_path: "tmp/deploy.json")
    )
    expect(stack).to have_received(:start)
  end
end
