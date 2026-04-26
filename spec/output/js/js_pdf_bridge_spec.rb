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
require "tmpdir"
require "asrfacet_rb/output/js/js_pdf_bridge"

RSpec.describe ASRFacet::Output::Js::JsPdfBridge do
  let(:store) { ASRFacet::ResultStore.new }

  it "invokes the node bridge when JS dependencies are marked installed" do
    renderer = described_class.new(store, "example.com", charts: {})
    allow(ASRFacet::Output::RuntimeDetector).to receive(:node_available?).and_return(true)
    allow(ASRFacet::Output::RuntimeDetector).to receive(:js_installed?).and_return(true)
    allow(renderer).to receive(:system).and_return(true)

    expect { renderer.render(File.join(Dir.tmpdir, "report.pdf")) }.not_to raise_error
  end
end
