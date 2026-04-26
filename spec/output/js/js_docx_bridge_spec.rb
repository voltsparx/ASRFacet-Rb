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
require "asrfacet_rb/output/js/js_docx_bridge"

RSpec.describe ASRFacet::Output::Js::JsDocxBridge do
  let(:store) { ASRFacet::ResultStore.new }

  it "invokes the node bridge when JS dependencies are marked installed" do
    renderer = described_class.new(store, "example.com", charts: {})
    lock_path = File.join(ASRFacet::Output::RuntimeDetector.js_dir, "package-lock.json")

    allow(File).to receive(:exist?).and_call_original
    allow(File).to receive(:exist?).with(lock_path).and_return(true)
    allow(renderer).to receive(:system).and_return(true)

    expect { renderer.render(File.join(Dir.tmpdir, "report.docx")) }.not_to raise_error
  end
end
