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

RSpec.describe ASRFacet::Output::RuntimeDetector do
  it "detects node availability from a version command" do
    allow(described_class).to receive(:capture).with("node", "--version").and_return(["v22.2.0\n", instance_double(Process::Status, success?: true)])

    expect(described_class.node_available?).to be(true)
    expect(described_class.node_version).to eq("v22.2.0")
  end

  it "detects npm availability independently" do
    allow(described_class).to receive(:capture).with("npm", "--version").and_return(["10.8.1\n", instance_double(Process::Status, success?: true)])

    expect(described_class.npm_available?).to be(true)
  end

  it "reports the js directory and installed state" do
    allow(File).to receive(:directory?).and_call_original
    allow(File).to receive(:file?).and_call_original
    allow(File).to receive(:directory?).with(described_class.js_dir).and_return(true)
    allow(File).to receive(:file?).with(File.join(described_class.js_dir, "package.json")).and_return(true)
    allow(File).to receive(:directory?).with(File.join(described_class.js_dir, "node_modules")).and_return(false)
    allow(File).to receive(:file?).with(File.join(described_class.js_dir, "package-lock.json")).and_return(true)

    expect(described_class.js_dir).to include("lib/asrfacet_rb/output/js")
    expect(described_class.js_installed?).to be(true)
  end
end
